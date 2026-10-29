/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with this
work for additional information regarding copyright ownership. The ASF
licenses this file to You under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
*/

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
	"vermeer/apps/auth"
	"vermeer/apps/common"
	"vermeer/apps/master/workers"
	pb "vermeer/apps/protos"
	"vermeer/apps/structure"
)

type clusterStatsClient struct {
	pb.WorkerClient
	response *pb.WorkerStatInfoResp
	err      error
}

type queuedClusterStatsClient struct {
	pb.WorkerClient
	block         bool
	started       chan struct{}
	calls         atomic.Int32
	canceledCalls atomic.Int32
}

func (client *queuedClusterStatsClient) GetWorkerStatInfo(ctx context.Context, _ *pb.WorkerStatInfoReq,
	_ ...grpc.CallOption) (*pb.WorkerStatInfoResp, error) {
	client.calls.Add(1)
	if ctx.Err() != nil {
		client.canceledCalls.Add(1)
	}
	client.started <- struct{}{}
	if client.block {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	return &pb.WorkerStatInfoResp{MetricSchemaVersion: 1, ProcessCpuCores: 0.5,
		ProcessRssBytes: 2048, SampleWindowSeconds: 1, MetricsObservedAt: 1234}, nil
}

func TestClusterMetricQueuePreservesAllWorkerHealth(t *testing.T) {
	const total = 25
	for _, mode := range []string{"success", "already_canceled", "cancel_in_flight", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "already_canceled" {
				cancel()
			}
			client := &queuedClusterStatsClient{
				block:   mode == "cancel_in_flight" || mode == "deadline",
				started: make(chan struct{}, total),
			}
			snapshots := make([]workers.WorkerHealthSnapshot, total)
			for index := range snapshots {
				snapshot := readyWorkerSnapshot(client)
				snapshot.Name = fmt.Sprintf("worker-%02d", index)
				snapshot.GrpcPeer = fmt.Sprintf("worker-%02d:6789", index)
				snapshot.Version = "test-version"
				snapshot.LaunchTime = time.Unix(5, 0)
				snapshots[index] = snapshot
			}
			// A readiness failure must remain distinct from a metric timeout, even
			// for a node queued beyond the first eight in-flight RPCs.
			snapshots[total-1].Checks.ComputeStreamReady = false
			done := make(chan ClusterSnapshot, 1)
			started := time.Now()
			go func() {
				done <- buildClusterSnapshot(ctx, MasterInfoSnapshot{LaunchTime: time.Unix(1, 0)}, snapshots, 1234)
			}()
			if mode == "cancel_in_flight" {
				for i := 0; i < 8; i++ {
					select {
					case <-client.started:
					case <-time.After(2 * time.Second):
						t.Fatal("metrics pool did not start eight RPCs")
					}
				}
				cancel()
			}
			var result ClusterSnapshot
			select {
			case result = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("metrics queue did not stop after cancellation/deadline")
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("metrics queue added work beyond its shared deadline")
			}
			wantCalls := int32(8)
			if mode == "success" {
				wantCalls = total
			}
			if mode == "already_canceled" {
				wantCalls = 0
			}
			if client.calls.Load() != wantCalls || client.canceledCalls.Load() != 0 {
				t.Fatalf("calls=%d, want=%d; calls with canceled context=%d",
					client.calls.Load(), wantCalls, client.canceledCalls.Load())
			}
			if result.RegisteredWorkers != total || result.ReadyWorkers != total-1 || len(result.Workers) != total ||
				result.Status != "DEGRADED" || result.Reason != "workers_not_ready" {
				t.Fatalf("metric collection changed aggregate health: %+v", result)
			}
			for index, node := range result.Workers {
				snapshot := snapshots[index]
				if node.ID != snapshot.Name || node.Name != snapshot.Name || node.Role != "WORKER" ||
					node.Group != snapshot.Group || node.GrpcPeer != snapshot.GrpcPeer || node.Version != snapshot.Version ||
					!node.LaunchTime.Equal(snapshot.LaunchTime) || node.Ready != snapshot.Checks.Ready() ||
					node.Reason != snapshot.Checks.Reason() || len(node.Checks) != 5 ||
					node.Checks["compute_stream_ready"] != snapshot.Checks.ComputeStreamReady || node.Metrics == nil {
					t.Fatalf("worker %d lost health metadata: %+v", index, node)
				}
				if mode == "success" {
					if node.MetricStatus.Availability != "AVAILABLE" || node.Metrics["rss_bytes"] != uint64(2048) {
						t.Fatalf("worker %d missing collected metrics: %+v", index, node)
					}
				} else if node.MetricStatus.Availability != "UNAVAILABLE" || node.MetricStatus.Reason != "metrics_timeout" ||
					len(node.Metrics) != 0 {
					t.Fatalf("worker %d missing timeout status: %+v", index, node)
				}
			}
		})
	}
}

func (client clusterStatsClient) GetWorkerStatInfo(context.Context, *pb.WorkerStatInfoReq, ...grpc.CallOption) (*pb.WorkerStatInfoResp, error) {
	return client.response, client.err
}

func readyWorkerSnapshot(client pb.WorkerClient) workers.WorkerHealthSnapshot {
	return workers.WorkerHealthSnapshot{Name: "worker-one", Group: "group-one", Session: client,
		Checks: workers.ReadinessChecks{Registered: true, ConnectionReady: true,
			LoadStreamReady: true, ComputeStreamReady: true, SuperstepStreamReady: true}}
}

func TestClusterWorkerMetricsNeverOverrideReadiness(t *testing.T) {
	for _, test := range []struct {
		name         string
		response     *pb.WorkerStatInfoResp
		err          error
		availability string
	}{
		{"legacy", &pb.WorkerStatInfoResp{}, nil, "UNSUPPORTED"},
		{"unimplemented", nil, status.Error(codes.Unimplemented, "old worker"), "UNSUPPORTED"},
		{"timeout", nil, status.Error(codes.DeadlineExceeded, "timeout"), "UNAVAILABLE"},
		{"failed", nil, errors.New("internal failure"), "UNAVAILABLE"},
		{"warming", &pb.WorkerStatInfoResp{MetricSchemaVersion: 1, MetricError: "metrics_warming_up"}, nil, "UNAVAILABLE"},
		{"invalid", &pb.WorkerStatInfoResp{MetricSchemaVersion: 1, ProcessCpuCores: math.NaN()}, nil, "UNAVAILABLE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			node := clusterWorkerNode(context.Background(), readyWorkerSnapshot(clusterStatsClient{response: test.response, err: test.err}), 1234)
			if !node.Ready || node.Status != "UP" || node.Reason != "" {
				t.Fatalf("metrics changed readiness: %+v", node)
			}
			if node.MetricStatus.Availability != test.availability || len(node.Metrics) != 0 {
				t.Fatalf("bad metrics failure: %+v", node)
			}
		})
	}
	snapshot := readyWorkerSnapshot(clusterStatsClient{response: &pb.WorkerStatInfoResp{MetricSchemaVersion: 1,
		ProcessCpuCores: 1.5, ProcessRssBytes: 1024, SampleWindowSeconds: 2, MetricsObservedAt: 1000}})
	node := clusterWorkerNode(context.Background(), snapshot, 1234)
	if node.Metrics["cpu_cores"] != 1.5 || node.Metrics["rss_bytes"] != uint64(1024) || node.MetricStatus.ObservedAt != 1000 {
		t.Fatalf("wrong process metric units: %+v", node)
	}
	snapshot.Checks.ComputeStreamReady = false
	node = clusterWorkerNode(context.Background(), snapshot, 1234)
	if node.Ready || node.Status != "DEGRADED" || node.Reason != "compute_stream_not_ready" || node.MetricStatus.Availability != "AVAILABLE" {
		t.Fatalf("stream failure conflated with metrics: %+v", node)
	}
}

func TestClusterEmptySnapshotAndMaster(t *testing.T) {
	previous := InfoMaster
	InfoMaster = &Info{LaunchTime: time.Now(), Version: "test", GrpcPeer: "master:6689"}
	t.Cleanup(func() { InfoMaster = previous })
	common.SetConfig("service_offline", false)
	result := collectClusterSnapshot(context.Background())
	if result.SchemaVersion != 1 || result.ObservedAt <= 0 || result.Status != "DEGRADED" || result.Reason != "no_workers" ||
		result.RegisteredWorkers != 0 || result.ReadyWorkers != 0 || result.Workers == nil || !result.Master.Ready {
		t.Fatalf("bad empty snapshot: %+v", result)
	}
	common.SetConfig("service_offline", true)
	t.Cleanup(func() { common.SetConfig("service_offline", false) })
	node := clusterMasterNode(InfoMaster.snapshot(), 1234)
	if node.Ready || node.Reason != "service_offline" {
		t.Fatalf("offline master ready: %+v", node)
	}
}

func TestClusterRouteRequiresAdminAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)
	common.SetConfig("auth_token_factor", "cluster-test-only-factor")
	auth.Init()
	sentinel := &common.Sentinel{}
	sentinel.Init("127.0.0.1:0", "release")
	SetAdminRouters(sentinel, auth.TokenFilter, auth.AdminFilter)
	factory := &auth.TokenFactory{Factor: "cluster-test-only-factor"}
	tokenFor := func(user string) string {
		token := factory.NewToken(user, structure.AdminSpace, "cluster-test")
		factory.Sign(token)
		encoded, _ := json.Marshal(token)
		return auth.ToBase58(string(encoded))
	}
	for _, test := range []struct {
		name, token string
		expected    int
	}{
		{"anonymous", "", 401}, {"member", tokenFor("member"), 401}, {"admin", tokenFor("admin"), 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/admin/cluster", nil)
			if test.token != "" {
				req.Header.Set("Authorization", "Bearer "+test.token)
			}
			recorder := httptest.NewRecorder()
			sentinel.ServeHTTP(recorder, req)
			if recorder.Code != test.expected {
				t.Fatalf("status %d, want %d", recorder.Code, test.expected)
			}
			if test.expected == 200 {
				var body map[string]interface{}
				if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || body["schema_version"] != float64(1) {
					t.Fatalf("bad snapshot: %s", recorder.Body.String())
				}
			}
		})
	}
	req := httptest.NewRequest("POST", "/api/v1/admin/cluster", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor("admin"))
	recorder := httptest.NewRecorder()
	sentinel.ServeHTTP(recorder, req)
	if recorder.Code < 400 {
		t.Fatal("cluster endpoint accepted mutation")
	}
}
