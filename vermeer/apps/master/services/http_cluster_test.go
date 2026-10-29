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
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"math"
	"net/http/httptest"
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
