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
	"math"
	"net/http"
	"sync"
	"time"
	"vermeer/apps/common"
	"vermeer/apps/master/workers"
	pb "vermeer/apps/protos"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ClusterMetricStatus struct {
	Availability string `json:"availability"`
	ObservedAt   int64  `json:"observed_at"`
	Reason       string `json:"reason,omitempty"`
}

type ClusterNode struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Role         string                 `json:"role"`
	Group        string                 `json:"group,omitempty"`
	GrpcPeer     string                 `json:"grpc_peer"`
	Version      string                 `json:"version"`
	LaunchTime   time.Time              `json:"launch_time"`
	Status       string                 `json:"status"`
	Ready        bool                   `json:"ready"`
	Reason       string                 `json:"reason,omitempty"`
	Checks       map[string]bool        `json:"checks"`
	Metrics      map[string]interface{} `json:"metrics"`
	MetricStatus ClusterMetricStatus    `json:"metric_status"`
}

type ClusterSnapshot struct {
	SchemaVersion     int           `json:"schema_version"`
	ObservedAt        int64         `json:"observed_at"`
	Status            string        `json:"status"`
	Reason            string        `json:"reason,omitempty"`
	RegisteredWorkers int           `json:"registered_workers"`
	ReadyWorkers      int           `json:"ready_workers"`
	Master            ClusterNode   `json:"master"`
	Workers           []ClusterNode `json:"workers"`
}

// Registered exclusively in SetAdminRouters, after the configured auth/admin
// filters. Like the existing admin APIs, anonymous mode retains its semantics.
type AdminClusterHandler struct{ common.SenHandler }

func (h *AdminClusterHandler) GET(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, collectClusterSnapshot(ctx.Request.Context()))
}

func collectClusterSnapshot(parent context.Context) ClusterSnapshot {
	now := time.Now().UnixMilli()
	snapshots := WorkerMgr.HealthSnapshots()
	info := InfoMaster.snapshot()
	return buildClusterSnapshot(parent, info, snapshots, now)
}

func buildClusterSnapshot(parent context.Context, info MasterInfoSnapshot,
	snapshots []workers.WorkerHealthSnapshot, now int64) ClusterSnapshot {
	result := ClusterSnapshot{
		SchemaVersion: 1, ObservedAt: now, Status: "UP",
		RegisteredWorkers: len(snapshots),
		Master:            clusterMasterNode(info, now),
		Workers:           make([]ClusterNode, len(snapshots)),
	}
	for index, snapshot := range snapshots {
		result.Workers[index] = clusterWorkerMetadata(snapshot, now)
	}
	// One total deadline and bounded fanout prevent telemetry from delaying health
	// indefinitely. Worker metadata is already copied, so no lock spans an RPC.
	ctx, cancel := context.WithTimeout(parent, 800*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	count := len(snapshots)
	if count > 8 {
		count = 8
	}
	jobs := make(chan int, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case index, ok := <-jobs:
					if !ok || ctx.Err() != nil {
						return
					}
					result.Workers[index] = collectWorkerMetrics(ctx, snapshots[index], result.Workers[index], now)
				}
			}
		}()
	}
enqueue:
	for index := range snapshots {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			break enqueue
		case jobs <- index:
		}
	}
	close(jobs)
	wg.Wait()
	for index, worker := range result.Workers {
		if ctx.Err() != nil && worker.MetricStatus.Reason == "metrics_not_collected" {
			result.Workers[index].MetricStatus.Reason = "metrics_timeout"
		}
		if worker.Ready {
			result.ReadyWorkers++
		}
	}
	switch {
	case !result.Master.Ready:
		result.Status, result.Reason = "DEGRADED", result.Master.Reason
	case len(snapshots) == 0:
		result.Status, result.Reason = "DEGRADED", "no_workers"
	case result.ReadyWorkers != result.RegisteredWorkers:
		result.Status, result.Reason = "DEGRADED", "workers_not_ready"
	}
	return result
}

func clusterMasterNode(info MasterInfoSnapshot, now int64) ClusterNode {
	offline := common.GetConfigDefault("service_offline", false)
	checks := map[string]bool{
		"http_ready":     true,
		"initialized":    !info.LaunchTime.IsZero(),
		"service_online": offline != true && offline != "true",
	}
	ready := checks["initialized"] && checks["service_online"]
	node := ClusterNode{ID: "master", Name: "Vermeer Master", Role: "MASTER",
		GrpcPeer: info.GrpcPeer, Version: info.Version, LaunchTime: info.LaunchTime,
		Status: "UP", Ready: ready, Checks: checks, Metrics: map[string]interface{}{}}
	if !ready {
		node.Status, node.Reason = "DEGRADED", "master_initializing"
		if !checks["service_online"] {
			node.Reason = "service_offline"
		}
	}
	metrics, err := common.ReadProcessMetrics()
	if err != nil {
		node.MetricStatus = ClusterMetricStatus{"UNAVAILABLE", now, err.Error()}
	} else {
		node.Metrics = processMetricValues(metrics.CPUCores, metrics.RSSBytes, metrics.SampleWindowSeconds)
		node.MetricStatus = ClusterMetricStatus{"AVAILABLE", metrics.ObservedAt, ""}
	}
	return node
}

func clusterWorkerNode(ctx context.Context, snapshot workers.WorkerHealthSnapshot, now int64) ClusterNode {
	return collectWorkerMetrics(ctx, snapshot, clusterWorkerMetadata(snapshot, now), now)
}

func clusterWorkerMetadata(snapshot workers.WorkerHealthSnapshot, now int64) ClusterNode {
	checks := snapshot.Checks
	node := ClusterNode{ID: snapshot.Name, Name: snapshot.Name, Role: "WORKER",
		Group: snapshot.Group, GrpcPeer: snapshot.GrpcPeer, Version: snapshot.Version,
		LaunchTime: snapshot.LaunchTime, Status: "UP", Ready: checks.Ready(),
		Reason: checks.Reason(), Checks: map[string]bool{
			"registered": checks.Registered, "connection_ready": checks.ConnectionReady,
			"load_stream_ready": checks.LoadStreamReady, "compute_stream_ready": checks.ComputeStreamReady,
			"superstep_stream_ready": checks.SuperstepStreamReady,
		}, Metrics: map[string]interface{}{},
		MetricStatus: ClusterMetricStatus{"UNAVAILABLE", now, "connection_not_ready"},
	}
	if !node.Ready {
		node.Status = "DEGRADED"
	}
	if checks.ConnectionReady && snapshot.Session != nil {
		node.MetricStatus.Reason = "metrics_not_collected"
	}
	return node
}

func collectWorkerMetrics(ctx context.Context, snapshot workers.WorkerHealthSnapshot, node ClusterNode, now int64) ClusterNode {
	if !snapshot.Checks.ConnectionReady || snapshot.Session == nil {
		return node
	}
	if ctx.Err() != nil {
		node.MetricStatus = ClusterMetricStatus{"UNAVAILABLE", now, "metrics_timeout"}
		return node
	}
	response, err := snapshot.Session.GetWorkerStatInfo(ctx, &pb.WorkerStatInfoReq{})
	if err != nil {
		reason := "metrics_rpc_failed"
		availability := "UNAVAILABLE"
		switch status.Code(err) {
		case codes.Unimplemented:
			availability, reason = "UNSUPPORTED", "runtime_metrics_unsupported"
		case codes.DeadlineExceeded, codes.Canceled:
			reason = "metrics_timeout"
		}
		node.MetricStatus = ClusterMetricStatus{availability, now, reason}
		return node
	}
	if response == nil || response.GetMetricSchemaVersion() != 1 {
		node.MetricStatus = ClusterMetricStatus{"UNSUPPORTED", now, "runtime_metrics_unsupported"}
		return node
	}
	if response.GetMetricError() != "" {
		node.MetricStatus = ClusterMetricStatus{"UNAVAILABLE", now, response.GetMetricError()}
		return node
	}
	cpu, window := response.GetProcessCpuCores(), response.GetSampleWindowSeconds()
	if cpu < 0 || math.IsNaN(cpu) || math.IsInf(cpu, 0) || window <= 0 ||
		math.IsNaN(window) || math.IsInf(window, 0) || response.GetMetricsObservedAt() <= 0 {
		node.MetricStatus = ClusterMetricStatus{"UNAVAILABLE", now, "invalid_runtime_metrics"}
		return node
	}
	node.Metrics = processMetricValues(cpu, response.GetProcessRssBytes(), window)
	node.MetricStatus = ClusterMetricStatus{"AVAILABLE", response.GetMetricsObservedAt(), ""}
	return node
}

func processMetricValues(cpu float64, rss uint64, window float64) map[string]interface{} {
	return map[string]interface{}{"cpu_cores": cpu, "rss_bytes": rss, "sample_window_seconds": window}
}
