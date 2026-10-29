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

package workers

import (
	"sort"
	"time"
	pb "vermeer/apps/protos"

	"google.golang.org/grpc/connectivity"
)

// WorkerHealthSnapshot is a value copy. Live sessions are retained only for a
// bounded metrics RPC after releasing the manager lock, never serialized.
type WorkerHealthSnapshot struct {
	ID         int32
	Name       string
	Group      string
	GrpcPeer   string
	Version    string
	LaunchTime time.Time
	Checks     ReadinessChecks
	Session    pb.WorkerClient
}

type ReadinessChecks struct {
	Registered           bool `json:"registered"`
	ConnectionReady      bool `json:"connection_ready"`
	LoadStreamReady      bool `json:"load_stream_ready"`
	ComputeStreamReady   bool `json:"compute_stream_ready"`
	SuperstepStreamReady bool `json:"superstep_stream_ready"`
	sessionEnded         bool
}

func (checks ReadinessChecks) Ready() bool {
	return !checks.sessionEnded && checks.Registered && checks.ConnectionReady && checks.LoadStreamReady &&
		checks.ComputeStreamReady && checks.SuperstepStreamReady
}

func (checks ReadinessChecks) Reason() string {
	switch {
	case !checks.Registered:
		return "worker_not_registered"
	case !checks.ConnectionReady:
		return "connection_not_ready"
	case !checks.LoadStreamReady:
		return "load_stream_not_ready"
	case !checks.ComputeStreamReady:
		return "compute_stream_not_ready"
	case !checks.SuperstepStreamReady:
		return "superstep_stream_not_ready"
	case checks.sessionEnded:
		return "worker_session_ended"
	default:
		return ""
	}
}

func (wm *workerManager) HealthSnapshots() []WorkerHealthSnapshot {
	defer wm.Unlock(wm.Lock())
	result := make([]WorkerHealthSnapshot, 0, len(wm.workersByName))
	for _, worker := range wm.workersByName {
		checks := wm.readinessChecksLocked(worker)
		snapshot := WorkerHealthSnapshot{
			ID: worker.Id, Name: worker.Name, Group: worker.Group,
			GrpcPeer: worker.GrpcPeer, Version: worker.Version,
			LaunchTime: worker.LaunchTime, Checks: checks,
		}
		// Registration writes Session before publishing Connection under this lock.
		// Do not read that field while a registration is still in progress.
		if checks.ConnectionReady {
			snapshot.Session = worker.Session
		}
		result = append(result, snapshot)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (wm *workerManager) readinessChecksLocked(worker *WorkerClient) ReadinessChecks {
	checks := ReadinessChecks{}
	if worker == nil || wm.workersByName[worker.Name] != worker {
		return checks
	}
	checks.Registered = true
	checks.ConnectionReady = worker.Connection != nil && worker.Connection.GetState() == connectivity.Ready
	live := func(stream TaskStream) bool {
		ctx := worker.taskStreams[stream]
		return ctx != nil && ctx.Err() == nil
	}
	checks.LoadStreamReady = live(LoadTaskStream)
	checks.ComputeStreamReady = live(ComputeTaskStream)
	checks.SuperstepStreamReady = live(SuperStepStream)
	// Reuse the authoritative lifecycle gate, including offline-cleanup ownership.
	checks.sessionEnded = checks.Ready() && !wm.workerReadyLocked(worker)
	return checks
}
