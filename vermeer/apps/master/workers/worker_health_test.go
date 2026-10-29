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
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"net"
	"sync"
	"testing"
	"time"
	pb "vermeer/apps/protos"
)

func testReadyConnection(t *testing.T) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, "passthrough:///worker", grpc.WithContextDialer(
		func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func TestHealthSnapshotsRequireConnectionAndAllTaskStreams(t *testing.T) {
	worker := &WorkerClient{Id: 1, Name: "worker-one", Group: "group-one"}
	manager := &workerManager{workersByName: map[string]*WorkerClient{worker.Name: worker}}
	first := manager.HealthSnapshots()
	if first[0].Checks.Ready() || first[0].Checks.Reason() != "connection_not_ready" {
		t.Fatalf("registration must not imply readiness: %+v", first[0])
	}
	manager.SetWorkerConnection(worker, testReadyConnection(t))
	for stream := LoadTaskStream; stream < taskStreamCount; stream++ {
		if manager.HealthSnapshots()[0].Checks.Ready() {
			t.Fatal("missing task stream reported ready")
		}
		manager.SetTaskStream(worker, stream, context.Background())
	}
	ready := manager.HealthSnapshots()[0]
	if !ready.Checks.Ready() || ready.Checks.Reason() != "" {
		t.Fatalf("not ready: %+v", ready)
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager.SetTaskStream(worker, ComputeTaskStream, ctx)
	cancel()
	if check := manager.HealthSnapshots()[0].Checks; check.Ready() || check.Reason() != "compute_stream_not_ready" {
		t.Fatalf("canceled stream remained ready: %+v", check)
	}
	manager.Lock()
	worker.Group = "changed"
	manager.Unlock(nil)
	if ready.Group != "group-one" {
		t.Fatal("snapshot aliases mutable metadata")
	}
	manager.Lock()
	delete(manager.workersByName, worker.Name)
	manager.Unlock(nil)
	if remaining := manager.HealthSnapshots(); len(remaining) != 0 {
		t.Fatal("removed worker was fabricated")
	}
}

func TestOldTaskStreamCannotClearReplacement(t *testing.T) {
	worker := &WorkerClient{Name: "worker-one"}
	manager := &workerManager{workersByName: map[string]*WorkerClient{worker.Name: worker}}
	old, cancelOld := context.WithCancel(context.Background())
	defer cancelOld()
	current, cancelCurrent := context.WithCancel(context.Background())
	defer cancelCurrent()
	manager.SetTaskStream(worker, LoadTaskStream, old)
	manager.SetTaskStream(worker, LoadTaskStream, current)
	manager.ClearTaskStream(worker, LoadTaskStream, old)
	if !manager.HealthSnapshots()[0].Checks.LoadStreamReady {
		t.Fatal("old stream cleared replacement")
	}
	replacement := &WorkerClient{Name: worker.Name}
	manager.workersByName[worker.Name] = replacement
	manager.SetTaskStream(replacement, LoadTaskStream, current)
	manager.ClearTaskStream(worker, LoadTaskStream, current)
	manager.SetTaskStream(worker, LoadTaskStream, old)
	if replacement.taskStreams[LoadTaskStream] != current {
		t.Fatal("old worker modified replacement session")
	}
}

func TestConcurrentStreamChangesAndHealthSnapshots(t *testing.T) {
	worker := &WorkerClient{Name: "worker-one"}
	manager := &workerManager{workersByName: map[string]*WorkerClient{worker.Name: worker}}
	var wg sync.WaitGroup
	for stream := LoadTaskStream; stream < taskStreamCount; stream++ {
		wg.Add(1)
		go func(stream TaskStream) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				manager.SetTaskStream(worker, stream, ctx)
				_ = manager.HealthSnapshots()
				cancel()
				manager.ClearTaskStream(worker, stream, ctx)
			}
		}(stream)
	}
	wg.Wait()
}

func TestWorkerAvailabilityRespectsGroupsAndCompleteReadiness(t *testing.T) {
	connection := testReadyConnection(t)
	for _, test := range []struct {
		name         string
		groups       map[string]string
		graphNames   []string
		workerGroups []string
		incomplete   int
		want         bool
	}{
		{name: "empty", incomplete: -1},
		{name: "common ready group", workerGroups: []string{"$"}, incomplete: -1, want: true},
		{name: "foreign group", workerGroups: []string{"foreign"}, incomplete: -1},
		{name: "explicit space group", groups: map[string]string{"own-space": "dedicated"},
			workerGroups: []string{"dedicated"}, incomplete: -1, want: true},
		{name: "explicit group blocks common fallback", groups: map[string]string{"own-space": "missing"},
			workerGroups: []string{"$"}, incomplete: -1},
		{name: "own graph group", groups: map[string]string{"own-space graph": "dedicated"},
			graphNames: []string{"graph"}, workerGroups: []string{"dedicated"}, incomplete: -1, want: true},
		{name: "another space graph does not leak", groups: map[string]string{"other-space graph": "dedicated"},
			graphNames: []string{"graph"}, workerGroups: []string{"dedicated"}, incomplete: -1},
		{name: "one incomplete member fails entire group", workerGroups: []string{"$", "$"}, incomplete: 1},
		{name: "ready own graph group survives incomplete common group", groups: map[string]string{"own-space graph": "dedicated"},
			graphNames: []string{"graph"}, workerGroups: []string{"$", "dedicated"}, incomplete: 0, want: true},
		{name: "ready foreign group cannot rescue own incomplete group", groups: map[string]string{"own-space": "own"},
			workerGroups: []string{"own", "foreign"}, incomplete: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := &workerManager{workersByName: map[string]*WorkerClient{}, groupMapper: test.groups}
			for index, group := range test.workerGroups {
				worker := &WorkerClient{Name: group + string(rune('a'+index)), Group: group}
				manager.workersByName[worker.Name] = worker
				manager.SetWorkerConnection(worker, connection)
				for stream := LoadTaskStream; stream < taskStreamCount; stream++ {
					if index == test.incomplete && stream == ComputeTaskStream {
						continue
					}
					manager.SetTaskStream(worker, stream, context.Background())
				}
			}
			if got := manager.HasAvailableWorkers("own-space", test.graphNames); got != test.want {
				t.Fatalf("availability %v, want %v", got, test.want)
			}
		})
	}
}

func TestWorkerAvailabilityCannotUsePendingOrCanceledConnections(t *testing.T) {
	worker := &WorkerClient{Name: "worker", Group: "$"}
	manager := &workerManager{workersByName: map[string]*WorkerClient{worker.Name: worker}}
	for stream := LoadTaskStream; stream < taskStreamCount; stream++ {
		manager.SetTaskStream(worker, stream, context.Background())
	}
	if manager.HasAvailableWorkers("space", nil) {
		t.Fatal("streams without reverse connection reported available")
	}
	connection := testReadyConnection(t)
	manager.SetWorkerConnection(worker, connection)
	if !manager.HasAvailableWorkers("space", nil) {
		t.Fatal("ready common worker unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager.SetTaskStream(worker, SuperStepStream, ctx)
	cancel()
	if manager.HasAvailableWorkers("space", nil) {
		t.Fatal("canceled task stream reported available")
	}
	manager.SetTaskStream(worker, SuperStepStream, context.Background())
	_ = connection.Close()
	if manager.HasAvailableWorkers("space", nil) {
		t.Fatal("closed reverse connection reported available")
	}
}

func TestHealthSnapshotHonorsUpstreamOfflineCleanup(t *testing.T) {
	worker := &WorkerClient{Name: "worker", Group: "$"}
	manager := &workerManager{workersByName: map[string]*WorkerClient{worker.Name: worker}}
	manager.SetWorkerConnection(worker, testReadyConnection(t))
	for stream := LoadTaskStream; stream < taskStreamCount; stream++ {
		manager.SetTaskStream(worker, stream, context.Background())
	}
	manager.Lock()
	worker.offlineCleanup = true
	manager.Unlock(nil)
	snapshot := manager.HealthSnapshots()[0]
	if snapshot.Checks.Ready() || snapshot.Checks.Reason() != "worker_session_ended" ||
		manager.IsWorkerReady(worker) || manager.HasAvailableWorkers("space", nil) {
		t.Fatalf("snapshot overrode upstream cleanup: %+v", snapshot.Checks)
	}
}

func TestHealthSnapshotWaitsForSessionPublication(t *testing.T) {
	worker := &WorkerClient{Name: "worker", Group: "$"}
	manager := &workerManager{workersByName: map[string]*WorkerClient{worker.Name: worker}}
	connection := testReadyConnection(t)
	started, published := make(chan struct{}), make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		close(started)
		for {
			_ = manager.HealthSnapshots()
			select {
			case <-published:
				return
			default:
			}
		}
	}()
	<-started
	// Mirror upstream registration: Session is assigned before Connection is
	// published under the manager lock. Snapshot readers must not race that write.
	worker.Session = pb.NewWorkerClient(connection)
	manager.SetWorkerConnection(worker, connection)
	close(published)
	readers.Wait()
	if manager.HealthSnapshots()[0].Session == nil {
		t.Fatal("published worker session was omitted")
	}
}
