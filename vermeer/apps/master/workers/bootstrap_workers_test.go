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
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"vermeer/apps/common"
	"vermeer/apps/storage"
)

func TestBootstrapExcludesEndedSessionsWithoutDroppingNewPeers(t *testing.T) {
	connection := readyWorkerConnection(t)
	fresh := &WorkerClient{Name: "fresh", Id: 1}
	active := &WorkerClient{Name: "active", Id: 2, Connection: connection, taskStreams: readyTaskStreams()}
	ended := &WorkerClient{Name: "ended", Id: 3, Connection: connection, taskStreams: readyTaskStreams()}
	canceledCtx, cancel := context.WithCancel(context.Background())
	canceled := &WorkerClient{Name: "canceled", Id: 4, Connection: connection, taskStreams: readyTaskStreams()}
	canceled.taskStreams[LoadTaskStream] = canceledCtx
	manager := workerManager{workersByName: map[string]*WorkerClient{
		fresh.Name: fresh, active.Name: active, ended.Name: ended, canceled.Name: canceled,
	}}
	manager.ClearTaskStream(ended, LoadTaskStream, ended.taskStreams[LoadTaskStream])
	cancel()
	peers := manager.GetBootstrapWorkers()
	if len(peers) != 2 || peers[0] != fresh || peers[1] != active {
		t.Fatal("bootstrap must preserve fresh/active peers and omit ended streams even with ready transport")
	}
	if manager.CheckWorkerAlive(ended.Name) {
		t.Fatal("an ended session cannot remain alive")
	}
}

func TestOfflineCleanupCannotTouchReplacementSession(t *testing.T) {
	previous := common.PrometheusMetrics.WorkerCnt
	common.PrometheusMetrics.WorkerCnt = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_session_cleanup"}, nil)
	t.Cleanup(func() { common.PrometheusMetrics.WorkerCnt = previous })
	connection := readyWorkerConnection(t)
	old := &WorkerClient{Name: "reused", Connection: connection, taskStreams: readyTaskStreams()}
	manager := workerManager{workersByName: map[string]*WorkerClient{old.Name: old}}
	oldCtx := old.taskStreams[LoadTaskStream]
	replacementCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.SetTaskStream(old, LoadTaskStream, replacementCtx)
	manager.ClearTaskStream(old, LoadTaskStream, oldCtx)
	if len(manager.GetBootstrapWorkers()) != 1 {
		t.Fatal("old stream EOF must not terminate its replacement")
	}
	manager.ClearTaskStream(old, LoadTaskStream, replacementCtx)
	var claimed atomic.Int32
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if manager.ClaimOfflineSession(old) {
				claimed.Add(1)
			}
		}()
	}
	wait.Wait()
	if manager.CanReplaceDisconnectedSession(old) {
		t.Fatal("an already claimed cleanup must wait rather than be reclaimed")
	}
	if claimed.Load() != 1 {
		t.Fatal("only one EOF handler may clean up a session")
	}
	newer := &WorkerClient{Name: old.Name, Connection: connection, taskStreams: readyTaskStreams()}
	manager.workersByName[old.Name] = newer
	manager.RemoveWorkerSession(old)
	manager.ClearTaskStream(old, LoadTaskStream, replacementCtx)
	if manager.GetWorker(newer.Name) != newer || !manager.IsWorkerReady(newer) {
		t.Fatal("late cleanup or EOF must not remove or terminate a new registration")
	}
}

func TestAbandonedRegistrationCanRegisterAgain(t *testing.T) {
	previous := common.PrometheusMetrics.WorkerCnt
	common.PrometheusMetrics.WorkerCnt = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_abandoned_registration"}, nil)
	t.Cleanup(func() { common.PrometheusMetrics.WorkerCnt = previous })
	connection, err := grpc.NewClient("passthrough:///abandoned",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return nil, errors.New("worker gone") }))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.Connect()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for connection.GetState() != connectivity.TransientFailure {
		state := connection.GetState()
		if !connection.WaitForStateChange(ctx, state) {
			t.Fatal("expected a disconnected reverse transport")
		}
	}
	store, err := storage.NewPebbleStore(storage.StoreOption{Path: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager := workerManager{workersByName: map[string]*WorkerClient{}, idSeed: 1, store: store}
	old := &WorkerClient{Name: "persisted-name", GrpcPeer: "127.0.0.1:6789", Connection: connection}
	if _, err := manager.AddWorker(old); err != nil {
		t.Fatal(err)
	}
	if !manager.IsAbandonedRegistration(old) || !manager.CanReplaceDisconnectedSession(old) {
		t.Fatal("disconnected registration without a lifeline must be reclaimable")
	}
	fresh := &WorkerClient{Name: "new"}
	manager.workersByName[fresh.Name] = fresh
	if manager.IsAbandonedRegistration(fresh) || manager.CanReplaceDisconnectedSession(fresh) {
		t.Fatal("an in-progress registration without a reverse connection is not abandoned")
	}
	active := &WorkerClient{Name: "active", Connection: connection, taskStreams: readyTaskStreams()}
	manager.workersByName[active.Name] = active
	if manager.IsAbandonedRegistration(active) {
		t.Fatal("a peer with live task streams cannot be skipped merely for transient transport failure")
	}
	oldStream := active.taskStreams[LoadTaskStream]
	replacementStream, done := context.WithCancel(context.Background())
	defer done()
	manager.SetTaskStream(active, LoadTaskStream, replacementStream)
	manager.ClearTaskStream(active, LoadTaskStream, oldStream)
	if manager.ClaimOfflineSession(active) || manager.CanReplaceDisconnectedSession(active) {
		t.Fatal("an obsolete stream EOF must not claim replacement live streams even during transient transport failure")
	}

	if !manager.ClaimOfflineSession(old) {
		t.Fatal("old abandoned registration must be claimed exactly once")
	}
	manager.RemoveWorkerSession(old)
	replacement, err := manager.CreateWorker(old.GrpcPeer, "127.0.0.1", "test-version", "$")
	if err != nil {
		t.Fatal(err)
	}
	replacement.Connection = readyWorkerConnection(t)
	if _, err := manager.AddWorker(replacement); err != nil {
		t.Fatalf("same-address re-registration is blocked by a ghost: %v", err)
	}
	if replacement.Name != old.Name || manager.GetWorker(old.Name) != replacement {
		t.Fatal("re-registration must preserve its stored identity with a new session")
	}
}
