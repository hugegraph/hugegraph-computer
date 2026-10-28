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

package worker

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"io"
	"sync"
	"testing"
	"time"
	"vermeer/apps/common"
	pb "vermeer/apps/protos"
)

type peerStreamFixture struct {
	grpc.ServerStream
	ctx         context.Context
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func (f *peerStreamFixture) Context() context.Context { return f.ctx }
func (f *peerStreamFixture) eof() error {
	f.enteredOnce.Do(func() { close(f.entered) })
	<-f.release
	return io.EOF
}
func (f *peerStreamFixture) finish() { f.releaseOnce.Do(func() { close(f.release) }) }
func newPeerStreamFixture(t *testing.T, ctx context.Context) *peerStreamFixture {
	t.Helper()
	f := &peerStreamFixture{ctx: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(f.finish)
	return f
}
func peerTestMetrics(t *testing.T) {
	t.Helper()
	previous := common.PrometheusMetrics.WorkerCnt
	common.PrometheusMetrics.WorkerCnt = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_peer_stream_generations"}, nil)
	PeerMgr.Init()
	t.Cleanup(func() { PeerMgr.Init(); common.PrometheusMetrics.WorkerCnt = previous })
}
func peerCount(t *testing.T) float64 {
	t.Helper()
	metric := new(dto.Metric)
	if err := common.PrometheusMetrics.WorkerCnt.WithLabelValues().Write(metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetGauge().GetValue()
}
func awaitPeerEvent(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("peer stream did not reach expected lifecycle event")
	}
}

type testScatterServer struct{ *peerStreamFixture }

func (f *testScatterServer) Recv() (*pb.ScatterReq, error) { return nil, f.eof() }
func (f *testScatterServer) Send(*pb.ScatterResp) error    { return nil }

type testLoadActionServer struct{ *peerStreamFixture }

func (f *testLoadActionServer) Recv() (*pb.LoadActionReq, error) { return nil, f.eof() }
func (f *testLoadActionServer) Send(*pb.LoadActionResp) error    { return nil }

type testStepEndServer struct{ *peerStreamFixture }

func (f *testStepEndServer) Recv() (*pb.StepEndReq, error) { return nil, f.eof() }
func (f *testStepEndServer) Send(*pb.StepEndResp) error    { return nil }

type testSettingActionServer struct{ *peerStreamFixture }

func (f *testSettingActionServer) Recv() (*pb.SettingActionReq, error) { return nil, f.eof() }
func (f *testSettingActionServer) Send(*pb.SettingActionResp) error    { return nil }

type testScatterClient struct {
	grpc.ClientStream
	fixture *peerStreamFixture
}

func (f *testScatterClient) Context() context.Context       { return f.fixture.ctx }
func (f *testScatterClient) Recv() (*pb.ScatterResp, error) { return nil, f.fixture.eof() }
func (f *testScatterClient) Send(*pb.ScatterReq) error      { return nil }

type testLoadActionClient struct {
	grpc.ClientStream
	fixture *peerStreamFixture
}

func (f *testLoadActionClient) Context() context.Context          { return f.fixture.ctx }
func (f *testLoadActionClient) Recv() (*pb.LoadActionResp, error) { return nil, f.fixture.eof() }
func (f *testLoadActionClient) Send(*pb.LoadActionReq) error      { return nil }

type testStepEndClient struct {
	grpc.ClientStream
	fixture *peerStreamFixture
}

func (f *testStepEndClient) Context() context.Context       { return f.fixture.ctx }
func (f *testStepEndClient) Recv() (*pb.StepEndResp, error) { return nil, f.fixture.eof() }
func (f *testStepEndClient) Send(*pb.StepEndReq) error      { return nil }

type testSettingActionClient struct {
	grpc.ClientStream
	fixture *peerStreamFixture
}

func (f *testSettingActionClient) Context() context.Context             { return f.fixture.ctx }
func (f *testSettingActionClient) Recv() (*pb.SettingActionResp, error) { return nil, f.fixture.eof() }
func (f *testSettingActionClient) Send(*pb.SettingActionReq) error      { return nil }

type peerStreamTestCase struct {
	name string
	bind func(*PeerClient, *peerStreamFixture) func()
	rpc  func(*peerStreamFixture) error
}

func peerStreamTestCases() []peerStreamTestCase {
	return []peerStreamTestCase{
		{"Scatter", func(peer *PeerClient, f *peerStreamFixture) func() {
			peer.ScatterHandler.SetServer(&testScatterServer{f})
			return func() { peer.ScatterHandler.RecvHandler(peer.Name) }
		}, func(f *peerStreamFixture) error { return new(PeerHandler).Scatter(&testScatterServer{f}) }},
		{"LoadAction", func(peer *PeerClient, f *peerStreamFixture) func() {
			peer.LoadActionHandler.SetServer(&testLoadActionServer{f})
			return func() { peer.LoadActionHandler.RecvHandler(peer.Name) }
		}, func(f *peerStreamFixture) error { return new(PeerHandler).LoadAction(&testLoadActionServer{f}) }},
		{"StepEnd", func(peer *PeerClient, f *peerStreamFixture) func() {
			peer.StepEndHandler.SetServer(&testStepEndServer{f})
			return func() { peer.StepEndHandler.RecvHandler(peer.Name) }
		}, func(f *peerStreamFixture) error { return new(PeerHandler).StepEnd(&testStepEndServer{f}) }},
		{"SettingAction", func(peer *PeerClient, f *peerStreamFixture) func() {
			peer.SettingActionHandler.SetServer(&testSettingActionServer{f})
			return func() { peer.SettingActionHandler.RecvHandler(peer.Name) }
		}, func(f *peerStreamFixture) error { return new(PeerHandler).SettingAction(&testSettingActionServer{f}) }},
	}
}

func peerClientTestCases() []peerStreamTestCase {
	return []peerStreamTestCase{
		{"Scatter/client", func(peer *PeerClient, f *peerStreamFixture) func() {
			peer.ScatterHandler.SetClient(&testScatterClient{fixture: f})
			return func() { peer.ScatterHandler.RecvHandler(peer.Name) }
		}, nil},
		{"LoadAction/client", func(peer *PeerClient, f *peerStreamFixture) func() {
			peer.LoadActionHandler.SetClient(&testLoadActionClient{fixture: f})
			return func() { peer.LoadActionHandler.RecvHandler(peer.Name) }
		}, nil},
		{"StepEnd/client", func(peer *PeerClient, f *peerStreamFixture) func() {
			peer.StepEndHandler.SetClient(&testStepEndClient{fixture: f})
			return func() { peer.StepEndHandler.RecvHandler(peer.Name) }
		}, nil},
		{"SettingAction/client", func(peer *PeerClient, f *peerStreamFixture) func() {
			peer.SettingActionHandler.SetClient(&testSettingActionClient{fixture: f})
			return func() { peer.SettingActionHandler.RecvHandler(peer.Name) }
		}, nil},
	}
}

func TestPeerOldEOFDoesNotRemoveNewRegistrationOrStream(t *testing.T) {
	for _, test := range append(peerStreamTestCases(), peerClientTestCases()...) {
		for _, replacePeer := range []bool{false, true} {
			suffix := "rebound-stream"
			if replacePeer {
				suffix = "new-hello"
			}
			t.Run(test.name+"/"+suffix, func(t *testing.T) {
				peerTestMetrics(t)
				old := PeerMgr.AddPeer("peer", 1, "127.0.0.1:6789")
				first := newPeerStreamFixture(t, context.Background())
				receive := test.bind(old, first)
				done := make(chan struct{})
				go func() { receive(); close(done) }()
				awaitPeerEvent(t, first.entered)
				current := old
				if replacePeer {
					current = PeerMgr.AddPeer("peer", 1, "127.0.0.1:6789")
				}
				second := newPeerStreamFixture(t, context.Background())
				receiveNew := test.bind(current, second)
				first.finish()
				awaitPeerEvent(t, done)
				if PeerMgr.GetPeer("peer") != current || peerCount(t) != 1 {
					t.Fatal("old EOF removed replacement registration/stream or inflated peer metric")
				}
				second.finish()
				receiveNew()
				if PeerMgr.GetPeer("peer") != nil || peerCount(t) != 0 {
					t.Fatal("current EOF must retire exactly its own session")
				}
			})
		}
	}
}

func TestPeerRPCRequiresRegistrationMetadata(t *testing.T) {
	for _, test := range peerStreamTestCases() {
		t.Run(test.name, func(t *testing.T) {
			peerTestMetrics(t)
			missing := newPeerStreamFixture(t, context.Background())
			if status.Code(test.rpc(missing)) != codes.InvalidArgument {
				t.Fatal("missing worker metadata must not panic")
			}
			unknown := newPeerStreamFixture(t, metadata.NewIncomingContext(context.Background(), metadata.Pairs("worker_name", "missing")))
			if status.Code(test.rpc(unknown)) != codes.FailedPrecondition {
				t.Fatal("unknown worker must register before streaming")
			}
		})
	}
}

func TestReplacingPeerCancelsOldServerRPC(t *testing.T) {
	peerTestMetrics(t)
	PeerMgr.AddPeer("peer", 1, "127.0.0.1:6789")
	fixture := newPeerStreamFixture(t, metadata.NewIncomingContext(context.Background(), metadata.Pairs("worker_name", "peer")))
	done := make(chan struct{})
	go func() { _ = new(PeerHandler).Scatter(&testScatterServer{fixture}); close(done) }()
	awaitPeerEvent(t, fixture.entered)
	replacement := PeerMgr.AddPeer("peer", 1, "127.0.0.1:6789")
	awaitPeerEvent(t, done)
	if PeerMgr.GetPeer("peer") != replacement {
		t.Fatal("retiring RPC must preserve replacement peer")
	}
	fixture.finish()
}

func TestPeerConnectionPublicationCannotReviveOldHello(t *testing.T) {
	peerTestMetrics(t)
	old := PeerMgr.AddPeer("peer", 1, "127.0.0.1:6789")
	current := PeerMgr.AddPeer("peer", 1, "127.0.0.1:6789")
	connection, err := grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	if PeerMgr.SetPeerConnection(old, connection) || connection.GetState() != connectivity.Shutdown {
		t.Fatal("late connection must be rejected and closed")
	}
	if PeerMgr.GetPeer("peer") != current || peerCount(t) != 1 {
		t.Fatal("connection race must not change current registration")
	}
}
