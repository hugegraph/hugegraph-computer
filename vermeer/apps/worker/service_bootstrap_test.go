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
	"errors"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"vermeer/apps/common"
	pb "vermeer/apps/protos"
)

type unavailableBootstrapMaster struct {
	pb.UnimplementedMasterServer
	peer           string
	lifelineClosed chan struct{}
}

func (m *unavailableBootstrapMaster) SayHelloMaster(context.Context, *pb.HelloMasterReq) (*pb.HelloMasterResp, error) {
	return &pb.HelloMasterResp{WorkerId: 1, WorkerName: "joining", Workers: []*pb.WorkerInfo{{Name: "stale", Id: 2, GrpcPeer: m.peer}}}, nil
}
func (m *unavailableBootstrapMaster) LoadGraphTask(stream pb.Master_LoadGraphTaskServer) error {
	<-stream.Context().Done()
	close(m.lifelineClosed)
	return nil
}

func TestWorkerBootstrapFailureReturnsAndClosesRegistrationLifeline(t *testing.T) {
	previousMaster := common.GetConfig("master_peer")
	previousPeer := common.GetConfig("grpc_peer")
	previousMetrics := common.PrometheusMetrics.WorkerCnt
	t.Cleanup(func() {
		common.SetConfig("master_peer", previousMaster)
		common.SetConfig("grpc_peer", previousPeer)
		common.PrometheusMetrics.WorkerCnt = previousMetrics
	})
	common.PrometheusMetrics.WorkerCnt = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_bootstrap_workers"}, nil)
	t.Setenv("VERMEER_GRPC_DIAL_TIMEOUT", "400ms")
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	go func() {
		conn, err := blackhole.Accept()
		if err == nil {
			defer conn.Close()
			buffer := make([]byte, 4096)
			for {
				if _, err = conn.Read(buffer); err != nil {
					return
				}
			}
		}
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	master := &unavailableBootstrapMaster{peer: blackhole.Addr().String(), lifelineClosed: make(chan struct{})}
	server := grpc.NewServer()
	pb.RegisterMasterServer(server, master)
	go server.Serve(listener)
	defer server.Stop()
	common.SetConfig("master_peer", listener.Addr().String())
	common.SetConfig("grpc_peer", "127.0.0.1:6789")
	service := new(Service)
	started := time.Now()
	err = service.Init()
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatalf("stale peer must fail bounded Init: %v", err)
	}
	if service.masterConn.GetState() != connectivity.Shutdown {
		t.Fatal("failed bootstrap must close master transport")
	}
	select {
	case <-master.lifelineClosed:
	case <-time.After(time.Second):
		t.Fatal("failed bootstrap must close its registration lifeline")
	}
}
