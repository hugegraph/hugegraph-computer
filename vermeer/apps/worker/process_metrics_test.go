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
	"net"
	"testing"
	"time"
	pb "vermeer/apps/protos"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestProcessMetricsTravelThroughWorkerRPC(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterWorkerServer(server, &PeerHandler{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, "passthrough:///worker-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	response, err := pb.NewWorkerClient(connection).GetWorkerStatInfo(ctx, &pb.WorkerStatInfoReq{})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetBase() == nil || response.GetMetricSchemaVersion() != 1 || response.GetMetricsObservedAt() <= 0 {
		t.Fatalf("missing resource protocol metadata: %v", response)
	}
	if response.GetMetricError() == "" {
		if response.GetProcessRssBytes() == 0 || response.GetSampleWindowSeconds() <= 0 {
			t.Fatalf("successful resource snapshot needs RSS and a real CPU window: %v", response)
		}
	} else if response.GetMetricError() != "metrics_warming_up" &&
		response.GetMetricError() != "process_metrics_unavailable" {
		t.Fatalf("unexpected collection failure: %s", response.GetMetricError())
	}
}
