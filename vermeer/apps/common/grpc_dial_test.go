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

package common

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestGRPCBootstrapDialHasBoundedFailure(t *testing.T) {
	previous := GetConfigDefault("grpc_dial_timeout", "5s")
	t.Cleanup(func() { SetConfig("grpc_dial_timeout", previous) })
	SetConfig("grpc_dial_timeout", "1s")
	t.Setenv("VERMEER_GRPC_DIAL_TIMEOUT", "40ms")
	started := time.Now()
	connection, err := DialGRPCPeer(context.Background(), "passthrough:///unreachable",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}))
	if connection != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("bootstrap dial did not stop at its configured deadline: %v", err)
	}
}

func TestGRPCBootstrapDialRejectsInvalidTimeout(t *testing.T) {
	for _, configured := range []string{"bad", "0s", "-1s"} {
		t.Run(configured, func(t *testing.T) {
			t.Setenv("VERMEER_GRPC_DIAL_TIMEOUT", configured)
			connection, err := DialGRPCPeer(context.Background(), "unreachable")
			if err == nil || connection != nil {
				t.Fatal("invalid timeout must fail before dialing")
			}
		})
	}
}
