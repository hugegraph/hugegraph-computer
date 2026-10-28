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
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
)

// DialGRPCPeer bounds blocking bootstrap connections without changing stream lifetimes.
func DialGRPCPeer(ctx context.Context, target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	configured := os.Getenv("VERMEER_GRPC_DIAL_TIMEOUT")
	if configured == "" {
		configured = fmt.Sprint(GetConfigDefault("grpc_dial_timeout", "5s"))
	}
	timeout, err := time.ParseDuration(configured)
	if err != nil || timeout <= 0 {
		return nil, fmt.Errorf("grpc_dial_timeout / VERMEER_GRPC_DIAL_TIMEOUT must be a positive duration")
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	options = append(options, grpc.WithBlock(), grpc.WithIdleTimeout(0))
	return grpc.DialContext(dialCtx, target, options...)
}
