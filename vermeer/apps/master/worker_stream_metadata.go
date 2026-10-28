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

package master

import (
	"context"
	"strings"
	"vermeer/apps/master/workers"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var registeredWorkerStreamMethods = map[string]struct{}{
	"/master.Master/LoadGraphTask": {},
	"/master.Master/ComputeTask":   {},
	"/master.Master/SuperStep":     {},
}

func validateWorkerStreamMetadata(ctx context.Context, fullMethod string) error {
	if _, required := registeredWorkerStreamMethods[fullMethod]; !required {
		return nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.InvalidArgument,
			"worker_name metadata is required")
	}
	names := md.Get("worker_name")
	if len(names) != 1 || names[0] == "" || strings.TrimSpace(names[0]) != names[0] {
		return status.Error(codes.InvalidArgument,
			"worker_name metadata must contain exactly one non-empty value")
	}
	if workers.WorkerManager.GetWorker(names[0]) == nil {
		return status.Error(codes.FailedPrecondition,
			"worker must register before opening task streams")
	}
	return nil
}

func validateWorkerStream(
	srv any,
	stream grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if err := validateWorkerStreamMetadata(stream.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, stream)
}
