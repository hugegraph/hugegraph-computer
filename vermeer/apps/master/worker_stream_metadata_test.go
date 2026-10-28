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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestValidateWorkerStreamMetadataRejectsInvalidIdentity(t *testing.T) {
	methods := []string{
		"/master.Master/LoadGraphTask",
		"/master.Master/ComputeTask",
		"/master.Master/SuperStep",
	}
	invalid := []struct {
		name string
		ctx  context.Context
	}{
		{"missing", context.Background()},
		{"empty", metadata.NewIncomingContext(context.Background(),
			metadata.Pairs("worker_name", ""))},
		{"padded", metadata.NewIncomingContext(context.Background(),
			metadata.Pairs("worker_name", " worker "))},
		{"duplicate", metadata.NewIncomingContext(context.Background(),
			metadata.Pairs("worker_name", "one", "worker_name", "two"))},
	}

	for _, method := range methods {
		for _, test := range invalid {
			t.Run(method+"/"+test.name, func(t *testing.T) {
				if code := status.Code(validateWorkerStreamMetadata(test.ctx, method));
					code != codes.InvalidArgument {
					t.Fatalf("expected InvalidArgument, got %s", code)
				}
			})
		}

		unknown := metadata.NewIncomingContext(context.Background(),
			metadata.Pairs("worker_name", "missing-worker-metadata-test"))
		if code := status.Code(validateWorkerStreamMetadata(unknown, method));
			code != codes.FailedPrecondition {
			t.Fatalf("%s: expected FailedPrecondition, got %s", method, code)
		}
	}
}

func TestValidateWorkerStreamMetadataIgnoresOtherRPCs(t *testing.T) {
	if err := validateWorkerStreamMetadata(context.Background(),
		"/master.Master/FetchLoadPart"); err != nil {
		t.Fatalf("unrelated RPC must not require stream metadata: %v", err)
	}
}
