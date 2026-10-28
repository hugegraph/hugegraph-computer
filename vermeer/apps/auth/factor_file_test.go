/*
Licensed to the Apache Software Foundation (ASF) under one or more
contributor license agreements. See the NOTICE file distributed with this
work for additional information regarding copyright ownership. The ASF
licenses this file to You under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vermeer/apps/common"
)

func TestTokenFactorFilePrecedenceAndFailClosed(t *testing.T) {
	previousFactor := common.GetConfigDefault("auth_token_factor", "")
	previousFile := common.GetConfigDefault("auth_token_factor_file", "")
	previousFactory := factory
	t.Cleanup(func() {
		common.SetConfig("auth_token_factor", previousFactor)
		common.SetConfig("auth_token_factor_file", previousFile)
		factory = previousFactory
	})
	common.SetConfig("auth_token_factor", "legacy-inline-factor")
	configured := filepath.Join(t.TempDir(), "configured")
	override := filepath.Join(t.TempDir(), "override")
	if err := os.WriteFile(configured, []byte("configured-factor\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(override, []byte("environment-factor"), 0600); err != nil {
		t.Fatal(err)
	}
	common.SetConfig("auth_token_factor_file", configured)
	t.Setenv("VERMEER_AUTH_TOKEN_FACTOR_FILE", override)
	if err := Init(); err != nil || factory.Factor != "" || string(factory.signingKey) != "environment-factor" {
		t.Fatal("environment factor file must override config and inline factor")
	}
	t.Setenv("VERMEER_AUTH_TOKEN_FACTOR_FILE", "")
	if err := Init(); err != nil || factory.Factor != "" || string(factory.signingKey) != "configured-factor" {
		t.Fatal("configured factor file must override inline factor")
	}
	for _, test := range []struct{ name, data string }{
		{"missing", ""}, {"empty", ""}, {"invalid", "synthetic-secret\nsecond-line"},
		{"short-ascii", "abc"}, {"short-unicode", "密碼"}, {"invalid-utf8", "abcd\xff"},
		{"whitespace-only", "    "},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "factor")
			if test.name != "missing" {
				if err := os.WriteFile(file, []byte(test.data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("VERMEER_AUTH_TOKEN_FACTOR_FILE", file)
			err := Init()
			if err == nil || factory != nil {
				t.Fatal("invalid file must not leave an active fallback factory")
			}
			if strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("errors must not expose factor contents")
			}
		})
	}
	common.SetConfig("auth_token_factor_file", "")
	if err := Init(); err != nil || factory.Factor != "legacy-inline-factor" {
		t.Fatal("unconfigured deployments must preserve inline factors")
	}
}
