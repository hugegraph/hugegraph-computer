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

package main

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vermeer/apps/auth"
	"vermeer/apps/common"
	"vermeer/apps/structure"

	"github.com/gin-gonic/gin"
)

func TestDeploymentTokenNativeAuthenticationAndRotation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	factorFile := filepath.Join(t.TempDir(), "factor")
	output := filepath.Join(t.TempDir(), "token")
	const firstFactor = "synthetic-部署-factor\\with-quotes\""
	if err := os.WriteFile(factorFile, []byte(firstFactor+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VERMEER_AUTH_TOKEN_FACTOR_FILE", factorFile)
	args := []string{"-factor-file", factorFile, "-output-file", output, "-quiet",
		"-user", "admin", "-space", "$DEFAULT", "-i"}
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("file output must not log credentials")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("token file must have mode 0600")
	}
	token := strings.TrimSpace(string(data))
	parsed := auth.ToTokenBase58(token)
	factory, err := auth.NewSecureTokenFactory(firstFactor)
	if err != nil {
		t.Fatal(err)
	}
	if parsed == nil || parsed.Time != math.MaxInt64 ||
		!strings.HasPrefix(parsed.Digest, "v2:") || !factory.Verify(parsed) {
		t.Fatal("helper token must use the native factory and immortal timestamp")
	}
	old := common.GetConfigDefault("auth_token_factor", "")
	t.Cleanup(func() { common.SetConfig("auth_token_factor", old) })
	common.SetConfig("auth_token_factor", "different-config-factor")
	if err := auth.Init(); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/protected", auth.TokenFilter, auth.AdminFilter, func(ctx *gin.Context) {
		credential := ctx.MustGet(structure.CredentialKey).(*structure.Credential)
		if credential.Space() != "$DEFAULT" {
			t.Fatal("token service space changed")
		}
		ctx.Status(http.StatusOK)
	})
	check := func(encoded string, want int) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/protected", nil)
		request.Header.Set("Authorization", "Bearer "+encoded)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("native filter status = %d, want %d", response.Code, want)
		}
	}
	check(token, http.StatusOK)
	legacyFactory := auth.TokenFactory{Factor: firstFactor}
	legacyToken := *parsed
	legacyFactory.Sign(&legacyToken)
	legacyData, err := json.Marshal(legacyToken)
	if err != nil {
		t.Fatal(err)
	}
	check(auth.ToBase58(string(legacyData)), http.StatusUnauthorized)
	parsed.Time = time.Now().Unix() - 25*60*60
	factory.Sign(parsed)
	expired, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	check(auth.ToBase58(string(expired)), http.StatusUnauthorized)
	if err := os.WriteFile(factorFile, []byte("rotated-deployment-factor"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := auth.Init(); err != nil {
		t.Fatal(err)
	}
	check(token, http.StatusUnauthorized)
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	rotated, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	check(strings.TrimSpace(string(rotated)), http.StatusOK)
}

func TestTokenOutputAndInputFailures(t *testing.T) {
	var stdout, stderr bytes.Buffer
	const secret = "synthetic-sensitive-factor"
	factorFile := filepath.Join(t.TempDir(), "factor")
	if err := os.WriteFile(factorFile, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-factor-file", factorFile, "-quiet", "-i"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if auth.ToTokenBase58(strings.TrimSpace(stdout.String())) == nil || stderr.Len() != 0 {
		t.Fatal("quiet output must contain only the native token")
	}
	stdout.Reset()
	if err := run([]string{"-factor-file", factorFile}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stdout.String(), "json:") {
		t.Fatal("interactive metadata must not print the factor or signed JSON")
	}
	for _, content := range []string{"", "\n", "secret\nsecond-line", "secret\rsecond-line"} {
		file := filepath.Join(t.TempDir(), "factor")
		if err := os.WriteFile(file, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		stderr.Reset()
		if err := run([]string{"-factor-file", file}, &stdout, &stderr); err == nil {
			t.Fatal("invalid factor files must fail")
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatal("invalid factors must not be printed")
		}
	}
	for _, args := range [][]string{
		{},
		{"-factor-file", filepath.Join(t.TempDir(), "missing")},
		{"-factor", secret},
		{"-factor", secret, "-factor-file", factorFile},
		{"-user", "", "-factor-file", factorFile},
		{"-factor-file", factorFile, "-output-file", filepath.Join(t.TempDir(), "missing", "token")},
	} {
		stdout.Reset()
		stderr.Reset()
		if err := run(args, &stdout, &stderr); err == nil {
			t.Fatal("invalid arguments must fail")
		}
		if stdout.Len() != 0 {
			t.Fatal("failed generation must not expose token contents")
		}
	}
}

func TestTokenFileReplacesSymlinkWithoutReadingTarget(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	output := filepath.Join(directory, "token")
	if err := os.WriteFile(target, []byte("keep-existing-file"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, output); err != nil {
		t.Fatal(err)
	}
	factorFile := filepath.Join(directory, "factor")
	if err := os.WriteFile(factorFile, []byte("synthetic-output-file-factor"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-factor-file", factorFile, "-output-file", output, "-i"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "keep-existing-file" {
		t.Fatal("token output must not follow a symlink")
	}
	info, err := os.Lstat(output)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("published token must be a private regular file")
	}
}
