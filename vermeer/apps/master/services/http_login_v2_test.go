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

package services

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"vermeer/apps/auth"
	"vermeer/apps/common"

	"github.com/gin-gonic/gin"
)

func TestNativeLoginCookieUsesSecureDeploymentToken(t *testing.T) {
	previousMode := gin.Mode()
	previousFactor := common.GetConfig("auth_token_factor")
	t.Cleanup(func() { gin.SetMode(previousMode); common.SetConfig("auth_token_factor", previousFactor) })
	gin.SetMode(gin.TestMode)
	const key = "synthetic-native-ui-signing-key"
	factorFile := filepath.Join(t.TempDir(), "factor")
	if err := os.WriteFile(factorFile, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VERMEER_AUTH_TOKEN_FACTOR_FILE", factorFile)
	common.SetConfig("auth_token_factor", key)
	if err := auth.Init(); err != nil {
		t.Fatal(err)
	}
	secure, err := auth.NewSecureTokenFactory(key)
	if err != nil {
		t.Fatal(err)
	}
	token := secure.NewToken("admin", "$DEFAULT", "native-ui")
	token.Time = math.MaxInt64
	secure.Sign(token)
	router := gin.New()
	router.POST("/api/v1/login", (&LoginHandler{}).POST)
	router.GET("/protected", auth.TokenFilter, auth.AdminFilter, func(ctx *gin.Context) { ctx.Status(http.StatusOK) })
	authenticate := func(token *auth.Token, want int) {
		t.Helper()
		encoded, err := json.Marshal(token)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(map[string]string{"token": auth.ToBase58(string(encoded))})
		if err != nil {
			t.Fatal(err)
		}
		login := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
		login.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, login)
		if want != http.StatusOK {
			if response.Code != http.StatusUnauthorized || len(response.Result().Cookies()) != 0 {
				t.Fatal("invalid token login must reject before issuing a cookie")
			}
			return
		}
		if response.Code != http.StatusOK {
			t.Fatalf("native login status = %d", response.Code)
		}
		cookies := response.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].HttpOnly {
			t.Fatal("native login must set its protected session cookie")
		}
		request := httptest.NewRequest(http.MethodGet, "/protected", nil)
		request.AddCookie(cookies[0])
		checked := httptest.NewRecorder()
		router.ServeHTTP(checked, request)
		if checked.Code != want {
			t.Fatalf("cookie authentication status = %d, want %d", checked.Code, want)
		}
	}
	authenticate(token, http.StatusOK)
	tampered := *token
	tampered.Space = "another-space"
	authenticate(&tampered, http.StatusUnauthorized)
	legacy := &auth.TokenFactory{Factor: key}
	legacy.Sign(token)
	authenticate(token, http.StatusUnauthorized)
}

func TestNativeLegacyTokenLoginRemainsSupported(t *testing.T) {
	for _, key := range []string{"auth_token_factor", "auth_token_factor_file", "admin_password_file"} {
		previous := common.GetConfigDefault(key, "")
		common.SetConfig(key, "")
		t.Cleanup(func() { common.SetConfig(key, previous) })
	}
	t.Setenv("VERMEER_AUTH_TOKEN_FACTOR_FILE", "")
	t.Setenv("VERMEER_ADMIN_PASSWORD_FILE", "")
	const factor = "synthetic-legacy-inline-factor"
	common.SetConfig("auth_token_factor", factor)
	if err := auth.Init(); err != nil {
		t.Fatal(err)
	}
	factory := &auth.TokenFactory{Factor: factor}
	token := factory.NewToken("admin", "$DEFAULT", "legacy-client")
	factory.Sign(token)
	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/api/v1/login", (&LoginHandler{}).POST)
	response := postNativeCredential(t, router, auth.ToBase58(string(encoded)), "")
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 1 {
		t.Fatal("valid historical inline-token login must remain supported")
	}
}
