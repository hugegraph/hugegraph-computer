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
	"strings"
	"testing"
	"time"
	"vermeer/apps/auth"
	"vermeer/apps/common"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

const nativePasswordFixture = "AdminFixture1234"
const nativeSigningFixture = "synthetic-native-password-signing-factor"

func configureNativePassword(t *testing.T) (string, string) {
	t.Helper()
	for _, key := range []string{"auth_token_factor", "auth_token_factor_file", "admin_password_file"} {
		previous := common.GetConfigDefault(key, "")
		common.SetConfig(key, "")
		t.Cleanup(func() { common.SetConfig(key, previous) })
	}
	directory := t.TempDir()
	factor := filepath.Join(directory, "factor")
	password := filepath.Join(directory, "password")
	if err := os.WriteFile(factor, []byte(nativeSigningFixture), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(password, []byte(nativePasswordFixture), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VERMEER_AUTH_TOKEN_FACTOR_FILE", factor)
	t.Setenv("VERMEER_ADMIN_PASSWORD_FILE", password)
	if err := auth.Init(); err != nil {
		t.Fatal(err)
	}
	factory, err := auth.NewSecureTokenFactory(nativeSigningFixture)
	if err != nil {
		t.Fatal(err)
	}
	token := factory.NewToken("admin", "$DEFAULT", "hubble-service")
	token.Time = math.MaxInt64
	factory.Sign(token)
	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	return password, auth.ToBase58(string(encoded))
}

func postNativeCredential(t *testing.T, handler http.Handler,
	credential, forwardedProto string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"token": credential})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if forwardedProto != "" {
		request.Header.Set("X-Forwarded-Proto", forwardedProto)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestNativeAdminPasswordCookieAndServiceToken(t *testing.T) {
	passwordFile, serviceToken := configureNativePassword(t)
	previousMode, previousOutput := gin.Mode(), logrus.StandardLogger().Out
	var logs bytes.Buffer
	logrus.SetOutput(&logs)
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() { gin.SetMode(previousMode); logrus.SetOutput(previousOutput) })
	router := gin.New()
	router.POST("/api/v1/login", (&LoginHandler{}).POST)
	router.GET("/protected", auth.TokenFilter, auth.AdminFilter, func(ctx *gin.Context) { ctx.Status(http.StatusOK) })
	check := func(cookie *http.Cookie, bearer string, want int) {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, "/protected", nil)
		if cookie != nil {
			request.AddCookie(cookie)
		}
		if bearer != "" {
			request.Header.Set(auth.HeaderKey, "Bearer "+bearer)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("protected status = %d, want %d", response.Code, want)
		}
	}
	check(nil, "", http.StatusUnauthorized)
	wrong := postNativeCredential(t, router, "IncorrectAdmin16", "")
	if wrong.Code != http.StatusUnauthorized || len(wrong.Result().Cookies()) != 0 {
		t.Fatal("incorrect UI password must not create a cookie")
	}
	response := postNativeCredential(t, router, nativePasswordFixture, "")
	cookies := response.Result().Cookies()
	if response.Code != http.StatusOK || len(cookies) != 1 || !cookies[0].HttpOnly ||
		cookies[0].MaxAge != auth.AdminSessionMaxAge || cookies[0].Secure {
		t.Fatal("internal HTTP login must create its HttpOnly 24-hour session cookie")
	}
	cookie := cookies[0]
	token := auth.ToTokenBase58(cookie.Value)
	now := time.Now().Unix()
	if token == nil || token.User != "admin" || token.Space != "$DEFAULT" || token.Time < now-1 || token.Time > now ||
		!strings.HasPrefix(token.Digest, "v2:") || cookie.Value == nativePasswordFixture {
		t.Fatal("short password must exchange for a separate current v2 admin session")
	}
	check(cookie, "", http.StatusOK)
	check(nil, nativePasswordFixture, http.StatusUnauthorized)
	check(nil, serviceToken, http.StatusOK)
	secureResponse := postNativeCredential(t, router, nativePasswordFixture, "https")
	if secureResponse.Code != http.StatusOK || !secureResponse.Result().Cookies()[0].Secure {
		t.Fatal("HTTPS browser sessions must carry the Secure cookie attribute")
	}
	serviceLogin := postNativeCredential(t, router, serviceToken, "")
	if serviceLogin.Code != http.StatusOK || len(serviceLogin.Result().Cookies()) != 1 {
		t.Fatal("long opaque service-token login must remain supported")
	}
	const rotated = "RotatedFixture16"
	if err := os.WriteFile(passwordFile, []byte(rotated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := auth.Init(); err != nil {
		t.Fatal(err)
	}
	if postNativeCredential(t, router, nativePasswordFixture, "").Code != http.StatusUnauthorized {
		t.Fatal("old password must stop authenticating after password reload")
	}
	if postNativeCredential(t, router, rotated, "").Code != http.StatusOK {
		t.Fatal("rotated password must authenticate")
	}
	check(nil, serviceToken, http.StatusOK)
	check(cookie, "", http.StatusOK)
	malformed := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"token":"`+rotated))
	malformed.Header.Set("Content-Type", "application/json")
	malformedResponse := httptest.NewRecorder()
	router.ServeHTTP(malformedResponse, malformed)
	if malformedResponse.Code != http.StatusBadRequest {
		t.Fatal("malformed login request must be rejected")
	}
	for _, observed := range []string{response.Body.String(), wrong.Body.String(),
		malformedResponse.Body.String(), logs.String()} {
		for _, sensitive := range []string{nativePasswordFixture, rotated, cookie.Value, serviceToken} {
			if strings.Contains(observed, sensitive) {
				t.Fatal("responses and logs must not expose credentials")
			}
		}
	}
}

func nativeRouteSentinel(t *testing.T, filters ...gin.HandlerFunc) *common.Sentinel {
	t.Helper()
	previousMetrics := common.PrometheusMetrics
	previousRegisterer, previousGatherer := prometheus.DefaultRegisterer, prometheus.DefaultGatherer
	previousMode := gin.Mode()
	registry := prometheus.NewRegistry()
	prometheus.DefaultRegisterer, prometheus.DefaultGatherer = registry, registry
	t.Cleanup(func() {
		common.PrometheusMetrics = previousMetrics
		prometheus.DefaultRegisterer, prometheus.DefaultGatherer = previousRegisterer, previousGatherer
		gin.SetMode(previousMode)
	})
	sentinel := &common.Sentinel{}
	sentinel.Init("127.0.0.1:0", "release")
	SetRouters(sentinel, filters...)
	return sentinel
}

func TestNativeStatusRoutesRequireConfiguredAuthentication(t *testing.T) {
	_, serviceToken := configureNativePassword(t)
	factory, err := auth.NewSecureTokenFactory(nativeSigningFixture)
	if err != nil {
		t.Fatal(err)
	}
	reader := factory.NewToken("space-user", "own-space", "status-test")
	factory.Sign(reader)
	readerJSON, err := json.Marshal(reader)
	if err != nil {
		t.Fatal(err)
	}
	readerToken := auth.ToBase58(string(readerJSON))
	sentinel := nativeRouteSentinel(t, auth.TokenFilter)
	login := postNativeCredential(t, sentinel, nativePasswordFixture, "")
	if login.Code != http.StatusOK {
		t.Fatal("native login route must remain reachable")
	}
	cookie := login.Result().Cookies()[0]
	for _, path := range []string{"/workers", "/api/v1/workers", "/master", "/api/v1/master"} {
		for _, test := range []struct {
			name, bearer string
			cookie       *http.Cookie
			want         int
		}{
			{name: "anonymous", want: http.StatusUnauthorized},
			{name: "raw-password", bearer: nativePasswordFixture, want: http.StatusUnauthorized},
			{name: "service-token", bearer: serviceToken, want: http.StatusOK},
			{name: "space-token", bearer: readerToken, want: http.StatusOK},
			{name: "password-session", cookie: cookie, want: http.StatusOK},
		} {
			t.Run(path+"/"+test.name, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodGet, path, nil)
				if test.bearer != "" {
					request.Header.Set(auth.HeaderKey, "Bearer "+test.bearer)
				}
				if test.cookie != nil {
					request.AddCookie(test.cookie)
				}
				response := httptest.NewRecorder()
				sentinel.ServeHTTP(response, request)
				if response.Code != test.want {
					t.Fatalf("status = %d, want %d", response.Code, test.want)
				}
			})
		}
	}
	health := httptest.NewRecorder()
	sentinel.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/v1/healthcheck", nil))
	if health.Code != http.StatusOK {
		t.Fatal("health probes must remain public")
	}
}

func TestNativeStatusRoutesRetainExplicitNoneMode(t *testing.T) {
	sentinel := nativeRouteSentinel(t, auth.NoneAuthFilter)
	for _, path := range []string{"/api/v1/workers", "/api/v1/master"} {
		response := httptest.NewRecorder()
		sentinel.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatal("explicit none mode must retain its historical route behavior")
		}
	}
}
