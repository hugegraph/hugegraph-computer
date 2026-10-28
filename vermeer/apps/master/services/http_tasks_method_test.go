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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"vermeer/apps/common"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func taskMethodRouter(t *testing.T, filters ...gin.HandlerFunc) *common.Sentinel {
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
	regVerAPI(sentinel, 1, "/tasks", map[string]common.BaseHandler{"": &TasksHandler{}}, filters...)
	return sentinel
}

func TestTaskCollectionPostRejectsFalseSuccess(t *testing.T) {
	router := taskMethodRouter(t)
	for _, path := range []string{"/tasks", "/api/v1/tasks"} {
		for _, body := range []string{
			`{}`, `{"algorithm":"pagerank"}`,
			`{"graph":"example","task_type":"compute","params":{"compute.algorithm":"pagerank"}}`,
		} {
			t.Run(path+body, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if response.Code != http.StatusMethodNotAllowed {
					t.Fatalf("POST %s returned %d: %s", path, response.Code, response.Body.String())
				}
				if response.Header().Get("Allow") != http.MethodGet {
					t.Fatalf("Allow = %q", response.Header().Get("Allow"))
				}
				var result common.BaseResp
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.ErrCode == 0 || !strings.Contains(result.Message, "/tasks/create") {
					t.Fatalf("missing submission guidance: %+v", result)
				}
			})
		}
	}
}

func TestTaskCollectionPostRetainsAuthenticationFilters(t *testing.T) {
	checked := false
	router := taskMethodRouter(t, func(ctx *gin.Context) {
		checked = true
		ctx.AbortWithStatus(http.StatusUnauthorized)
	})
	for _, path := range []string{"/tasks", "/api/v1/tasks"} {
		checked = false
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if !checked || response.Code != http.StatusUnauthorized {
			t.Fatalf("authentication bypassed for %s: checked=%v status=%d", path, checked, response.Code)
		}
	}
}
