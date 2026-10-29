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
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

func TestProcessMetricsMeasureCoresAndCacheObservation(t *testing.T) {
	now := time.Unix(100, 0)
	cpuSeconds := 10.0
	reads := 0
	s := processMetricsSampler{
		now: func() time.Time { return now },
		read: func() (float64, uint64, error) {
			reads++
			return cpuSeconds, 12345, nil
		},
	}
	if _, err := s.sample(); !errors.Is(err, errMetricsWarmingUp) {
		t.Fatalf("first observation must warm up, got %v", err)
	}
	now = now.Add(2 * time.Second)
	cpuSeconds += 3
	got, err := s.sample()
	if err != nil || got.CPUCores != 1.5 || got.RSSBytes != 12345 || got.SampleWindowSeconds != 2 {
		t.Fatalf("expected 1.5 process CPU cores with 2s window, got %+v, %v", got, err)
	}
	now = now.Add(100 * time.Millisecond)
	cached, err := s.sample()
	if err != nil || cached != got || reads != 2 {
		t.Fatalf("cached observation changed: %+v, reads=%d, err=%v", cached, reads, err)
	}
}

func TestProcessMetricsFailureDoesNotFabricateUsage(t *testing.T) {
	now := time.Unix(100, 0)
	invalid := false
	s := processMetricsSampler{
		now: func() time.Time { return now },
		read: func() (float64, uint64, error) {
			if invalid {
				return math.NaN(), 100, nil
			}
			return 5, 100, nil
		},
	}
	_, _ = s.sample()
	now = now.Add(time.Second)
	invalid = true
	got, err := s.sample()
	if !errors.Is(err, errProcessMetricsUnavailable) || got.RSSBytes != 0 || got.SampleWindowSeconds != 0 {
		t.Fatalf("invalid sample must be unavailable, got %+v, %v", got, err)
	}
}

func TestProcessMetricsConcurrentReadsShareBaseline(t *testing.T) {
	s := processMetricsSampler{
		now:  func() time.Time { return time.Unix(100, 0) },
		read: func() (float64, uint64, error) { return 5, 100, nil },
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.sample(); !errors.Is(err, errMetricsWarmingUp) {
				t.Errorf("concurrent initial sample: %v", err)
			}
		}()
	}
	wg.Wait()
}
