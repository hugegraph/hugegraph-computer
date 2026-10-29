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
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// ProcessMetrics describes this process, rather than the host or a Kubernetes Pod.
// CPUCores is CPU seconds consumed divided by elapsed wall time; it may exceed 1.
type ProcessMetrics struct {
	CPUCores            float64
	RSSBytes            uint64
	SampleWindowSeconds float64
	ObservedAt          int64
}

var errMetricsWarmingUp = errors.New("metrics_warming_up")
var errProcessMetricsUnavailable = errors.New("process_metrics_unavailable")

type processMetricsReader func() (cpuSeconds float64, rssBytes uint64, err error)

type processMetricsSampler struct {
	mu          sync.Mutex
	read        processMetricsReader
	now         func() time.Time
	lastAttempt time.Time
	baselineAt  time.Time
	baselineCPU float64
	result      ProcessMetrics
	err         error
}

var currentProcessMetrics = processMetricsSampler{read: readCurrentProcessMetrics, now: time.Now}

// ReadProcessMetrics samples without waiting for a measurement interval. Calls
// within one second reuse the last observation. The first call establishes a baseline
// and returns metrics_warming_up instead of inventing a zero CPU measurement.
func ReadProcessMetrics() (ProcessMetrics, error) {
	return currentProcessMetrics.sample()
}

func (s *processMetricsSampler) sample() (ProcessMetrics, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.lastAttempt.IsZero() && now.Sub(s.lastAttempt) >= 0 && now.Sub(s.lastAttempt) < time.Second {
		return s.result, s.err
	}
	s.lastAttempt = now
	s.result = ProcessMetrics{ObservedAt: now.UnixMilli()}
	cpuSeconds, rssBytes, err := s.read()
	if err != nil || math.IsNaN(cpuSeconds) || math.IsInf(cpuSeconds, 0) || cpuSeconds < 0 {
		s.err = errProcessMetricsUnavailable
		return s.result, s.err
	}
	s.result.RSSBytes = rssBytes
	if s.baselineAt.IsZero() || !now.After(s.baselineAt) || cpuSeconds < s.baselineCPU {
		s.baselineAt, s.baselineCPU = now, cpuSeconds
		s.err = errMetricsWarmingUp
		return s.result, s.err
	}
	s.result.SampleWindowSeconds = now.Sub(s.baselineAt).Seconds()
	s.result.CPUCores = (cpuSeconds - s.baselineCPU) / s.result.SampleWindowSeconds
	s.baselineAt, s.baselineCPU = now, cpuSeconds
	s.err = nil
	return s.result, nil
}

func readCurrentProcessMetrics() (float64, uint64, error) {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return 0, 0, err
	}
	times, err := p.Times()
	if err != nil {
		return 0, 0, err
	}
	memory, err := p.MemoryInfo()
	if err != nil {
		return 0, 0, err
	}
	return times.User + times.System, memory.RSS, nil
}
