//go:build vermeer_test

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

package functional

import (
	"math"

	"github.com/stretchr/testify/require"
)

type SccTest struct {
	ComputeTaskBase
}

func (sct *SccTest) TaskComputeBody() map[string]string {
	//获取compute任务的body
	return map[string]string{
		"compute.algorithm": "scc",
		"compute.max_step":  "200",
		"compute.parallel":  "100",
		"output.file_path":  "./data/" + sct.algoName,
		"output.type":       "local",
		"output.parallel":   "10",
	}
}

// CheckRes
//
//	@Description: 仅校验scc的总群落数、最大群落结点数、最小群落结点数。
func (sct *SccTest) CheckRes() {
	//解析输出结果，校验结果正确性。
	computeRes, err := sct.LoadComputeRes()
	require.NoError(sct.t, err)
	sccMap := make(map[int]int)
	for i := range computeRes {
		sccMap[computeRes[i].(int)]++
	}
	maxNums := 0
	minNums := math.MaxInt
	for i := range sccMap {
		if sccMap[i] > maxNums {
			maxNums = sccMap[i]
		}
		if sccMap[i] < minNums {
			minNums = sccMap[i]
		}
	}
	expectWcc, err := sct.LoadExpectRes("test/case/expect_scc")
	require.NoError(sct.t, err)
	expectMap := make(map[int]int)
	for i := range expectWcc {
		expectMap[expectWcc[i].(int)]++
	}
	expectMaxNums := 0
	expectMinNums := math.MaxInt
	for i := range expectMap {
		if expectMap[i] > expectMaxNums {
			expectMaxNums = expectMap[i]
		}
		if expectMap[i] < expectMinNums {
			expectMinNums = expectMap[i]
		}
	}
	require.Equal(sct.t, len(expectMap), len(sccMap))
	require.Equal(sct.t, expectMaxNums, maxNums)
	require.Equal(sct.t, expectMinNums, minNums)
}