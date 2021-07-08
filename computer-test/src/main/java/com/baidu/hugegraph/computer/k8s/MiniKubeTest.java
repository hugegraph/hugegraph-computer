/*
 * Copyright 2017 HugeGraph Authors
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.baidu.hugegraph.computer.k8s;

import static io.fabric8.kubernetes.client.Config.getKubeconfigFilename;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.baidu.hugegraph.computer.driver.DefaultJobState;
import com.baidu.hugegraph.computer.driver.JobObserver;
import com.baidu.hugegraph.computer.k8s.config.KubeDriverOptions;
import com.baidu.hugegraph.computer.k8s.config.KubeSpecOptions;
import com.baidu.hugegraph.computer.k8s.operator.config.OperatorOptions;
import com.baidu.hugegraph.computer.suite.unit.UnitTestBase;
import com.baidu.hugegraph.testutil.Assert;

import io.fabric8.kubernetes.client.utils.Utils;

public class MiniKubeTest extends AbstractK8sTest {

    @Before
    public void setup() throws IOException {
        String kubeconfigFilename = getKubeconfigFilename();
        File file = new File(kubeconfigFilename);
        Assert.assertTrue(file.exists());

        this.namespace = "minikube";
        System.setProperty(OperatorOptions.WATCH_NAMESPACE.name(),
                           Constants.ALL_NAMESPACE);
        super.setup();
    }

    @Test
    public void testProbe() throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        String probePort = Utils.getSystemPropertyOrEnvVar(
                           OperatorOptions.PROBE_PORT.name());
        URI health = URI.create(String.format("http://localhost:%s/healthz",
                                              probePort));
        HttpGet request = new HttpGet(health);
        HttpResponse response = client.execute(request);
        Assert.assertEquals(HttpStatus.SC_OK,
                            response.getStatusLine().getStatusCode());

        URI ready = URI.create(String.format("http://localhost:%s/readyz",
                                              probePort));
        HttpGet requestReady = new HttpGet(ready);
        HttpResponse responseReady = client.execute(requestReady);
        Assert.assertEquals(HttpStatus.SC_OK,
                            responseReady.getStatusLine().getStatusCode());
    }

    @Test
    public void testWaitJob() {
        super.updateOptions(KubeDriverOptions.IMAGE_REPOSITORY_URL.name(),
                            "czcoder/hugegraph-computer-test");

        Map<String, String> params = new HashMap<>();
        params.put(KubeSpecOptions.WORKER_INSTANCES.name(), "1");
        String jobId = this.driver.submitJob("PageRank", params);

        JobObserver jobObserver = Mockito.mock(JobObserver.class);

        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            this.driver.waitJob(jobId, params, jobObserver);
        });

        UnitTestBase.sleep(200L);

        this.driver.cancelJob(jobId, params);

        Mockito.verify(jobObserver, Mockito.timeout(15000L).atLeast(3))
               .onJobStateChanged(Mockito.any(DefaultJobState.class));

        future.getNow(null);
    }
}