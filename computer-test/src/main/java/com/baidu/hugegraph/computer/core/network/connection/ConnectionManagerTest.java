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

package com.baidu.hugegraph.computer.core.network.connection;

import java.io.IOException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;

import com.baidu.hugegraph.computer.core.UnitTestBase;
import com.baidu.hugegraph.computer.core.common.ComputerContext;
import com.baidu.hugegraph.computer.core.config.ComputerOptions;
import com.baidu.hugegraph.computer.core.config.Config;
import com.baidu.hugegraph.computer.core.network.ConnectionID;
import com.baidu.hugegraph.computer.core.network.MessageHandler;
import com.baidu.hugegraph.computer.core.network.MockMessageHandler;
import com.baidu.hugegraph.computer.core.network.MockTransportHandler;
import com.baidu.hugegraph.computer.core.network.TransportClient;
import com.baidu.hugegraph.computer.core.network.TransportHandler;
import com.baidu.hugegraph.computer.core.network.TransportServer;
import com.baidu.hugegraph.testutil.Assert;
import com.baidu.hugegraph.util.Log;

public class ConnectionManagerTest {

    private static final Logger LOG = Log.logger(ConnectionManagerTest.class);

    private static Config config;
    private static MessageHandler serverHandler;
    private static TransportHandler clientHandler;
    private static ConnectionManager connectionManager;
    private static int port;

    @Before
    public void setup() {
        UnitTestBase.updateWithRequiredOptions(
                ComputerOptions.TRANSPORT_SERVER_HOST, "127.0.0.1",
                ComputerOptions.TRANSPORT_IO_MODE, "NIO"
        );
        config = ComputerContext.instance().config();
        serverHandler = new MockMessageHandler();
        clientHandler = new MockTransportHandler();
        connectionManager = new TransportConnectionManager();
        port = connectionManager.startServer(config, serverHandler);
        connectionManager.initClientManager(config, clientHandler);
    }

    @After
    public void teardown() {
        if (connectionManager != null) {
            connectionManager.shutdown();
        }
    }

    @Test
    public void testGetServer() {
        TransportServer server = connectionManager.getServer();
        Assert.assertTrue(server.bound());
        Assert.assertEquals(port, server.port());
        Assert.assertNotEquals(0, server.port());
    }

    @Test
    public void testGetServerWithNoStart() {
        ConnectionManager connectionManager1 = new TransportConnectionManager();
        Assert.assertThrows(IllegalArgumentException.class, () -> {
            TransportServer server = connectionManager1.getServer();
        }, e -> {
            Assert.assertContains("has not been initialized yet",
                                  e.getMessage());
        });
    }

    @Test
    public void testGetOrCreateClient() throws IOException {
        ConnectionID connectionID = ConnectionID.parseConnectionID(
                                    "127.0.0.1", port);
        TransportClient client = connectionManager.getOrCreateClient(
                                 connectionID);
        Assert.assertTrue(client.active());
    }

    @Test
    public void testCloseClient() throws IOException {
        ConnectionID connectionID = ConnectionID.parseConnectionID(
                                    "127.0.0.1", port);
        TransportClient client = connectionManager.getOrCreateClient(
                                 connectionID);
        Assert.assertTrue(client.active());
        connectionManager.closeClient(client.connectionID());
        Assert.assertFalse(client.active());
    }

    @Test
    public void testGetClientWithNoInit() {
        ConnectionManager connectionManager1 = new TransportConnectionManager();
        ConnectionID connectionID = ConnectionID.parseConnectionID(
                                    "127.0.0.1", port);
        Assert.assertThrows(IllegalArgumentException.class, () -> {
            connectionManager1.getOrCreateClient(connectionID);
        }, e -> {
            Assert.assertContains("has not been initialized yet",
                                  e.getMessage());
        });
    }

    @Test
    public void testShutDown() throws IOException {
        ConnectionID connectionID = ConnectionID.parseConnectionID(
                                    "127.0.0.1", port);
        TransportClient client = connectionManager.getOrCreateClient(
                                 connectionID);
        Assert.assertTrue(client.active());
        connectionManager.shutdownClientManager();
        Assert.assertThrows(IllegalArgumentException.class, () -> {
            connectionManager.getOrCreateClient(connectionID);
        }, e -> {
            Assert.assertContains("has not been initialized yet",
                                  e.getMessage());
        });
        connectionManager.shutdownServer();
        Assert.assertThrows(IllegalArgumentException.class, () -> {
            TransportServer server = connectionManager.getServer();
        }, e -> {
            Assert.assertContains("has not been initialized yet",
                                  e.getMessage());
        });
        connectionManager.shutdown();
    }
}