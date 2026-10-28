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

package worker

import (
	"context"
	"sync"
	"vermeer/apps/common"
	pb "vermeer/apps/protos"

	"github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

var PeerMgr PeerManager

type peerStreamKind uint8

const (
	peerScatterStream peerStreamKind = iota
	peerLoadStream
	peerStepStream
	peerSettingStream
	peerStreamCount
)

type PeerClient struct {
	Id                   int32
	Name                 string
	GrpcPeer             string
	Self                 bool
	ScatterHandler       ScatterHandler
	LoadActionHandler    LoadActionHandler
	StepEndHandler       StepEndHandler
	SettingActionHandler SettingActionHandler
	peerConn             *grpc.ClientConn
	streamGenerations    [peerStreamCount]uint64
	streamCancels        [peerStreamCount]context.CancelFunc
	peerSession          pb.WorkerClient
}

type PeerManager struct {
	peersByName map[string]*PeerClient
	locker      sync.Mutex
}

func closePeerResources(connection *grpc.ClientConn, cancels [peerStreamCount]context.CancelFunc) {
	for _, cancel := range cancels {
		if cancel != nil {
			cancel()
		}
	}
	if connection != nil {
		_ = connection.Close()
	}
}

func (pm *PeerManager) Init() {
	pm.locker.Lock()
	previous := pm.peersByName
	pm.peersByName = make(map[string]*PeerClient)
	pm.locker.Unlock()
	for _, peer := range previous {
		closePeerResources(peer.peerConn, peer.streamCancels)
	}
}

func (pm *PeerManager) AddPeer(name string, id int32, grpcPeer string) *PeerClient {
	pm.locker.Lock()
	previous := pm.peersByName[name]
	peer := &PeerClient{Id: id, Name: name, GrpcPeer: grpcPeer, Self: name == ServiceWorker.WorkerName}
	peer.ScatterHandler.peer = peer
	peer.LoadActionHandler.peer = peer
	peer.StepEndHandler.peer = peer
	peer.SettingActionHandler.peer = peer
	if pm.peersByName == nil {
		pm.peersByName = make(map[string]*PeerClient)
	}
	pm.peersByName[name] = peer
	if previous == nil {
		common.PrometheusMetrics.WorkerCnt.WithLabelValues().Inc()
	}
	var connection *grpc.ClientConn
	var cancels [peerStreamCount]context.CancelFunc
	if previous != nil {
		connection, cancels = previous.peerConn, previous.streamCancels
	}
	pm.locker.Unlock()
	closePeerResources(connection, cancels)
	return peer
}

func (pm *PeerManager) SetPeerConnection(peer *PeerClient, connection *grpc.ClientConn) bool {
	pm.locker.Lock()
	if peer == nil || pm.peersByName[peer.Name] != peer {
		pm.locker.Unlock()
		_ = connection.Close()
		return false
	}
	peer.peerConn, peer.peerSession = connection, pb.NewWorkerClient(connection)
	pm.locker.Unlock()
	return true
}

func (pm *PeerManager) bindPeerStream(peer *PeerClient, kind peerStreamKind, cancel context.CancelFunc) uint64 {
	pm.locker.Lock()
	if peer == nil || pm.peersByName[peer.Name] != peer {
		pm.locker.Unlock()
		return 0
	}
	previous := peer.streamCancels[kind]
	peer.streamGenerations[kind]++
	generation := peer.streamGenerations[kind]
	peer.streamCancels[kind] = cancel
	pm.locker.Unlock()
	if previous != nil {
		previous()
	}
	return generation
}

// RemovePeerStream ignores both old Hello registrations and rebound stream generations.
func (pm *PeerManager) RemovePeerStream(peer *PeerClient, kind peerStreamKind, generation uint64) bool {
	pm.locker.Lock()
	if peer == nil || pm.peersByName[peer.Name] != peer || peer.streamGenerations[kind] != generation {
		pm.locker.Unlock()
		return false
	}
	delete(pm.peersByName, peer.Name)
	connection, cancels := peer.peerConn, peer.streamCancels
	common.PrometheusMetrics.WorkerCnt.WithLabelValues().Dec()
	pm.locker.Unlock()
	closePeerResources(connection, cancels)
	logrus.Infof("removed peer session: %s", peer.Name)
	return true
}

func (pm *PeerManager) RemovePeer(name string) {
	pm.locker.Lock()
	peer := pm.peersByName[name]
	if peer == nil {
		pm.locker.Unlock()
		return
	}
	delete(pm.peersByName, name)
	connection, cancels := peer.peerConn, peer.streamCancels
	common.PrometheusMetrics.WorkerCnt.WithLabelValues().Dec()
	pm.locker.Unlock()
	closePeerResources(connection, cancels)
}

func (pm *PeerManager) GetPeer(name string) *PeerClient {
	pm.locker.Lock()
	defer pm.locker.Unlock()
	return pm.peersByName[name]
}

func (pm *PeerManager) GetAllWorkers() []*PeerClient {
	pm.locker.Lock()
	defer pm.locker.Unlock()
	peers := make([]*PeerClient, 0)
	for _, v := range pm.peersByName {
		peers = append(peers, v)
	}
	return peers
}

func (pm *PeerManager) CheckPeerAlive(name string) bool {
	pm.locker.Lock()
	defer pm.locker.Unlock()
	peer, ok := pm.peersByName[name]
	if !ok || peer.peerConn == nil || peer.peerConn.GetState() == connectivity.Idle {
		return false
	}
	return true
}
