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
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"vermeer/algorithms"
	"vermeer/apps/common"
	"vermeer/apps/compute"
	"vermeer/apps/graphio"
	pb "vermeer/apps/protos"
	"vermeer/apps/structure"
	"vermeer/apps/version"
)

var ServiceWorker Service

var GraphMgr = structure.GraphManager
var TaskMgr = structure.TaskManager
var LoadGraphMgr = graphio.LoadGraphWorker
var ComputeTaskMgr = compute.ComputerTaskManager
var AlgorithmMgr = compute.AlgorithmManager
var SpaceMgr = structure.SpaceManager

type Service struct {
	masterConn         *grpc.ClientConn
	MasterClient       pb.MasterClient
	LoadGraphHandler   *LoadGraphTaskHandler
	ComputeTaskHandler *ComputeTaskHandler
	SuperStepHandler   *SuperStepHandler
	locker             *sync.Mutex
	WorkerName         string
	WorkerId           int32
}

func (s *Service) Init() (err error) {
	defer func() {
		if err != nil {
			if s.masterConn != nil {
				_ = s.masterConn.Close()
			}
			for _, peer := range PeerMgr.GetAllWorkers() {
				if peer.peerConn != nil {
					_ = peer.peerConn.Close()
				}
			}
		}
	}()
	//node, err := snowflake.NewNode(rand.Int63n(1023))
	//if err != nil {
	//	logrus.Errorf("new snowflake error: %s", err)
	//}
	//s.WorkerName = node.Generate().String()
	s.ComputeTaskHandler = &ComputeTaskHandler{}
	s.LoadGraphHandler = &LoadGraphTaskHandler{}
	s.SuperStepHandler = &SuperStepHandler{}
	masterPeer := common.GetConfig("master_peer").(string)
	grpcPeer := common.GetConfig("grpc_peer").(string)
	workerGroup := common.GetConfigDefault("worker_group", "$").(string)
	// init peer manager
	PeerMgr.Init()

	dialOptions := grpc.WithDefaultCallOptions(
		grpc.MaxCallSendMsgSize(4*1024*1024*1024),
		grpc.MaxCallRecvMsgSize(4*1024*1024*1024))

	s.masterConn, err = common.DialGRPCPeer(context.Background(),
		masterPeer, grpc.WithTransportCredentials(insecure.NewCredentials()), dialOptions)
	if err != nil {
		logrus.Errorf("connect master error: %s", err)
		return err
	}
	s.MasterClient = pb.NewMasterClient(s.masterConn)
	ctx, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()
	resp, err := s.MasterClient.SayHelloMaster(
		ctx, &pb.HelloMasterReq{WorkerPeer: grpcPeer, Version: version.Version, WorkerGroup: workerGroup})
	if err != nil {
		logrus.Errorf("say hello master error: %s", err)
		return err
	}
	s.WorkerId = resp.GetWorkerId()
	s.WorkerName = resp.GetWorkerName()
	logrus.Infof("Hello World, I am worker %s", s.WorkerName)
	PeerMgr.AddPeer(s.WorkerName, s.WorkerId, grpcPeer)
	md := metadata.New(map[string]string{"worker_name": s.WorkerName})
	// Keep registration tied to a live stream even if peer bootstrap fails.
	// Compute/SuperStep stay unopened until the entire peer mesh is installed.
	loadCtx := metadata.NewOutgoingContext(context.Background(), md)
	s.LoadGraphHandler.grpcStream, err = s.MasterClient.LoadGraphTask(loadCtx)
	if err != nil {
		return fmt.Errorf("open registration lifeline: %w", err)
	}
	for _, w := range resp.GetWorkers() {
		peerClient := PeerMgr.AddPeer(w.Name, w.Id, w.GrpcPeer)
		peerConnection, err := common.DialGRPCPeer(context.Background(),
			w.GrpcPeer, grpc.WithTransportCredentials(insecure.NewCredentials()), dialOptions)
		if err != nil {
			return fmt.Errorf("connect to peer %s: %w", w.GrpcPeer, err)
		}
		if !PeerMgr.SetPeerConnection(peerClient, peerConnection) {
			return fmt.Errorf("peer registration was replaced during bootstrap")
		}
		ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := peerClient.peerSession.SayHelloPeer(
			ctx, &pb.HelloPeerReq{SourceName: s.WorkerName, TargetName: w.Name, WorkerPeer: grpcPeer})
		if err != nil {
			cancel2()
			return fmt.Errorf("bootstrap peer %s: %w", w.GrpcPeer, err)
		}

		// install scatter
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		stream, err := peerClient.peerSession.Scatter(ctx)
		if err != nil {
			cancel2()
			return fmt.Errorf("bootstrap peer %s: %w", w.GrpcPeer, err)
		}
		if peerClient.ScatterHandler.SetClient(stream) == 0 {
			cancel2()
			return fmt.Errorf("peer registration was replaced while binding streams")
		}

		// install load action
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		stream2, err := peerClient.peerSession.LoadAction(ctx)
		if err != nil {
			cancel2()
			return fmt.Errorf("bootstrap peer %s: %w", w.GrpcPeer, err)
		}
		if peerClient.LoadActionHandler.SetClient(stream2) == 0 {
			cancel2()
			return fmt.Errorf("peer registration was replaced while binding streams")
		}

		// install step end
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		stream3, err := peerClient.peerSession.StepEnd(ctx)
		if err != nil {
			cancel2()
			return fmt.Errorf("bootstrap peer %s: %w", w.GrpcPeer, err)
		}
		if peerClient.StepEndHandler.SetClient(stream3) == 0 {
			cancel2()
			return fmt.Errorf("peer registration was replaced while binding streams")
		}

		// install setting action
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		stream4, err := peerClient.peerSession.SettingAction(ctx)
		if err != nil {
			cancel2()
			return fmt.Errorf("bootstrap peer %s: %w", w.GrpcPeer, err)
		}
		if peerClient.SettingActionHandler.SetClient(stream4) == 0 {
			cancel2()
			return fmt.Errorf("peer registration was replaced while binding streams")
		}

		logrus.Infof("say hello peer %s, ok, %s", w.GrpcPeer, resp.GetStatus())
		cancel2()
	}
	logrus.Infof("say hello master ok, worker id: %d", s.WorkerId)

	ctx = metadata.NewOutgoingContext(context.Background(), md)
	s.ComputeTaskHandler.grpcStream, err = s.MasterClient.ComputeTask(ctx)
	if err != nil {
		logrus.Errorf("create load graph task stream error: %s", err)
		return err
	}
	logrus.Infof("create compute task stream ok")

	ctx = metadata.NewOutgoingContext(context.Background(), md)
	stepReq := pb.SuperStepReq{}
	s.SuperStepHandler.grpcStream, err = s.MasterClient.SuperStep(ctx, &stepReq)
	if err != nil {
		logrus.Errorf("create super step stream error: %s", err)
		return err
	}
	logrus.Infof("create super step stream ok")

	SpaceMgr.Init()
	GraphMgr.Init()
	TaskMgr.Init()
	LoadGraphMgr.Init()
	ComputeTaskMgr.Init()
	AlgorithmMgr.Init()
	for _, maker := range algorithms.Algorithms {
		AlgorithmMgr.Register(maker, "built-in")
	}
	AlgorithmMgr.LoadPlugins()
	s.locker = &sync.Mutex{}
	// for _, space := range resp.Spaces {
	// 	err := createSpaceIfAbsent(space)
	// 	if err != nil {
	// 		logrus.Errorf("create space error:%v", err)
	// 		return err
	// 	}
	// }
	return nil
}

func (s *Service) Run() {
	//与master的连接
	go s.LoadGraphHandler.HandleLoadGraphTask()
	go s.ComputeTaskHandler.HandleComputeTask()
	go s.SuperStepHandler.HandleSuperStep()

	//与peer worker的连接
	for _, w := range PeerMgr.GetAllWorkers() {
		if w.ScatterHandler.IsClient() {
			go w.ScatterHandler.RecvHandler(w.Name)
		}
		if w.LoadActionHandler.IsClient() {
			go w.LoadActionHandler.RecvHandler(w.Name)
		}
		if w.StepEndHandler.IsClient() {
			go w.StepEndHandler.RecvHandler(w.Name)
		}
		if w.SettingActionHandler.IsClient() {
			go w.SettingActionHandler.RecvHandler(w.Name)
		}
	}
}

func (s *Service) Close() {
	err := s.masterConn.Close()
	if err != nil {
		logrus.Errorf("master connection close error: %s", err)
	}
	logrus.Infof("master connection closed.")
}

func (s *Service) CheckMasterAlive() bool {
	if s.masterConn == nil || s.masterConn.GetState() != connectivity.Ready {
		return false
	}
	return s.LoadGraphHandler != nil && s.LoadGraphHandler.grpcStream != nil && s.LoadGraphHandler.grpcStream.Context().Err() == nil &&
		s.ComputeTaskHandler != nil && s.ComputeTaskHandler.grpcStream != nil && s.ComputeTaskHandler.grpcStream.Context().Err() == nil &&
		s.SuperStepHandler != nil && s.SuperStepHandler.grpcStream != nil && s.SuperStepHandler.grpcStream.Context().Err() == nil
}

func (s *Service) ReconnectMaster() {
	s.locker.Lock()
	defer s.locker.Unlock()
	if s.CheckMasterAlive() {
		logrus.Infof("master is alive:%v", s.masterConn.GetState())
		return
	}
	bootstrapped := false
	defer func() {
		if !bootstrapped {
			if s.masterConn != nil {
				_ = s.masterConn.Close()
				s.masterConn = nil
			}
			for _, peer := range PeerMgr.GetAllWorkers() {
				if peer.peerConn != nil {
					_ = peer.peerConn.Close()
				}
			}
		}
	}()
	logrus.Infof("try to reconnect master")
	//初始化
	SpaceMgr.Init()
	GraphMgr.Init()
	TaskMgr.Init()
	LoadGraphMgr.Init()
	ComputeTaskMgr.Init()
	PeerMgr.Init()
	//common.PrometheusMetrics.TaskCnt.Reset()
	common.PrometheusMetrics.TaskRunningCnt.Reset()
	//common.PrometheusMetrics.GraphCnt.Reset()
	//common.PrometheusMetrics.GraphLoadedCnt.Reset()
	masterPeer := common.GetConfig("master_peer").(string)
	grpcPeer := common.GetConfig("grpc_peer").(string)
	//连接master
	dialOptions := grpc.WithDefaultCallOptions(
		grpc.MaxCallSendMsgSize(4*1024*1024*1024),
		grpc.MaxCallRecvMsgSize(4*1024*1024*1024),
	)
	var err error
	s.masterConn, err = common.DialGRPCPeer(context.Background(),
		masterPeer, grpc.WithTransportCredentials(insecure.NewCredentials()), dialOptions)
	if err != nil {
		logrus.Errorf("connect master error: %s", err)
		return
	}
	s.MasterClient = pb.NewMasterClient(s.masterConn)
	ctx, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()
	resp, err := s.MasterClient.SayHelloMaster(
		ctx, &pb.HelloMasterReq{WorkerPeer: grpcPeer, Version: version.Version})
	if err != nil {
		logrus.Infof("reconnect say hello master error:%v", err)
		return
	}
	s.WorkerId = resp.GetWorkerId()
	s.WorkerName = resp.GetWorkerName()
	logrus.Infof("Reconnect, I am worker %s", s.WorkerName)
	PeerMgr.AddPeer(s.WorkerName, s.WorkerId, grpcPeer)
	md := metadata.New(map[string]string{"worker_name": s.WorkerName})
	loadCtx := metadata.NewOutgoingContext(context.Background(), md)
	tempLoadGraphGrpcStream, err := s.MasterClient.LoadGraphTask(loadCtx)
	if err != nil {
		logrus.Errorf("reconnect registration lifeline: %v", err)
		return
	}
	s.LoadGraphHandler.grpcStream = tempLoadGraphGrpcStream
	for _, workerInfo := range resp.GetWorkers() {
		//对已建立grpc连接的peer忽略。建立未知peer的grpc连接，并启动handler
		peer := PeerMgr.GetPeer(workerInfo.GetName())
		if peer != nil {
			continue
		}
		peerClient := PeerMgr.AddPeer(workerInfo.Name, workerInfo.Id, workerInfo.GrpcPeer)
		peerConnection, err := common.DialGRPCPeer(context.Background(),
			workerInfo.GrpcPeer, grpc.WithTransportCredentials(insecure.NewCredentials()), dialOptions)
		if err != nil {
			logrus.Errorf("connect to peer %s error: %s", workerInfo.GrpcPeer, err)
			return
		}
		if !PeerMgr.SetPeerConnection(peerClient, peerConnection) {
			logrus.Error("peer registration was replaced during reconnect")
			return
		}
		ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		resp, err := peerClient.peerSession.SayHelloPeer(
			ctx, &pb.HelloPeerReq{SourceName: s.WorkerName, TargetName: workerInfo.Name, WorkerPeer: grpcPeer})
		if err != nil {
			logrus.Errorf("say hello peer %s error: %s", workerInfo.GrpcPeer, err)
			return
		}

		// install scatter
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		stream, err := peerClient.peerSession.Scatter(ctx)
		if err != nil {
			logrus.Errorf("create scatter stream peer: %s error: %s", workerInfo.GrpcPeer, err)
			return
		}
		if peerClient.ScatterHandler.SetClient(stream) == 0 {
			logrus.Error("peer registration was replaced while binding streams")
			return
		}

		// install load action
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		stream2, err := peerClient.peerSession.LoadAction(ctx)
		if err != nil {
			logrus.Errorf("create load action stream peer: %s error: %s", workerInfo.GrpcPeer, err)
			return
		}
		if peerClient.LoadActionHandler.SetClient(stream2) == 0 {
			logrus.Error("peer registration was replaced while binding streams")
			return
		}

		// install step end
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		stream3, err := peerClient.peerSession.StepEnd(ctx)
		if err != nil {
			logrus.Errorf("create step end stream peer: %s error: %s", workerInfo.GrpcPeer, err)
			return
		}
		if peerClient.StepEndHandler.SetClient(stream3) == 0 {
			logrus.Error("peer registration was replaced while binding streams")
			return
		}

		// install setting action
		ctx = metadata.NewOutgoingContext(context.Background(), md)
		stream4, err := peerClient.peerSession.SettingAction(ctx)
		if err != nil {
			logrus.Errorf("create step end stream peer: %s error: %s", workerInfo.GrpcPeer, err)
			return
		}
		if peerClient.SettingActionHandler.SetClient(stream4) == 0 {
			logrus.Error("peer registration was replaced while binding streams")
			return
		}

		logrus.Infof("say hello peer %s, ok, %s", workerInfo.GrpcPeer, resp.GetStatus())
		cancel2()
		if peerClient.ScatterHandler.IsClient() {
			go peerClient.ScatterHandler.RecvHandler(peerClient.Name)
		}
		if peerClient.LoadActionHandler.IsClient() {
			go peerClient.LoadActionHandler.RecvHandler(peerClient.Name)
		}
		if peerClient.StepEndHandler.IsClient() {
			go peerClient.StepEndHandler.RecvHandler(peerClient.Name)
		}
		if peerClient.SettingActionHandler.IsClient() {
			go peerClient.SettingActionHandler.RecvHandler(peerClient.Name)
		}
	}

	ctx = metadata.NewOutgoingContext(context.Background(), md)
	tempComputeGrpcStream, err := s.MasterClient.ComputeTask(ctx)
	if err != nil {
		logrus.Errorf("reconnect create load graph task stream error: %s", err)
		return
	}
	s.ComputeTaskHandler.grpcStream = tempComputeGrpcStream
	logrus.Infof("reconnect create compute task stream ok")

	ctx = metadata.NewOutgoingContext(context.Background(), md)
	stepReq := pb.SuperStepReq{}
	tempSuperStepGrpcStream, err := s.MasterClient.SuperStep(ctx, &stepReq)
	if err != nil {
		logrus.Errorf("reconnect create super step stream error: %s", err)
		return
	}
	s.SuperStepHandler.grpcStream = tempSuperStepGrpcStream
	logrus.Infof("reconnect create super step stream ok")
	bootstrapped = true
}
