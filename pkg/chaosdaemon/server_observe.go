// Copyright 2021 Chaos Mesh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package chaosdaemon

import (
	"context"
	pb "github.com/chaos-mesh/chaos-mesh/pkg/chaosdaemon/pb"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"time"
)

const (
	observeElf    = "/tmp/observe.o"
	observeIO     = "observe_io"
	observeKernel = "observe_kernel"
	observeTcp    = "observe_tcp"
)

type sockKey struct {
	Sip4   [4]byte
	Dip4   [4]byte
	Family [1]byte
	Pad1   [1]byte
	Pad2   [2]byte
	Pad3   [4]byte
	Sport  [4]byte
	Dport  [4]byte
}

func (s *DaemonServer) CommonObserve(ctx context.Context, req *pb.CommonObserveRequest) (*pb.CommonObserveResponse, error) {
	logrus.Info("handling observe request", "req", req)

	resp := &pb.CommonObserveResponse{}
	pid, err := s.crClient.GetPidFromContainerID(ctx, req.GetContainerId())
	if err != nil {
		resp.Tcp = append(resp.Tcp, err.Error())
		return resp, status.Errorf(codes.Internal, "get pid from containerID error: %v", err)
	}
	interfaces, err := getAllInterfaces(pid)
	if err != nil {
		resp.Tcp = append(resp.Tcp, err.Error())
		return resp, status.Errorf(codes.Internal, "get interfaces error: %v", err)
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		resp.Tcp = append(resp.Tcp, err.Error())
		return resp, status.Errorf(codes.Internal, "get devices error: %v", err)
	}
	var monitorDevices []pcap.Interface
	for _, d := range devices {
		for _, n := range interfaces {
			if n == d.Name {
				monitorDevices = append(monitorDevices, d)
			}
		}
	}

	if len(monitorDevices) > 0 {
		i := monitorDevices[0]
		logrus.Infof("open live of interface %s", i.Name)
		handle, err := pcap.OpenLive(i.Name, 1024, false, 3*time.Second)
		if err != nil {
			zap.L().Error(err.Error())
		}
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			resp.Tcp = append(resp.Tcp, packet.String())
		}
	}

	return resp, nil
}
