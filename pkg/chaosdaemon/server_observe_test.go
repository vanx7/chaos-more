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
	"strings"
	"testing"
	"time"

	"github.com/chaos-mesh/chaos-mesh/pkg/chaosdaemon/crclients"
	"github.com/chaos-mesh/chaos-mesh/pkg/chaosdaemon/pb"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCommonObserve(t *testing.T) {
	ctx := context.Background()
	crClient, err := crclients.CreateContainerRuntimeInfoClient("docker")
	if err != nil {
		t.Fatal(err)
	}

	id := "docker://f26c09d1bc4c4994e6881636377bb0b0cab72957a26ac0454e9c3f0be410e019"
	pid, err := crClient.GetPidFromContainerID(ctx, id)
	if err != nil {
		t.Fatal(status.Errorf(codes.Internal, "get pid from containerID error: %v", err))
	}
	interfaces, err := getAllInterfaces(pid)
	if err != nil {
		t.Fatal(status.Errorf(codes.Internal, "get pid from containerID error: %v", err))
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		t.Fatal(status.Errorf(codes.Internal, "get pid from containerID error: %v", err))
	}
	var monitorDevices []pcap.Interface
	for _, d := range devices {
		for _, n := range interfaces {
			if n == d.Name {
				monitorDevices = append(monitorDevices, d)
			}
		}
	}

	// var key [44]byte
	for {
		select {
		case <-ctx.Done():
			t.Log("done")
		default:
			if len(monitorDevices) > 0 {
				i := monitorDevices[0]
				logrus.Infof("open live of interface %s", i.Name)
				handle, err := pcap.OpenLive(i.Name, 1024, false, 3*time.Second)
				if err != nil {
					zap.L().Error(err.Error())
				}
				defer handle.Close()
				packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

				var info []string
				for packet := range packetSource.Packets() {
					info = append(info, packet.String())
				}

				resp := &pb.CommonObserveResponse{Tcp: strings.Join(info, ";")}
				t.Log(resp)
			}

		}

	}

}
