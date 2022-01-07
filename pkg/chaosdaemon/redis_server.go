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
	"fmt"
	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
	"github.com/chaos-mesh/chaos-mesh/pkg/bpm"
	"github.com/sirupsen/logrus"
	"strings"

	pb "github.com/chaos-mesh/chaos-mesh/pkg/chaosdaemon/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/ptypes/empty"
)

const (
	delayElf      = "/tmp/redis-delay.o"
	dropElf       = "/tmp/redis-drop.o"
	emptyQueryElf = "/tmp/redis-empty-query.o"
)

func (s *DaemonServer) ApplyRedisChaos(ctx context.Context, in *pb.RedisRequest) (*empty.Empty, error) {

	logrus.Info("handling redis request", in.String())

	pid, err := s.crClient.GetPidFromContainerID(ctx, in.GetContainerId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get pid from containerID error: %v", err)
	}
	logrus.Infof("get pid %d for container %s redis", pid, in.GetContainerId())

	tcCli := buildTcClient(ctx, true, pid)

	ifaces, err := getAllInterfaces(pid)
	if err != nil {
		log.Error(err, "error while getting interfaces")
		return nil, err
	}
	//for _, iface := range ifaces {
	//	err = tcCli.flush(iface)
	//	if err != nil {
	//		log.Error(err, "fail to flush tc rules on device", "device", iface)
	//	}
	//}
	if err != nil {
		return &empty.Empty{}, err
	}

	var tcfunc func(device string, handle string) error
	if in.GetLoad() {
		tcfunc = tcCli.addEgress
	} else {
		tcfunc = tcCli.recoverEgress
	}

	switch in.Action {
	case string(v1alpha1.RedisEmptyQueryAction):
		for _, i := range ifaces {
			tcfunc(i, emptyQueryElf)
		}
	case string(v1alpha1.RedisDelayAction):
		for _, i := range ifaces {
			tcfunc(i, delayElf)
		}
	case string(v1alpha1.RedisDropAction):
		for _, i := range ifaces {
			tcfunc(i, dropElf)
		}
	default:
		return nil, fmt.Errorf("not support action %s", in.Action)
	}
	logrus.Infof("apply to ifaces %+v with action %s", ifaces, in.GetAction())
	return &empty.Empty{}, nil
}

func (c *tcClient) addEgress(device string, handle string) error {
	logrus.Infof("adding egress", "device", device, "handle", handle)

	args := fmt.Sprintf("qdisc add dev %s clsact", device)
	processBuilder := bpm.DefaultProcessBuilder("tc", strings.Split(args, " ")...).SetContext(c.ctx)
	if c.enterNS {
		processBuilder = processBuilder.SetNS(c.pid, bpm.NetNS)
	}
	cmd := processBuilder.Build()
	output, err := cmd.CombinedOutput()
	if err != nil {
		logrus.Infof("adding egress clsact failed", "device", device, "handle", handle)
	}
	// egress section
	args = fmt.Sprintf("filter add dev %s egress bpf da obj %s sec egress", device, handle)
	processBuilder = bpm.DefaultProcessBuilder("tc", strings.Split(args, " ")...).SetContext(c.ctx)
	if c.enterNS {
		processBuilder = processBuilder.SetNS(c.pid, bpm.NetNS)
	}
	cmd = processBuilder.Build()
	output, err = cmd.CombinedOutput()
	if err != nil {
		return encodeOutputToError(output, err)
	}
	return nil
}

func (c *tcClient) recoverEgress(device string, handle string) error {
	logrus.Infof("delete egress", "device", device, "handle", handle)

	args := fmt.Sprintf("filter add dev %s egress bpf da obj %s sec egress", device, handle)
	processBuilder := bpm.DefaultProcessBuilder("tc", strings.Split(args, " ")...).SetContext(c.ctx)
	if c.enterNS {
		processBuilder = processBuilder.SetNS(c.pid, bpm.NetNS)
	}
	cmd := processBuilder.Build()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return encodeOutputToError(output, err)
	}
	return nil
}
