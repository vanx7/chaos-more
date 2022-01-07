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
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/chaos-mesh/chaos-mesh/pkg/chaosdaemon/pb"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/golang/protobuf/ptypes/empty"
)

func (s *DaemonServer) ApplyEBPFChaos(ctx context.Context, in *pb.EBPFRequest) (*empty.Empty, error) {
	log.Info("handling ebpf request", "id", in.GetContainerId(), "action", in.GetAction())

	var elf []byte
	_, err := base64.StdEncoding.Decode([]byte(in.GetData()), elf)
	if err != nil {
		return nil, err
	}
	// if unload send stop signal
	if !in.GetLoad() {
		uniq := fmt.Sprintf("%s-%s", in.ContainerId, in.Action)
		if ch, ok := daemonMap[uniq]; ok {
			ch <- struct{}{}
		}
		return &empty.Empty{}, nil
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		log.Error(err, "error while getting interfaces")
		return nil, err
	}

	if len(spec.Programs) == 0 {
		return nil, fmt.Errorf("programs should exist")
	}
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	var prog *ebpf.ProgramSpec
	for _, p := range spec.Programs {
		if prog != nil {
			break
		}
		prog = p
	}

	target, err := ebpf.NewProgram(prog)
	if err != nil {
		return nil, err
	}

	var lk link.Link
	switch prog.Type {
	case ebpf.CGroupSockAddr:
		containerCgroup, err := findCgroupByContainerId(in.GetContainerId())
		if err != nil {
			return nil, fmt.Errorf("link not sockops failed %+v", err)
		}
		lk, err = link.AttachCgroup(link.CgroupOptions{
			Path:    containerCgroup,
			Attach:  ebpf.AttachCGroupInet4Connect,
			Program: target,
		})
	case ebpf.Kprobe:
		lk, err = link.Kprobe(prog.AttachTo, target)
		if err != nil {
			return nil, fmt.Errorf("link for Kprobe program failed %+v", err)
		}
	case ebpf.SockOps:
		containerCgroup, err := findCgroupByContainerId(in.GetContainerId())
		if err != nil {
			return nil, fmt.Errorf("link not sockops failed %+v", err)
		}
		lk, err = link.AttachCgroup(link.CgroupOptions{
			Path:    containerCgroup,
			Attach:  ebpf.AttachCGroupSockOps,
			Program: target,
		})
	default:
		return nil, fmt.Errorf("current not support type %d", prog.Type)
	}
	if err != nil {
		return nil, err
	}

	// go routine exec such thing
	go func() {
		uniqId := fmt.Sprintf("%s-%s", in.GetContainerId(), in.GetAction())
		select {
		case <-daemonMap[uniqId]:
			lk.Close()
		}
	}()

	return &empty.Empty{}, nil
}

func findCgroupByContainerId(containerId string) (string, error) {
	return "", nil
}
