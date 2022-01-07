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

package redischaos

import (
	"context"
	"github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/utils"
	"github.com/chaos-mesh/chaos-mesh/controllers/utils/controller"
	"github.com/chaos-mesh/chaos-mesh/pkg/chaosdaemon/pb"
	"github.com/go-logr/logr"
	"github.com/sirupsen/logrus"
	"go.uber.org/fx"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"

	"github.com/chaos-mesh/chaos-mesh/api/v1alpha1"
	impltypes "github.com/chaos-mesh/chaos-mesh/controllers/chaosimpl/types"
)

var _ impltypes.ChaosImpl = (*Impl)(nil)

type Impl struct {
	client.Client
	Log     logr.Logger
	decoder *utils.ContainerRecordDecoder
}

func (impl *Impl) Apply(ctx context.Context, index int, records []*v1alpha1.Record, obj v1alpha1.InnerObject) (v1alpha1.Phase, error) {
	var pod v1.Pod
	name, err := controller.ParseNamespacedName(records[index].Id)
	if err != nil {
		return v1alpha1.NotInjected, err
	}
	logrus.Info("redis chaos apply")
	err = impl.Get(ctx, name, &pod)
	if err != nil {
		return v1alpha1.NotInjected, err
	}
	pbClient, err := impl.decoder.ChaosDaemonClientBuilder.Build(ctx, &pod)
	if err != nil {
		return v1alpha1.NotInjected, err
	}

	if pbClient != nil {
		defer pbClient.Close()
	}
	if err != nil {
		return v1alpha1.NotInjected, err
	}

	redischaos := obj.(*v1alpha1.RedisChaos)

	logrus.Info("redis chaos %s", redischaos.Name)
	var dockerId string
	for i := 0; i < 5; i++ {
		if len(pod.Status.ContainerStatuses) == 0 {
			time.Sleep(1 * time.Second)
			continue
		}
		sta := pod.Status.ContainerStatuses[0]
		dockerId = sta.ContainerID
	}
	logrus.Info("setting redis chaos", "ns", redischaos.Namespace,
		"name", redischaos.Name, "action", redischaos.Spec.Action, "podId", name.Name)
	_, err = pbClient.ApplyRedisChaos(ctx, &pb.RedisRequest{
		ContainerId: dockerId,
		Action:      string(redischaos.Spec.Action),
		Load:        true,
	})
	if err != nil {
		return v1alpha1.NotInjected, err
	}

	return v1alpha1.Injected, nil
}

func (impl *Impl) Recover(ctx context.Context, index int, records []*v1alpha1.Record, obj v1alpha1.InnerObject) (v1alpha1.Phase, error) {
	decodedContainer, err := impl.decoder.DecodeContainerRecord(ctx, records[index])
	pbClient := decodedContainer.PbClient
	containerId := decodedContainer.ContainerId
	if pbClient != nil {
		defer pbClient.Close()
	}
	if err != nil {
		if utils.IsFailToGet(err) {
			// pretend the disappeared container has been recovered
			return v1alpha1.NotInjected, nil
		}
		return v1alpha1.Injected, err
	}

	impl.Log.Info("recover redis chaos for container", "containerId", containerId)
	_, err = pbClient.ApplyRedisChaos(ctx, &pb.RedisRequest{
		ContainerId: containerId,
		Action:      "recover",
		Load:        false,
	})
	if err != nil {
		return v1alpha1.Injected, err
	}

	return v1alpha1.NotInjected, nil
}

func NewImpl(c client.Client, log logr.Logger, decoder *utils.ContainerRecordDecoder) *impltypes.ChaosImplPair {
	return &impltypes.ChaosImplPair{
		Name:   "redischaos",
		Object: &v1alpha1.RedisChaos{},
		Impl: &Impl{
			Client:  c,
			Log:     log.WithName("redischaos"),
			decoder: decoder,
		},
	}
}

var Module = fx.Provide(
	fx.Annotated{
		Group:  "impl",
		Target: NewImpl,
	},
)
