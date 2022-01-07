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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +chaos-mesh:experiment
// +chaos-mesh:oneshot=in.Spec.Action==RedisDropAction || in.Spec.Action==RedisDelayAction ||  in.Spec.Action==RedisEmptyQueryAction

// RedisChaos is the control script`s spec.
type RedisChaos struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the behavior of a pod chaos experiment
	Spec RedisChaosSpec `json:"spec"`

	// +optional
	// Most recently observed status of the chaos experiment about pods
	Status RedisChaosStatus `json:"status"`
}

var _ InnerObjectWithSelector = (*RedisChaos)(nil)
var _ InnerObject = (*RedisChaos)(nil)

// RedisChaosAction represents the chaos action about pods.
type RedisChaosAction string

const (
	// RedisDropAction represents the chaos action of drop redis packet.
	RedisDropAction RedisChaosAction = "redis-drop"
	// RedisDelayAction represents the chaos action of delay redis packet.
	RedisDelayAction RedisChaosAction = "redis-delay"
	// RedisEmptyQueryAction represents the chaos action of delay redis packet.
	RedisEmptyQueryAction RedisChaosAction = "redis-empty-query"
)

// RedisChaosSpec defines the attributes that a user creates on a chaos experiment about pods.
type RedisChaosSpec struct {
	ContainerSelector `json:",inline"`

	// Action defines the specific redis chaos action.
	// Supported action: redis-drop / redis-delay / redis-empty-query
	// Default action: redis-drop
	// +kubebuilder:validation:Enum=redis-drop;redis-delay;redis-empty-query
	Action RedisChaosAction `json:"action"`

	// Duration represents the duration of the chaos action.
	// It is required when the action is `PodFailureAction`.
	// A duration string is a possibly signed sequence of
	// decimal numbers, each with optional fraction and a unit suffix,
	// such as "300ms", "-1.5h" or "2h45m".
	// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	// +optional
	Duration *string `json:"duration,omitempty" webhook:"Duration"`

	// GracePeriod is used in pod-kill action. It represents the duration in seconds before the pod should be deleted.
	// Value must be non-negative integer. The default value is zero that indicates delete immediately.
	// +optional
	Latency int64 `json:"latency,omitempty"`
}

// RedisChaosStatus represents the current status of the chaos experiment about pods.
type RedisChaosStatus struct {
	ChaosStatus `json:",inline"`
}

func (obj *RedisChaos) GetSelectorSpecs() map[string]interface{} {
	switch obj.Spec.Action {
	case RedisDelayAction, RedisDropAction, RedisEmptyQueryAction:
		return map[string]interface{}{
			".": &obj.Spec.PodSelector,
		}
	}
	return nil
}
