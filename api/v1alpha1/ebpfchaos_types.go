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

// EBPFChaos is the control script`s spec.
type EBPFChaos struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the behavior of a pod chaos experiment
	Spec EBPFChaosSpec `json:"spec"`

	// +optional
	// Most recently observed status of the chaos experiment about pods
	Status EBPFChaosStatus `json:"status"`
}

var _ InnerObjectWithSelector = (*EBPFChaos)(nil)
var _ InnerObject = (*EBPFChaos)(nil)

type EBPFChaosAction string

// EBPFChaosSpec defines the attributes that a user creates on a chaos experiment about pods.
type EBPFChaosSpec struct {
	ContainerSelector `json:",inline"`

	// Action defines the specific pod ebpf action.
	Action EBPFChaosAction `json:"action"`

	// Duration represents the duration of the chaos action.
	// It is required when the action is `PodFailureAction`.
	// A duration string is a possibly signed sequence of
	// decimal numbers, each with optional fraction and a unit suffix,
	// such as "300ms", "-1.5h" or "2h45m".
	// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
	// +optional
	Duration *string `json:"duration,omitempty" webhook:"Duration"`

	// Data is ELF 64-bit LSB relocatable, eBPF with base64 encode
	// use it should first decode it with base64
	Data string `json:"data"`
}

// EBPFChaosStatus represents the current status of the chaos experiment about pods.
type EBPFChaosStatus struct {
	ChaosStatus `json:",inline"`
}

func (obj *EBPFChaos) GetSelectorSpecs() map[string]interface{} {
	return map[string]interface{}{
		".": &obj.Spec.PodSelector,
	}
}
