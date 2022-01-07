// Copyright Chaos Mesh Authors.
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

// Code generated by chaos-builder. DO NOT EDIT.

package v1alpha1


import (
	"fmt"
)


const (
	ScheduleTypeAWSChaos ScheduleTemplateType = "AWSChaos"
	ScheduleTypeDNSChaos ScheduleTemplateType = "DNSChaos"
	ScheduleTypeEBPFChaos ScheduleTemplateType = "EBPFChaos"
	ScheduleTypeGCPChaos ScheduleTemplateType = "GCPChaos"
	ScheduleTypeHTTPChaos ScheduleTemplateType = "HTTPChaos"
	ScheduleTypeIOChaos ScheduleTemplateType = "IOChaos"
	ScheduleTypeJVMChaos ScheduleTemplateType = "JVMChaos"
	ScheduleTypeKernelChaos ScheduleTemplateType = "KernelChaos"
	ScheduleTypeNetworkChaos ScheduleTemplateType = "NetworkChaos"
	ScheduleTypePhysicalMachineChaos ScheduleTemplateType = "PhysicalMachineChaos"
	ScheduleTypePodChaos ScheduleTemplateType = "PodChaos"
	ScheduleTypeRedisChaos ScheduleTemplateType = "RedisChaos"
	ScheduleTypeStressChaos ScheduleTemplateType = "StressChaos"
	ScheduleTypeTimeChaos ScheduleTemplateType = "TimeChaos"
	ScheduleTypeWorkflow ScheduleTemplateType = "Workflow"

)

var allScheduleTemplateType = []ScheduleTemplateType{
	ScheduleTypeAWSChaos,
	ScheduleTypeDNSChaos,
	ScheduleTypeEBPFChaos,
	ScheduleTypeGCPChaos,
	ScheduleTypeHTTPChaos,
	ScheduleTypeIOChaos,
	ScheduleTypeJVMChaos,
	ScheduleTypeKernelChaos,
	ScheduleTypeNetworkChaos,
	ScheduleTypePhysicalMachineChaos,
	ScheduleTypePodChaos,
	ScheduleTypeRedisChaos,
	ScheduleTypeStressChaos,
	ScheduleTypeTimeChaos,
	ScheduleTypeWorkflow,

}

func (it *ScheduleItem) SpawnNewObject(templateType ScheduleTemplateType) (GenericChaos, error) {
	switch templateType {
	case ScheduleTypeAWSChaos:
		result := AWSChaos{}
		result.Spec = *it.AWSChaos
		return &result, nil
	case ScheduleTypeDNSChaos:
		result := DNSChaos{}
		result.Spec = *it.DNSChaos
		return &result, nil
	case ScheduleTypeEBPFChaos:
		result := EBPFChaos{}
		result.Spec = *it.EBPFChaos
		return &result, nil
	case ScheduleTypeGCPChaos:
		result := GCPChaos{}
		result.Spec = *it.GCPChaos
		return &result, nil
	case ScheduleTypeHTTPChaos:
		result := HTTPChaos{}
		result.Spec = *it.HTTPChaos
		return &result, nil
	case ScheduleTypeIOChaos:
		result := IOChaos{}
		result.Spec = *it.IOChaos
		return &result, nil
	case ScheduleTypeJVMChaos:
		result := JVMChaos{}
		result.Spec = *it.JVMChaos
		return &result, nil
	case ScheduleTypeKernelChaos:
		result := KernelChaos{}
		result.Spec = *it.KernelChaos
		return &result, nil
	case ScheduleTypeNetworkChaos:
		result := NetworkChaos{}
		result.Spec = *it.NetworkChaos
		return &result, nil
	case ScheduleTypePhysicalMachineChaos:
		result := PhysicalMachineChaos{}
		result.Spec = *it.PhysicalMachineChaos
		return &result, nil
	case ScheduleTypePodChaos:
		result := PodChaos{}
		result.Spec = *it.PodChaos
		return &result, nil
	case ScheduleTypeRedisChaos:
		result := RedisChaos{}
		result.Spec = *it.RedisChaos
		return &result, nil
	case ScheduleTypeStressChaos:
		result := StressChaos{}
		result.Spec = *it.StressChaos
		return &result, nil
	case ScheduleTypeTimeChaos:
		result := TimeChaos{}
		result.Spec = *it.TimeChaos
		return &result, nil
	case ScheduleTypeWorkflow:
		result := Workflow{}
		result.Spec = *it.Workflow
		return &result, nil

	default:
		return nil, fmt.Errorf("unsupported template type %s", templateType)
	}
}

func (it *ScheduleItem) RestoreChaosSpec(root interface{}) error {
	switch chaos := root.(type) {
	case *AWSChaos:
		*it.AWSChaos = chaos.Spec
		return nil
	case *DNSChaos:
		*it.DNSChaos = chaos.Spec
		return nil
	case *EBPFChaos:
		*it.EBPFChaos = chaos.Spec
		return nil
	case *GCPChaos:
		*it.GCPChaos = chaos.Spec
		return nil
	case *HTTPChaos:
		*it.HTTPChaos = chaos.Spec
		return nil
	case *IOChaos:
		*it.IOChaos = chaos.Spec
		return nil
	case *JVMChaos:
		*it.JVMChaos = chaos.Spec
		return nil
	case *KernelChaos:
		*it.KernelChaos = chaos.Spec
		return nil
	case *NetworkChaos:
		*it.NetworkChaos = chaos.Spec
		return nil
	case *PhysicalMachineChaos:
		*it.PhysicalMachineChaos = chaos.Spec
		return nil
	case *PodChaos:
		*it.PodChaos = chaos.Spec
		return nil
	case *RedisChaos:
		*it.RedisChaos = chaos.Spec
		return nil
	case *StressChaos:
		*it.StressChaos = chaos.Spec
		return nil
	case *TimeChaos:
		*it.TimeChaos = chaos.Spec
		return nil
	case *Workflow:
		*it.Workflow = chaos.Spec
		return nil

	default:
		return fmt.Errorf("unsupported chaos %#v", root)
	}
}
