/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// RebootPodSpec defines the desired state of RebootPod
type RebootPodSpec struct {
	// Targets holds a list of RestartTarget items
	RestartTargets  []RestartTarget `json:"restartTargets,omitempty"`
	JwtRole         string          `json:"jwtRole,omitempty"`         // Vault Role for JWT Auth
	VaultEndpointDB string          `json:"vaultEndpointDB,omitempty"` // Vault Database Credentials API endpoint
}

type RestartTarget struct {
	// Kind indicates the type of resource (e.g., Deployment, StatefulSet)
	// +kubebuilder:validation:Enum=Deployment;StatefulSet

	Kind string `json:"kind"`
	Name string `json:"name"`
}

// RebootPodStatus defines the observed state of RebootPod
type RebootPodStatus struct {
	RolloutStatus   RolloutStatus            `json:"rolloutStatus,omitempty"`
	LastHealthCheck metav1.Time              `json:"lastHealthCheck,omitempty"`
	VaultSyncStatus VaultSync                `json:"vaultSyncStatus,omitempty"`
	EventIssues     []corev1.ObjectReference `json:"eventIssues,omitempty"` // Field to track event-related issues
}

// RolloutStatus tracks the status of a rollout or pod reboot
type RolloutStatus struct {
	State              string                   `json:"state,omitempty"` // Success/Failure
	FailedHealthChecks []corev1.ObjectReference `json:"failedHealthChecks,omitempty"`
}

// VaultSync defines the observed state of Vault synchronization
type VaultSync struct {
	State         string                   `json:"state,omitempty"` // Success/Failure
	SynchedSecret []corev1.ObjectReference `json:"synchedSecret,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// RebootPod is the Schema for the rebootpods API
type RebootPod struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RebootPodSpec   `json:"spec,omitempty"`
	Status RebootPodStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RebootPodList contains a list of RebootPod
type RebootPodList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RebootPod `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RebootPod{}, &RebootPodList{})
}
