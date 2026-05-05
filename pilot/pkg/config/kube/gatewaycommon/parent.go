// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gatewaycommon

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
)

// ParentKey holds info about a parentRef (e.g. a route binding to a Gateway). It is a
// map-friendly representation of gatewayv1.ParentReference.
type ParentKey struct {
	Kind config.GroupVersionKind
	// Name is the original name of the resource (e.g. Kubernetes Gateway name)
	Name string
	// Namespace is the namespace of the resource
	Namespace string
}

func (p ParentKey) String() string {
	return p.Kind.String() + "/" + p.Namespace + "/" + p.Name
}

// ParentReference holds the parent key, section name and port for a parent reference.
type ParentReference struct {
	ParentKey

	SectionName gatewayv1.SectionName
	Port        gatewayv1.PortNumber
}

func (p ParentReference) String() string {
	return p.ParentKey.String() + "/" + string(p.SectionName) + "/" + fmt.Sprint(p.Port)
}

// ParentInfo holds info about a "Parent" — something that can be referenced as a ParentRef in the
// Gateway API. Today this is just Gateway.
type ParentInfo struct {
	ParentGateway types.NamespacedName
	// +krtEqualsTodo ensure gateway class changes trigger equality differences
	ParentGatewayClassName string
	// InternalName refers to the internal name we can reference the parent by, e.g. "my-ns/my-gateway"
	InternalName string
	// AllowedKinds indicates which kinds can be admitted by this Parent
	AllowedKinds []gatewayv1.RouteGroupKind
	// Hostnames is the hostnames that must match to reference to the Parent (listener hostname).
	// Format is ns/hostname.
	Hostnames []string
	// OriginalHostname is the unprocessed form of Hostnames as it appeared in user config
	OriginalHostname string

	SectionName    gatewayv1.SectionName
	Port           gatewayv1.PortNumber
	Protocol       gatewayv1.ProtocolType
	TLSPassthrough bool
}

func (g ParentInfo) Equals(other ParentInfo) bool {
	return g.ParentGateway == other.ParentGateway &&
		g.InternalName == other.InternalName &&
		g.OriginalHostname == other.OriginalHostname &&
		g.SectionName == other.SectionName &&
		g.Port == other.Port &&
		g.Protocol == other.Protocol &&
		g.TLSPassthrough == other.TLSPassthrough &&
		slices.EqualFunc(g.AllowedKinds, other.AllowedKinds, func(a, b gatewayv1.RouteGroupKind) bool {
			return a.Kind == b.Kind && ptr.Equal(a.Group, b.Group)
		}) &&
		slices.Equal(g.Hostnames, other.Hostnames)
}

// TLSInfo contains the resolved TLS certificate material for a gateway listener.
type TLSInfo struct {
	Cert   []byte
	CaCert []byte
	Key    []byte `json:"-"`
}

// ConfigErrorReason represents a reason for a configuration error.
type ConfigErrorReason = string

const (
	// InvalidDestination indicates an issue with the destination
	InvalidDestination ConfigErrorReason = "InvalidDestination"
	InvalidAddress     ConfigErrorReason = ConfigErrorReason(gatewayv1.GatewayReasonUnsupportedAddress)
	// InvalidDestinationPermit indicates a destination was not permitted
	InvalidDestinationPermit ConfigErrorReason = ConfigErrorReason(gatewayv1.RouteReasonRefNotPermitted)
	// InvalidDestinationKind indicates an issue with the destination kind
	InvalidDestinationKind ConfigErrorReason = ConfigErrorReason(gatewayv1.RouteReasonInvalidKind)
	// InvalidDestinationNotFound indicates a destination does not exist
	InvalidDestinationNotFound ConfigErrorReason = ConfigErrorReason(gatewayv1.RouteReasonBackendNotFound)
	// InvalidFilter indicates an issue with the filters
	InvalidFilter ConfigErrorReason = "InvalidFilter"
	// InvalidTLS indicates an issue with TLS settings
	InvalidTLS ConfigErrorReason = ConfigErrorReason(gatewayv1.ListenerReasonInvalidCertificateRef)
	// InvalidListenerRefNotPermitted indicates a listener reference was not permitted
	InvalidListenerRefNotPermitted ConfigErrorReason = ConfigErrorReason(gatewayv1.ListenerReasonRefNotPermitted)
	// InvalidConfiguration indicates a generic error for all other invalid configurations
	InvalidConfiguration ConfigErrorReason = "InvalidConfiguration"
	DeprecateFieldUsage  ConfigErrorReason = "DeprecatedField"
)

// ConfigError represents an invalid configuration that will be reported back to the user.
type ConfigError struct {
	Reason  ConfigErrorReason
	Message string
}

// Condition represents a Kubernetes status condition with optional error state.
type Condition struct {
	// reason defines the reason to report on success. Ignored if error is set
	Reason string
	// message defines the message to report on success. Ignored if error is set
	Message string
	// status defines the status to report on success. The inverse will be set if error is set.
	// Defaults to StatusTrue when empty.
	Status metav1.ConditionStatus
	// Error defines an error state; the reason and message will be replaced with that of the error and
	// the status inverted
	Error *ConfigError
	// SetOnce, if set, will only set the condition if it is not yet present or set to this reason
	SetOnce string
}

// ParentErrorReason describes why a parent reference was denied.
type ParentErrorReason string

const (
	ParentErrorNotAccepted       = ParentErrorReason(gatewayv1.RouteReasonNoMatchingParent)
	ParentErrorNotAllowed        = ParentErrorReason(gatewayv1.RouteReasonNotAllowedByListeners)
	ParentErrorNoHostname        = ParentErrorReason(gatewayv1.RouteReasonNoMatchingListenerHostname)
	ParentErrorParentRefConflict = ParentErrorReason("ParentRefConflict")
	ParentNoError                = ParentErrorReason("")
)

// ParentError represents that a parent could not be referenced
type ParentError struct {
	Reason  ParentErrorReason
	Message string
}

