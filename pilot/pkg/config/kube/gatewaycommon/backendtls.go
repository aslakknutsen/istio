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
	"cmp"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/maps"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
)

// AncestorBackend tracks the relationship between a backend (Service) and the Gateway
// that references it via a route. Used for BackendTLSPolicy status reporting.
type AncestorBackend struct {
	Gateway types.NamespacedName
	Backend types.NamespacedName
	Source  TypedResource
}

func (a AncestorBackend) ResourceName() string {
	return a.Source.String() + "/" + a.Gateway.String() + "/" + a.Backend.String()
}

func (a AncestorBackend) Equals(other AncestorBackend) bool {
	return a.Gateway == other.Gateway && a.Backend == other.Backend && a.Source == other.Source
}

// ResolvedBackendTLSTarget describes the backend target for a resolved TLS policy.
type ResolvedBackendTLSTarget struct {
	// Namespace is the namespace of the backend.
	Namespace string
	// Hostname is the fully-qualified service hostname (expanded with domainSuffix).
	Hostname string
	// Port is the optional port, nil when not specified.
	Port *uint32
	// Kind is the resource kind of the target: "Service" or "InferencePool".
	Kind string
}

// ResolvedBackendTLS is the neutral representation of a resolved BackendTLSPolicy entry.
// One ResolvedBackendTLS is produced per (policy target × gateway) combination.
// Proxy-specific packages translate this into their own policy representations.
type ResolvedBackendTLS struct {
	// Key uniquely identifies this resolved entry.
	Key string
	// Gateway is the Gateway that references the backend.
	Gateway types.NamespacedName
	// Target describes the backend service this TLS policy applies to.
	Target ResolvedBackendTLSTarget
	// CACert is the PEM-encoded CA certificate bundle. nil means "use system CA".
	CACert []byte
	// Hostname is the TLS SNI / expected hostname.
	Hostname string
	// SANs are the expected Subject Alternative Names for the backend certificate.
	SANs []string
	// ClientCert is the PEM-encoded client certificate for mTLS to the backend. nil = no mTLS.
	ClientCert []byte
	// ClientKey is the PEM-encoded private key paired with ClientCert.
	ClientKey []byte
	// Invalid is true when certificate resolution failed. Proxy-specific callers
	// should treat this as an error (e.g. send a sentinel cert or reject the policy).
	Invalid bool
}

func (r ResolvedBackendTLS) ResourceName() string { return r.Key }

func (r ResolvedBackendTLS) Equals(other ResolvedBackendTLS) bool {
	return r.Key == other.Key &&
		r.Gateway == other.Gateway &&
		r.Target == other.Target &&
		string(r.CACert) == string(other.CACert) &&
		r.Hostname == other.Hostname &&
		slices.Equal(r.SANs, other.SANs) &&
		string(r.ClientCert) == string(other.ClientCert) &&
		string(r.ClientKey) == string(other.ClientKey) &&
		r.Invalid == other.Invalid
}

// BackendTLSPolicyInputs holds all collections needed by BackendTLSPolicyCollection.
type BackendTLSPolicyInputs struct {
	BackendTLSPolicies krt.Collection[*gatewayv1.BackendTLSPolicy]
	ConfigMaps         krt.Collection[*corev1.ConfigMap]
	Secrets            krt.Collection[*corev1.Secret]
	Services           krt.Collection[*corev1.Service]
	Gateways           krt.Collection[*gatewayv1.Gateway]
	// AncestorBackends maps backend targets to the gateways that reference them (via routes).
	AncestorBackends krt.Collection[*AncestorBackend]
	ControllerName   string
	DomainSuffix     string
}

// BackendTLSPolicyCollection translates BackendTLSPolicy resources into neutral
// ResolvedBackendTLS values and writes status back to each policy.
func BackendTLSPolicyCollection(
	inputs BackendTLSPolicyInputs,
	opts krt.OptionsBuilder,
) (krt.StatusCollection[*gatewayv1.BackendTLSPolicy, gatewayv1.PolicyStatus], krt.Collection[ResolvedBackendTLS]) {
	backendTLSTargetIndex := krt.NewIndex(inputs.BackendTLSPolicies, "btls-targets", func(o *gatewayv1.BackendTLSPolicy) []string {
		return slices.Map(o.Spec.TargetRefs, func(e gatewayv1.LocalPolicyTargetReferenceWithSectionName) string {
			return fmt.Sprintf("%s/%s/%s", o.Namespace, e.Kind, e.Name)
		})
	})

	ancestorIndex := krt.NewIndex(inputs.AncestorBackends, "btls-ancestors", func(o *AncestorBackend) []string {
		return []string{o.Backend.String()}
	})

	return krt.NewStatusManyCollection(inputs.BackendTLSPolicies, func(krtctx krt.HandlerContext, btls *gatewayv1.BackendTLSPolicy) (
		*gatewayv1.PolicyStatus,
		[]ResolvedBackendTLS,
	) {
		return resolveBackendTLSPolicy(krtctx, inputs, backendTLSTargetIndex, ancestorIndex, btls)
	}, opts.WithName("BackendTLSPolicies")...)
}

func resolveBackendTLSPolicy(
	krtctx krt.HandlerContext,
	inputs BackendTLSPolicyInputs,
	backendTLSTargetIndex krt.Index[string, *gatewayv1.BackendTLSPolicy],
	ancestorIndex krt.Index[string, *AncestorBackend],
	btls *gatewayv1.BackendTLSPolicy,
) (*gatewayv1.PolicyStatus, []ResolvedBackendTLS) {
	var resolved []ResolvedBackendTLS
	status := btls.Status.DeepCopy()

	conds := map[string]*Condition{
		string(gatewayv1.PolicyConditionAccepted): {
			Reason:  string(gatewayv1.PolicyReasonAccepted),
			Message: "Configuration is valid",
		},
		string(gatewayv1.BackendTLSPolicyConditionResolvedRefs): {
			Reason:  string(gatewayv1.BackendTLSPolicyReasonResolvedRefs),
			Message: "Configuration is valid",
		},
	}

	caCert, certErr := btlsGetCACert(krtctx, inputs.ConfigMaps, btls, conds)
	invalid := certErr != nil

	sans := slices.MapFilter(btls.Spec.Validation.SubjectAltNames, func(e gatewayv1.SubjectAltName) *string {
		switch e.Type {
		case gatewayv1.HostnameSubjectAltNameType:
			return ptr.Of(string(e.Hostname))
		case gatewayv1.URISubjectAltNameType:
			return ptr.Of(string(e.URI))
		}
		return nil
	})

	uniqueGateways := sets.New[types.NamespacedName]()
	for _, target := range btls.Spec.TargetRefs {
		tgtKey := fmt.Sprintf("%s/%s/%s", btls.Namespace, target.Kind, target.Name)
		tgtNN := types.NamespacedName{
			Name:      string(target.Name),
			Namespace: btls.Namespace,
		}

		ancestors := ancestorIndex.Fetch(krtctx, tgtNN.String())
		for _, a := range ancestors {
			uniqueGateways.Insert(a.Gateway)
		}

		allPoliciesForTarget := backendTLSTargetIndex.Fetch(krtctx, tgtKey)
		if err := btlsCheckConflicted(btls, target, allPoliciesForTarget); err != nil {
			conds[string(gatewayv1.PolicyConditionAccepted)].Error = &ConfigError{
				Reason:  string(gatewayv1.PolicyReasonConflicted),
				Message: err.Error(),
			}
			continue
		}

		serviceHostname := fmt.Sprintf("%s.%s.svc.%s", target.Name, btls.Namespace, inputs.DomainSuffix)
		targetKind := string(target.Kind)
		var port *uint32

		switch targetKind {
		case gvk.Service.Kind:
			if sn := target.SectionName; sn != nil {
				// Named port — look up actual port number.
				svc := ptr.Flatten(krt.FetchOne(krtctx, inputs.Services, krt.FilterObjectName(tgtNN)))
				if svc != nil {
					for _, p := range svc.Spec.Ports {
						if p.Name == string(*sn) {
							v := uint32(p.Port) //nolint:gosec
							port = &v
							break
						}
					}
				}
			}
		case gvk.InferencePool.Kind:
			if sn := (*string)(target.SectionName); sn != nil {
				var parsed int
				fmt.Sscanf(*sn, "%d", &parsed)
				if parsed > 0 {
					v := uint32(parsed) //nolint:gosec
					port = &v
				}
			}
		default:
			log.Warnf("unsupported BackendTLSPolicy target kind %q", target.Kind)
			continue
		}

		// Fetch client cert from gateway if only a single gateway references this backend.
		var clientCert, clientKey []byte
		if uniqueGateways.Len() == 1 {
			gwNN := uniqueGateways.UnsortedList()[0]
			gtw := ptr.Flatten(krt.FetchOne(krtctx, inputs.Gateways, krt.FilterObjectName(gwNN)))
			if gtw != nil && gtw.Spec.TLS != nil && gtw.Spec.TLS.Backend != nil && gtw.Spec.TLS.Backend.ClientCertificateRef != nil {
				clientRef := gtw.Spec.TLS.Backend.ClientCertificateRef
				if clientRef.Namespace == nil && (clientRef.Kind == nil || *clientRef.Kind == "Secret") {
					nn := types.NamespacedName{Namespace: gtw.Namespace, Name: string(clientRef.Name)}
					scrt := ptr.Flatten(krt.FetchOne(krtctx, inputs.Secrets, krt.FilterObjectName(nn)))
					if scrt != nil {
						clientCert = scrt.Data[corev1.TLSCertKey]
						clientKey = scrt.Data[corev1.TLSPrivateKeyKey]
					}
				}
			}
		}

		policyKey := btls.Namespace + "/" + btls.Name + ":backend-tls:" + btls.Namespace + "/" + serviceHostname

		entry := ResolvedBackendTLS{
			Key: policyKey,
			Target: ResolvedBackendTLSTarget{
				Namespace: btls.Namespace,
				Hostname:  serviceHostname,
				Port:      port,
				Kind:      targetKind,
			},
			CACert:     caCert,
			Hostname:   string(btls.Spec.Validation.Hostname),
			SANs:       sans,
			ClientCert: clientCert,
			ClientKey:  clientKey,
			Invalid:    invalid,
		}

		gatewayList := uniqueGateways.UnsortedList()
		if len(gatewayList) > 0 {
			for _, gw := range gatewayList {
				r := entry
				r.Key = policyKey + "/" + gw.String()
				r.Gateway = gw
				resolved = append(resolved, r)
			}
		} else {
			resolved = append(resolved, entry)
		}
	}

	// Build ancestor status per gateway.
	ancestorStatuses := make([]gatewayv1.PolicyAncestorStatus, 0, uniqueGateways.Len())
	for gw := range uniqueGateways {
		pr := gatewayv1.ParentReference{
			Group: ptr.Of(gatewayv1.Group(gvk.KubernetesGateway.Group)),
			Kind:  ptr.Of(gatewayv1.Kind(gvk.KubernetesGateway.Kind)),
			Name:  gatewayv1.ObjectName(gw.Name),
		}
		ancestorStatuses = append(ancestorStatuses, btlsSetAncestorStatus(
			pr, btls.Generation, conds, gatewayv1.GatewayController(inputs.ControllerName),
		))
	}
	status.Ancestors = btlsMergeAncestors(inputs.ControllerName, status.Ancestors, ancestorStatuses)
	return status, resolved
}

// btlsGetCACert fetches CA certificate data from ConfigMap references or handles WellKnownCACertificates.
func btlsGetCACert(
	krtctx krt.HandlerContext,
	cfgmaps krt.Collection[*corev1.ConfigMap],
	btls *gatewayv1.BackendTLSPolicy,
	conds map[string]*Condition,
) ([]byte, error) {
	validation := btls.Spec.Validation
	if wk := validation.WellKnownCACertificates; wk != nil {
		switch kind := *wk; kind {
		case gatewayv1.WellKnownCACertificatesSystem:
			return nil, nil
		default:
			conds[string(gatewayv1.PolicyConditionAccepted)].Error = &ConfigError{
				Reason:  string(gatewayv1.PolicyReasonInvalid),
				Message: fmt.Sprintf("Unknown wellKnownCACertificates: %v", *wk),
			}
			return nil, fmt.Errorf("unknown wellKnownCACertificates: %v", *wk)
		}
	}

	if len(validation.CACertificateRefs) == 0 {
		return nil, fmt.Errorf("no CACertificateRefs specified")
	}

	var sb strings.Builder
	for _, ref := range validation.CACertificateRefs {
		if ref.Group != "" || ref.Kind != "ConfigMap" {
			conds[string(gatewayv1.BackendTLSPolicyConditionResolvedRefs)].Error = &ConfigError{
				Reason:  string(gatewayv1.BackendTLSPolicyReasonInvalidKind),
				Message: "Certificate reference invalid: " + string(ref.Kind),
			}
			return nil, fmt.Errorf("invalid certificate reference kind: %v", ref.Kind)
		}
		nn := types.NamespacedName{
			Name:      string(ref.Name),
			Namespace: btls.Namespace,
		}
		cfgmap := krt.FetchOne(krtctx, cfgmaps, krt.FilterObjectName(nn))
		if cfgmap == nil {
			conds[string(gatewayv1.BackendTLSPolicyConditionResolvedRefs)].Error = &ConfigError{
				Reason:  string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef),
				Message: "Certificate reference not found",
			}
			return nil, fmt.Errorf("certificate reference not found: %v", nn)
		}
		cm := ptr.Flatten(cfgmap)
		caCert, ok := cm.Data["ca.crt"]
		if !ok {
			conds[string(gatewayv1.BackendTLSPolicyConditionResolvedRefs)].Error = &ConfigError{
				Reason:  string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef),
				Message: "ConfigMap missing ca.crt key",
			}
			return nil, fmt.Errorf("ConfigMap %v missing ca.crt key", nn)
		}
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(caCert)
	}
	return []byte(sb.String()), nil
}

// btlsCheckConflicted returns an error if a higher-priority policy already targets the same backend.
func btlsCheckConflicted(
	btls *gatewayv1.BackendTLSPolicy,
	target gatewayv1.LocalPolicyTargetReferenceWithSectionName,
	allPolicies []*gatewayv1.BackendTLSPolicy,
) error {
	for _, m := range allPolicies {
		if m.UID == btls.UID {
			continue
		}
		hasMatchingTarget := false
		for _, t := range m.Spec.TargetRefs {
			if btlsTargetEqual(target, t) {
				hasMatchingTarget = true
				break
			}
		}
		if !hasMatchingTarget {
			continue
		}
		if btlsComparePolicy(m, btls) {
			return fmt.Errorf("policy %v matches the same target but with higher priority", m.Name)
		}
	}
	return nil
}

// btlsComparePolicy returns true if a has higher priority than b.
func btlsComparePolicy(a, b metav1.Object) bool {
	ts := a.GetCreationTimestamp().Compare(b.GetCreationTimestamp().Time)
	if ts < 0 {
		return true
	}
	if ts > 0 {
		return false
	}
	ns := cmp.Compare(a.GetNamespace(), b.GetNamespace())
	if ns < 0 {
		return true
	}
	if ns > 0 {
		return false
	}
	return a.GetName() < b.GetName()
}

func btlsTargetEqual(a, b gatewayv1.LocalPolicyTargetReferenceWithSectionName) bool {
	return a.Group == b.Group &&
		a.Kind == b.Kind &&
		a.Name == b.Name &&
		ptr.Equal(a.SectionName, b.SectionName)
}

// btlsSetAncestorStatus builds a PolicyAncestorStatus for a given gateway.
func btlsSetAncestorStatus(
	pr gatewayv1.ParentReference,
	generation int64,
	conds map[string]*Condition,
	controller gatewayv1.GatewayController,
) gatewayv1.PolicyAncestorStatus {
	conditions := make([]metav1.Condition, 0, len(conds))
	for _, k := range slices.Sort(maps.Keys(conds)) {
		c := conds[k]
		if c.Error != nil {
			conditions = append(conditions, metav1.Condition{
				Type:               k,
				Status:             metav1.ConditionFalse,
				ObservedGeneration: generation,
				LastTransitionTime: metav1.Now(),
				Reason:             c.Error.Reason,
				Message:            c.Error.Message,
			})
		} else {
			conditions = append(conditions, metav1.Condition{
				Type:               k,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: generation,
				LastTransitionTime: metav1.Now(),
				Reason:             c.Reason,
				Message:            c.Message,
			})
		}
	}
	return gatewayv1.PolicyAncestorStatus{
		AncestorRef:    pr,
		ControllerName: controller,
		Conditions:     conditions,
	}
}

// btlsMergeAncestors merges new ancestor statuses into existing ones, preserving entries
// from other controllers.
func btlsMergeAncestors(
	controllerName string,
	existing []gatewayv1.PolicyAncestorStatus,
	newStatuses []gatewayv1.PolicyAncestorStatus,
) []gatewayv1.PolicyAncestorStatus {
	controller := gatewayv1.GatewayController(controllerName)
	result := make([]gatewayv1.PolicyAncestorStatus, 0, len(existing)+len(newStatuses))
	for _, e := range existing {
		if e.ControllerName != controller {
			result = append(result, e)
		}
	}
	result = append(result, newStatuses...)
	return result
}

// BuildAncestorBackends extracts backend→gateway relationships from routes.
// This is used to determine which gateways reference a given backend Service,
// which is needed for BackendTLSPolicy status reporting.
func BuildAncestorBackends(
	httpRoutes krt.Collection[*gatewayv1.HTTPRoute],
	grpcRoutes krt.Collection[*gatewayv1.GRPCRoute],
	opts krt.OptionsBuilder,
) krt.Collection[*AncestorBackend] {
	httpAncestors := krt.NewManyCollection(httpRoutes, func(_ krt.HandlerContext, obj *gatewayv1.HTTPRoute) []*AncestorBackend {
		source := TypedResource{
			Kind: gvk.HTTPRoute,
			Name: types.NamespacedName{Namespace: obj.Namespace, Name: obj.Name},
		}
		gateways := extractGatewayRefs(obj.Namespace, obj.Spec.ParentRefs)
		backends := sets.New[types.NamespacedName]()
		for _, rule := range obj.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				if ref.Kind != nil && *ref.Kind != "Service" {
					continue
				}
				ns := obj.Namespace
				if ref.Namespace != nil {
					ns = string(*ref.Namespace)
				}
				backends.Insert(types.NamespacedName{Namespace: ns, Name: string(ref.Name)})
			}
		}
		return buildAncestorPairs(gateways, backends, source)
	}, opts.WithName("HTTPRouteAncestorBackends")...)

	grpcAncestors := krt.NewManyCollection(grpcRoutes, func(_ krt.HandlerContext, obj *gatewayv1.GRPCRoute) []*AncestorBackend {
		source := TypedResource{
			Kind: gvk.HTTPRoute,
			Name: types.NamespacedName{Namespace: obj.Namespace, Name: obj.Name},
		}
		gateways := extractGatewayRefs(obj.Namespace, obj.Spec.ParentRefs)
		backends := sets.New[types.NamespacedName]()
		for _, rule := range obj.Spec.Rules {
			for _, ref := range rule.BackendRefs {
				if ref.Kind != nil && *ref.Kind != "Service" {
					continue
				}
				ns := obj.Namespace
				if ref.Namespace != nil {
					ns = string(*ref.Namespace)
				}
				backends.Insert(types.NamespacedName{Namespace: ns, Name: string(ref.Name)})
			}
		}
		return buildAncestorPairs(gateways, backends, source)
	}, opts.WithName("GRPCRouteAncestorBackends")...)

	return krt.JoinCollection([]krt.Collection[*AncestorBackend]{httpAncestors, grpcAncestors},
		opts.WithName("AllAncestorBackends")...)
}

func extractGatewayRefs(defaultNS string, refs []gatewayv1.ParentReference) sets.Set[types.NamespacedName] {
	gateways := sets.New[types.NamespacedName]()
	for _, r := range refs {
		if r.Group != nil && *r.Group != gatewayv1.GroupName {
			continue
		}
		if r.Kind != nil && *r.Kind != "Gateway" {
			continue
		}
		ns := defaultNS
		if r.Namespace != nil {
			ns = string(*r.Namespace)
		}
		gateways.Insert(types.NamespacedName{Namespace: ns, Name: string(r.Name)})
	}
	return gateways
}

func buildAncestorPairs(gateways, backends sets.Set[types.NamespacedName], source TypedResource) []*AncestorBackend {
	result := make([]*AncestorBackend, 0, gateways.Len()*backends.Len())
	for gw := range gateways {
		for be := range backends {
			result = append(result, &AncestorBackend{Source: source, Gateway: gw, Backend: be})
		}
	}
	return result
}
