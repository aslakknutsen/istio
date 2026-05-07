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

package gwxds

import (
	"fmt"

	inferencev1 "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	gwxdsapi "istio.io/istio/pkg/gwxdsapi"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/ptr"
)

// GatewayListenerToGwListener translates a resolved gatewaycommon.GatewayListener
// into a proto Listener ready for xDS distribution.
//
// The GatewayListener already carries resolved TLS material (cert/key bytes),
// so no additional Kubernetes API access is required at this stage.
func GatewayListenerToGwListener(gl *gatewaycommon.GatewayListener) *gwxdsapi.Listener {
	if gl == nil {
		return nil
	}

	out := &gwxdsapi.Listener{
		Key:           gl.Name,
		Hostname:      gl.ParentInfo.OriginalHostname,
		Port:          uint32(gl.ParentInfo.Port),
		Protocol:      gatewayProtocolToGwProtocol(gl.ParentInfo.Protocol),
		AllowedRoutes: make([]string, 0, len(gl.ParentInfo.AllowedKinds)),
	}

	if gl.TLSInfo != nil {
		out.Tls = &gwxdsapi.TLSConfig{
			CertPem: gl.TLSInfo.Cert,
			KeyPem:  gl.TLSInfo.Key,
			CaPem:   gl.TLSInfo.CaCert,
		}
	}

	for _, rk := range gl.ParentInfo.AllowedKinds {
		out.AllowedRoutes = append(out.AllowedRoutes, fmt.Sprintf("%s/%s",
			groupOrDefault(rk), string(rk.Kind)))
	}

	return out
}

// BackendLookup provides the lookups needed to fully resolve backends during route translation.
type BackendLookup struct {
	// PoolByKey returns the InferencePool for a given "namespace/name" key, or nil if not found.
	PoolByKey func(key string) *inferencev1.InferencePool
	// TLSByHost returns the resolved BackendTLS policy for a given "namespace/expanded-hostname"
	// key, or nil. The hostname is the FQDN already expanded with DomainSuffix.
	TLSByHost func(key string) *gatewaycommon.ResolvedBackendTLS
	// DomainSuffix is used to expand service hostnames.
	DomainSuffix string
}

// HTTPRouteRuleToGwRoute translates a single HTTPRouteRule into a proto Route.
// lookup provides InferencePool and BackendTLS resolution; pass a zero BackendLookup
// when those features are not needed.
func HTTPRouteRuleToGwRoute(
	routeKey string,
	listenerKey string,
	routeNamespace string,
	hostnames []gatewayv1.Hostname,
	rule gatewayv1.HTTPRouteRule,
	lookup BackendLookup,
) *gwxdsapi.Route {
	out := &gwxdsapi.Route{
		Key:         routeKey,
		ListenerKey: listenerKey,
		Hostnames:   make([]string, 0, len(hostnames)),
		Matches:     make([]*gwxdsapi.RouteMatch, 0, len(rule.Matches)),
		Backends:    make([]*gwxdsapi.Backend, 0, len(rule.BackendRefs)),
	}

	for _, h := range hostnames {
		out.Hostnames = append(out.Hostnames, string(h))
	}

	for _, m := range rule.Matches {
		out.Matches = append(out.Matches, httpMatchToRouteMatch(m))
	}

	var redirect *gwxdsapi.RequestRedirect
	var hdrMod *gwxdsapi.RequestHeaderModifier
	for _, f := range rule.Filters {
		switch f.Type {
		case gatewayv1.HTTPRouteFilterRequestRedirect:
			if f.RequestRedirect != nil {
				redirect = httpRequestRedirectToProto(f.RequestRedirect)
			}
		case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
			if f.RequestHeaderModifier != nil {
				hdrMod = mergeRequestHeaderModifier(hdrMod, f.RequestHeaderModifier)
			}
		}
	}
	out.RequestRedirect = redirect
	out.RequestHeaderModifier = hdrMod

	hadBackendRefs := len(rule.BackendRefs) > 0
	resolvedBackends := 0
	for _, b := range rule.BackendRefs {
		backend := resolveBackend(b.BackendRef, routeNamespace, lookup)
		if backend != nil {
			out.Backends = append(out.Backends, backend)
			resolvedBackends++
		}
	}
	if hadBackendRefs && resolvedBackends == 0 && redirect == nil {
		out.InvalidBackendRef = true
	}

	return out
}

func mergeRequestHeaderModifier(
	dst *gwxdsapi.RequestHeaderModifier,
	src *gatewayv1.HTTPHeaderFilter,
) *gwxdsapi.RequestHeaderModifier {
	if src == nil {
		return dst
	}
	if dst == nil {
		dst = &gwxdsapi.RequestHeaderModifier{}
	}
	for _, h := range src.Set {
		dst.Set = append(dst.Set, &gwxdsapi.HeaderNameValue{
			Name:  string(h.Name),
			Value: h.Value,
		})
	}
	for _, h := range src.Add {
		dst.Add = append(dst.Add, &gwxdsapi.HeaderNameValue{
			Name:  string(h.Name),
			Value: h.Value,
		})
	}
	dst.Remove = append(dst.Remove, src.Remove...)
	return dst
}

func httpRequestRedirectToProto(r *gatewayv1.HTTPRequestRedirectFilter) *gwxdsapi.RequestRedirect {
	if r == nil {
		return nil
	}
	out := &gwxdsapi.RequestRedirect{}
	if r.Scheme != nil {
		out.Scheme = *r.Scheme
	}
	if r.Hostname != nil {
		out.Hostname = string(*r.Hostname)
	}
	if r.Port != nil {
		out.Port = uint32(*r.Port)
	}
	if r.StatusCode != nil {
		out.StatusCode = uint32(*r.StatusCode)
	}
	if r.Path != nil {
		switch r.Path.Type {
		case gatewayv1.FullPathHTTPPathModifier:
			if r.Path.ReplaceFullPath != nil {
				out.Path = *r.Path.ReplaceFullPath
			}
		case gatewayv1.PrefixMatchHTTPPathModifier:
			if r.Path.ReplacePrefixMatch != nil {
				out.Path = *r.Path.ReplacePrefixMatch
			}
		}
	}
	return out
}

// resolveBackend converts a single HTTPBackendRef into a proto Backend, handling both
// ordinary Service backends and InferencePool backends.
func resolveBackend(
	ref gatewayv1.BackendRef,
	routeNamespace string,
	lookup BackendLookup,
) *gwxdsapi.Backend {
	backendNS := routeNamespace
	if ref.Namespace != nil {
		backendNS = string(*ref.Namespace)
	}
	backendName := string(ref.Name)

	// Detect InferencePool backend refs.
	refGroup := ptr.OrEmpty((*gatewayv1.Group)(ref.Group))
	refKind := ptr.OrEmpty((*gatewayv1.Kind)(ref.Kind))
	isPool := refGroup == gatewayv1.Group(gvk.InferencePool.Group) &&
		refKind == gatewayv1.Kind(gvk.InferencePool.Kind)

	if isPool {
		return resolveInferencePoolBackend(backendName, backendNS, weightOrOne(ref.Weight), lookup)
	}

	// Ordinary Service backend.
	if ref.Port == nil {
		return nil
	}
	backend := &gwxdsapi.Backend{
		Host:   fmt.Sprintf("%s.%s.svc.%s", backendName, backendNS, lookup.DomainSuffix),
		Port:   uint32(*ref.Port),
		Weight: weightOrOne(ref.Weight),
	}
	// Omit DialPort: use backendRef port only (same as agentgateway; ClusterIP VIP + targetPort is wrong).
	if lookup.TLSByHost != nil {
		if tls := lookup.TLSByHost(backendNS + "/" + backend.Host); tls != nil {
			backend.Tls = resolvedTLSToBackendTLS(tls)
		}
	}
	return backend
}

// resolveInferencePoolBackend builds a proto Backend for an InferencePool backend ref.
func resolveInferencePoolBackend(
	poolName, poolNS string,
	weight uint32,
	lookup BackendLookup,
) *gwxdsapi.Backend {
	poolHost := fmt.Sprintf("%s.%s.inference.%s", poolName, poolNS, lookup.DomainSuffix)

	backend := &gwxdsapi.Backend{
		Host:   poolHost,
		Weight: weight,
	}

	if lookup.PoolByKey != nil {
		pool := lookup.PoolByKey(poolNS + "/" + poolName)
		if pool != nil && pool.Spec.EndpointPickerRef.Port != nil {
			eppHost := fmt.Sprintf("%s.%s.svc.%s",
				pool.Spec.EndpointPickerRef.Name, poolNS, lookup.DomainSuffix)
			eppPort := uint32(pool.Spec.EndpointPickerRef.Port.Number) //nolint:gosec
			failureMode := gwxdsapi.FailureMode_FAIL_CLOSED
			if pool.Spec.EndpointPickerRef.FailureMode == inferencev1.EndpointPickerFailOpen {
				failureMode = gwxdsapi.FailureMode_FAIL_OPEN
			}
			backend.InferencePool = &gwxdsapi.InferencePool{
				EndpointPicker: &gwxdsapi.BackendRef{Host: eppHost, Port: eppPort},
				FailureMode:    failureMode,
			}
		}
	}

	return backend
}

func resolvedTLSToBackendTLS(r *gatewaycommon.ResolvedBackendTLS) *gwxdsapi.BackendTLS {
	if r == nil {
		return nil
	}
	return &gwxdsapi.BackendTLS{
		CaCert:     r.CACert,
		Hostname:   r.Hostname,
		Sans:       r.SANs,
		ClientCert: r.ClientCert,
		ClientKey:  r.ClientKey,
		Invalid:    r.Invalid,
	}
}

func gatewayProtocolToGwProtocol(p gatewayv1.ProtocolType) gwxdsapi.Protocol {
	switch p {
	case gatewayv1.HTTPProtocolType:
		return gwxdsapi.Protocol_HTTP
	case gatewayv1.HTTPSProtocolType:
		return gwxdsapi.Protocol_HTTPS
	case gatewayv1.TLSProtocolType:
		return gwxdsapi.Protocol_TLS
	case gatewayv1.TCPProtocolType:
		return gwxdsapi.Protocol_TCP
	default:
		return gwxdsapi.Protocol_UNKNOWN
	}
}

func httpMatchToRouteMatch(m gatewayv1.HTTPRouteMatch) *gwxdsapi.RouteMatch {
	rm := &gwxdsapi.RouteMatch{
		Headers: make(map[string]string),
		Methods: make([]string, 0),
	}
	if m.Path != nil {
		switch *m.Path.Type {
		case gatewayv1.PathMatchExact:
			rm.PathExact = *m.Path.Value
		case gatewayv1.PathMatchRegularExpression:
			rm.PathRegex = *m.Path.Value
		default:
			// PathMatchPathPrefix is the default
			rm.PathPrefix = *m.Path.Value
		}
	}
	if m.Method != nil {
		rm.Methods = []string{string(*m.Method)}
	}
	if len(m.Headers) > 0 {
		for _, h := range m.Headers {
			rm.Headers[string(h.Name)] = h.Value
		}
	}
	return rm
}

func groupOrDefault(rk gatewayv1.RouteGroupKind) gatewayv1.Group {
	if rk.Group == nil {
		return gatewayv1.Group(gatewayv1.GroupVersion.Group)
	}
	return *rk.Group
}

func weightOrOne(w *int32) uint32 {
	if w == nil || *w == 0 {
		return 1
	}
	if *w < 0 {
		return 0
	}
	return uint32(*w)
}
