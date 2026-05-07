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
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/log"
)

// validateHTTPRouteBackends checks Service / InferencePool backend refs for status.Conditions
// (ResolvedRefs). Data-plane translation happens in collectRoutes / HTTPRouteRuleToGwRoute;
// this must stay aligned with resolveBackend supported kinds.
func validateHTTPRouteBackends(ctx gatewaycommon.RouteContext, hr *gatewayv1.HTTPRoute) *gatewaycommon.Condition {
	for _, rule := range hr.Spec.Rules {
		for _, b := range rule.BackendRefs {
			if c := validateGatewayBackendRef(
				ctx,
				b.Group,
				b.Kind,
				b.Name,
				b.Namespace,
				b.Port,
				hr.Namespace,
				gvk.HTTPRoute,
			); c != nil {
				return c
			}
		}
	}
	return nil
}

func validateGRPCRouteBackends(ctx gatewaycommon.RouteContext, gr *gatewayv1.GRPCRoute) *gatewaycommon.Condition {
	for _, rule := range gr.Spec.Rules {
		for _, b := range rule.BackendRefs {
			if c := validateGatewayBackendRef(
				ctx,
				b.Group,
				b.Kind,
				b.Name,
				b.Namespace,
				b.Port,
				gr.Namespace,
				gvk.GRPCRoute,
			); c != nil {
				return c
			}
		}
	}
	return nil
}

func validateGatewayBackendRef(
	ctx gatewaycommon.RouteContext,
	group *gatewayv1.Group,
	kind *gatewayv1.Kind,
	name gatewayv1.ObjectName,
	namespace *gatewayv1.Namespace,
	port *gatewayv1.PortNumber,
	routeNS string,
	routeKind config.GroupVersionKind,
) *gatewaycommon.Condition {
	ref := gatewaycommon.NormalizeReference(group, kind, gvk.Service)

	if namespace != nil && string(*namespace) != routeNS {
		if !ctx.Grants.BackendAllowed(ctx.Krt, routeKind, ref, name, gatewayv1.Namespace(*namespace), routeNS) {
			msg := fmt.Sprintf(
				"backendRef %v/%v not accessible to a %s in namespace %q (missing a ReferenceGrant?)",
				name, *namespace, routeKind.Kind, routeNS,
			)
			log.Debug(msg)
			return &gatewaycommon.Condition{
				Error: &gatewaycommon.ConfigError{
					Reason:  gatewaycommon.ConfigErrorReason(gatewayv1.RouteReasonRefNotPermitted),
					Message: msg,
				},
			}
		}
	}

	ns := routeNS
	if namespace != nil {
		ns = string(*namespace)
	}

	switch {
	case ref.Group == gvk.InferencePool.Group && ref.Kind == gvk.InferencePool.Kind:
		if strings.Contains(string(name), ".") {
			msg := fmt.Sprintf(
				"service name invalid; the name of the InferencePool must be used, not the hostname. Got %q",
				name,
			)
			log.Debug(msg)
			return &gatewaycommon.Condition{
				Error: &gatewaycommon.ConfigError{
					Reason:  gatewaycommon.ConfigErrorReason(gatewayv1.RouteReasonUnsupportedValue),
					Message: msg,
				},
			}
		}
		key := ns + "/" + string(name)
		if !krt.ResourceExists(ctx.Krt, ctx.InferencePools, key) {
			msg := fmt.Sprintf("backendRef %s not found", key)
			log.Debug(msg)
			return &gatewaycommon.Condition{
				Error: &gatewaycommon.ConfigError{
					Reason:  gatewaycommon.ConfigErrorReason(gatewayv1.RouteReasonBackendNotFound),
					Message: msg,
				},
			}
		}
		return nil

	case ref.Group == gvk.Service.Group && ref.Kind == gvk.Service.Kind:
		if strings.Contains(string(name), ".") {
			msg := fmt.Sprintf(
				"service name invalid; the name of the Service must be used, not the hostname. Got %q",
				name,
			)
			log.Debug(msg)
			return &gatewaycommon.Condition{
				Error: &gatewaycommon.ConfigError{
					Reason:  gatewaycommon.ConfigErrorReason(gatewayv1.RouteReasonUnsupportedValue),
					Message: msg,
				},
			}
		}
		hostname := fmt.Sprintf("%s.%s.svc.%s", name, ns, ctx.DomainSuffix)
		key := ns + "/" + string(name)
		if !krt.ResourceExists(ctx.Krt, ctx.Services, key) {
			msg := fmt.Sprintf("backend(%s) not found", hostname)
			log.Debug(msg)
			return &gatewaycommon.Condition{
				Error: &gatewaycommon.ConfigError{
					Reason:  gatewaycommon.ConfigErrorReason(gatewayv1.RouteReasonBackendNotFound),
					Message: msg,
				},
			}
		}
		if port == nil {
			msg := fmt.Sprintf("port is required in backendRef when referencing service %q", hostname)
			log.Debug(msg)
			return &gatewaycommon.Condition{
				Error: &gatewaycommon.ConfigError{
					Reason:  gatewaycommon.ConfigErrorReason(gatewayv1.RouteReasonUnsupportedValue),
					Message: "port is required in backendRef",
				},
			}
		}
		return nil

	default:
		msg := fmt.Sprintf("referencing unsupported backendRef: group %q kind %q", ref.Group, ref.Kind)
		log.Debug(msg)
		return &gatewaycommon.Condition{
			Error: &gatewaycommon.ConfigError{
				Reason:  gatewaycommon.ConfigErrorReason(gatewayv1.RouteReasonInvalidKind),
				Message: msg,
			},
		}
	}
}
