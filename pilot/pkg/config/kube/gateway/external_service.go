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

package gateway

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayx "sigs.k8s.io/gateway-api/apisx/v1alpha1"

	"istio.io/istio/pilot/pkg/features"
	kubegw "istio.io/istio/pkg/config/gateway/kube"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
)

// resolveExtAuthzForHTTPRoute finds all XGatewayExternalService resources of type ExtAuth
// that target the given HTTPRoute, optionally filtered by sectionName (rule name).
// Results are sorted by priority (lower values first).
func resolveExtAuthzForHTTPRoute(
	ctx RouteContext,
	httpRoute *gatewayv1.HTTPRoute,
	ruleName string,
) []kubegw.ExtAuthzRouteRuleConfig {
	allExtSvcs := krt.Fetch(ctx.Krt, ctx.GatewayExternalServices)
	var configs []kubegw.ExtAuthzRouteRuleConfig

	for _, extSvc := range allExtSvcs {
		if extSvc.Spec.Type != gatewayx.ExternalServiceTypeExtAuth {
			continue
		}

		ref := extSvc.Spec.TargetRef
		// Must target HTTPRoute in the gateway.networking.k8s.io group
		if string(ref.Group) != gatewayv1.GroupName {
			continue
		}
		if string(ref.Kind) != "HTTPRoute" {
			continue
		}
		// Must be in the same namespace and match the HTTPRoute name
		if extSvc.Namespace != httpRoute.Namespace {
			continue
		}
		if string(ref.Name) != httpRoute.Name {
			continue
		}
		// If sectionName is specified, it must match the rule name
		if ref.SectionName != nil && string(*ref.SectionName) != ruleName {
			continue
		}

		var timeout time.Duration
		if extSvc.Spec.Timeout != nil {
			d, err := time.ParseDuration(string(*extSvc.Spec.Timeout))
			if err == nil {
				timeout = d
			}
		}

		var priority int32
		if extSvc.Spec.Priority != nil {
			priority = *extSvc.Spec.Priority
		}

		configs = append(configs, kubegw.ExtAuthzRouteRuleConfig{
			FilterName: kubegw.ExtAuthzFilterName(extSvc.Namespace, extSvc.Name),
			Host:       string(extSvc.Spec.Endpoint.Host),
			Port:       int(extSvc.Spec.Endpoint.Port),
			Protocol:   string(extSvc.Spec.Endpoint.Protocol),
			Timeout:    timeout,
			Priority:   priority,
			Data:       extSvc.Spec.Data,
		})
	}

	// Sort by priority (lower first), then by host for deterministic ordering
	slices.SortFunc(configs, func(a, b kubegw.ExtAuthzRouteRuleConfig) int {
		if c := cmp.Compare(a.Priority, b.Priority); c != 0 {
			return c
		}
		return cmp.Compare(a.Host, b.Host)
	})

	return configs
}

// GatewayExternalServiceStatusCollection builds a status collection for XGatewayExternalService resources.
// It validates that the targetRef points to an existing Gateway or HTTPRoute and sets the Accepted condition.
func GatewayExternalServiceStatusCollection(
	externalServices krt.Collection[*gatewayx.XGatewayExternalService],
	gateways krt.Collection[*gatewayv1.Gateway],
	httpRoutes krt.Collection[*gatewayv1.HTTPRoute],
	opts krt.OptionsBuilder,
) krt.StatusCollection[*gatewayx.XGatewayExternalService, gatewayx.PolicyStatus] {
	// We only need the status collection, not the output; use a dummy type.
	statusCol, _ := krt.NewStatusManyCollection(externalServices, func(ctx krt.HandlerContext, i *gatewayx.XGatewayExternalService) (
		*gatewayx.PolicyStatus,
		[]struct{},
	) {
		status := i.Status.DeepCopy()
		ref := i.Spec.TargetRef

		conds := map[string]*condition{
			string(gatewayv1.PolicyConditionAccepted): {
				reason:  string(gatewayv1.PolicyReasonAccepted),
				message: "Configuration is valid",
			},
		}

		// Validate the targetRef group
		if string(ref.Group) != gatewayv1.GroupName {
			conds[string(gatewayv1.PolicyConditionAccepted)].error = &ConfigError{
				Reason:  string(gatewayv1.PolicyReasonInvalid),
				Message: fmt.Sprintf("unsupported targetRef group: %q", ref.Group),
			}
		} else {
			// Validate the target exists
			switch string(ref.Kind) {
			case "Gateway":
				allGateways := krt.Fetch(ctx, gateways)
				found := false
				for _, gw := range allGateways {
					if gw.Namespace == i.Namespace && gw.Name == string(ref.Name) {
						found = true
						break
					}
				}
				if !found {
					conds[string(gatewayv1.PolicyConditionAccepted)].error = &ConfigError{
						Reason:  string(gatewayv1.PolicyReasonTargetNotFound),
						Message: fmt.Sprintf("Gateway %q not found", ref.Name),
					}
				}
			case "HTTPRoute":
				allRoutes := krt.Fetch(ctx, httpRoutes)
				found := false
				for _, hr := range allRoutes {
					if hr.Namespace == i.Namespace && hr.Name == string(ref.Name) {
						found = true
						break
					}
				}
				if !found {
					conds[string(gatewayv1.PolicyConditionAccepted)].error = &ConfigError{
						Reason:  string(gatewayv1.PolicyReasonTargetNotFound),
						Message: fmt.Sprintf("HTTPRoute %q not found", ref.Name),
					}
				}
			default:
				conds[string(gatewayv1.PolicyConditionAccepted)].error = &ConfigError{
					Reason:  string(gatewayv1.PolicyReasonInvalid),
					Message: fmt.Sprintf("unsupported targetRef kind: %q", ref.Kind),
				}
			}
		}

		// Build the ancestor status using the targetRef as the ancestor
		pr := gatewayv1.ParentReference{
			Group:       ptr.Of(ref.Group),
			Kind:        ptr.Of(ref.Kind),
			Name:        gatewayv1.ObjectName(ref.Name),
			SectionName: ref.SectionName,
		}
		ancestor := setAncestorStatus(pr, status, i.Generation, conds, gatewayv1.GatewayController(features.ManagedGatewayController))
		status.Ancestors = mergeAncestors(status.Ancestors, []gatewayv1.PolicyAncestorStatus{ancestor})
		return status, nil
	}, opts.WithName("GatewayExternalService")...)

	return statusCol
}
