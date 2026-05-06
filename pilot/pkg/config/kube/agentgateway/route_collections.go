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

// Crediting the kgateway authors for the patterns used in this file, as well as some of the code

package agentgateway

import (
	"iter"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayalpha "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	"istio.io/istio/pilot/pkg/status"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/revisions"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/protomarshal"
)

// AgwRouteCollection creates the collection of translated Routes
func AgwRouteCollection(
	queue *status.StatusCollections,
	httpRouteCol krt.Collection[*gatewayv1.HTTPRoute],
	grpcRouteCol krt.Collection[*gatewayv1.GRPCRoute],
	tcpRouteCol krt.Collection[*gatewayalpha.TCPRoute],
	tlsRouteCol krt.Collection[*gatewayv1.TLSRoute],
	inputs gatewaycommon.RouteContextInputs,
	tagWatcher krt.RecomputeProtected[revisions.TagWatcher],
	krtopts krt.OptionsBuilder,
) (krt.Collection[AgwResource], krt.Collection[*gatewaycommon.RouteAttachment]) {
	// Create httpRoutes collection
	httpRouteStatus, httpRoutes := createRouteCollection(httpRouteCol, inputs, krtopts, "HTTPRoutes",
		func(ctx gatewaycommon.RouteContext, obj *gatewayv1.HTTPRoute) (gatewaycommon.RouteContext, iter.Seq2[AgwRoute, *gatewaycommon.Condition]) {
			route := obj.Spec
			return ctx, func(yield func(AgwRoute, *gatewaycommon.Condition) bool) {
				for n, r := range route.Rules {
					// split the rule to make sure each rule has up to one match
					matches := slices.Reference(r.Matches)
					if len(matches) == 0 {
						matches = append(matches, nil)
					}
					for idx, m := range matches {
						if m != nil {
							r.Matches = []gatewayv1.HTTPRouteMatch{*m}
						}
						res, err := ConvertHTTPRouteToAgw(ctx, r, obj, n, idx)
						if !yield(AgwRoute{Route: res}, err) {
							return
						}
					}
				}
			}
		}, func(status gatewayv1.RouteStatus) gatewayv1.HTTPRouteStatus {
			return gatewayv1.HTTPRouteStatus{RouteStatus: status}
		})
	status.RegisterStatus(queue, httpRouteStatus, GetStatus, tagWatcher.AccessUnprotected())

	// Create gRPCRoutes collection
	grpcRouteStatus, grpcRoutes := createRouteCollection(grpcRouteCol, inputs, krtopts, "GRPCRoutes",
		func(ctx gatewaycommon.RouteContext, obj *gatewayv1.GRPCRoute) (gatewaycommon.RouteContext, iter.Seq2[AgwRoute, *gatewaycommon.Condition]) {
			route := obj.Spec
			return ctx, func(yield func(AgwRoute, *gatewaycommon.Condition) bool) {
				for n, r := range route.Rules {
					res, err := ConvertGRPCRouteToAgw(ctx, r, obj, n)
					if !yield(AgwRoute{Route: res}, err) {
						return
					}
				}
			}
		}, func(status gatewayv1.RouteStatus) gatewayv1.GRPCRouteStatus {
			return gatewayv1.GRPCRouteStatus{RouteStatus: status}
		})
	status.RegisterStatus(queue, grpcRouteStatus, GetStatus, tagWatcher.AccessUnprotected())

	// Create TCPRoutes collection
	tcpRouteStatus, tcpRoutes := createTCPRouteCollection(tcpRouteCol, inputs, krtopts, "TCPRoutes",
		func(ctx gatewaycommon.RouteContext, obj *gatewayalpha.TCPRoute) (gatewaycommon.RouteContext, iter.Seq2[AgwTCPRoute, *gatewaycommon.Condition]) {
			route := obj.Spec
			return ctx, func(yield func(AgwTCPRoute, *gatewaycommon.Condition) bool) {
				for n, r := range route.Rules {
					res, err := ConvertTCPRouteToAgw(ctx, r, obj, n)
					if !yield(AgwTCPRoute{TCPRoute: res}, err) {
						return
					}
				}
			}
		}, func(status gatewayv1.RouteStatus) gatewayalpha.TCPRouteStatus {
			return gatewayalpha.TCPRouteStatus{RouteStatus: status}
		})
	status.RegisterStatus(queue, tcpRouteStatus, GetStatus, tagWatcher.AccessUnprotected())

	// Create TLSRoutes collection
	tlsRouteStatus, tlsRoutes := createTCPRouteCollection(tlsRouteCol, inputs, krtopts, "TLSRoutes",
		func(ctx gatewaycommon.RouteContext, obj *gatewayv1.TLSRoute) (gatewaycommon.RouteContext, iter.Seq2[AgwTCPRoute, *gatewaycommon.Condition]) {
			route := obj.Spec
			return ctx, func(yield func(AgwTCPRoute, *gatewaycommon.Condition) bool) {
				for n, r := range route.Rules {
					res, err := ConvertTLSRouteToAgw(ctx, r, obj, n)
					if !yield(AgwTCPRoute{TCPRoute: res}, err) {
						return
					}
				}
			}
		}, func(status gatewayv1.RouteStatus) gatewayv1.TLSRouteStatus {
			return gatewayv1.TLSRouteStatus{RouteStatus: status}
		})
	status.RegisterStatus(queue, tlsRouteStatus, GetStatus, tagWatcher.AccessUnprotected())

	// Join all the route types into a single collection
	routes := krt.JoinCollection([]krt.Collection[AgwResource]{httpRoutes, grpcRoutes, tcpRoutes, tlsRoutes}, krtopts.WithName("ADPRoutes")...)

	routeAttachments := krt.JoinCollection([]krt.Collection[*gatewaycommon.RouteAttachment]{
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs, httpRouteCol, gvk.HTTPRoute, krtopts),
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs, grpcRouteCol, gvk.GRPCRoute, krtopts),
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs, tlsRouteCol, gvk.TLSRoute, krtopts),
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs, tcpRouteCol, gvk.TCPRoute, krtopts),
	})

	return routes, routeAttachments
}

// Simplified HTTP route collection function
func createRouteCollection[T controllers.Object, ST any](
	routeCol krt.Collection[T],
	inputs gatewaycommon.RouteContextInputs,
	krtopts krt.OptionsBuilder,
	collectionName string,
	translator func(ctx gatewaycommon.RouteContext, obj T) (gatewaycommon.RouteContext, iter.Seq2[AgwRoute, *gatewaycommon.Condition]),
	buildStatus func(status gatewayv1.RouteStatus) ST,
) (
	krt.StatusCollection[T, ST],
	krt.Collection[AgwResource],
) {
	return gatewaycommon.RouteStatusManyCollection(routeCol, inputs, krtopts, collectionName,
		translator,
		func(e AgwRoute, parent gatewaycommon.RouteParentReference) AgwResource {
			// safety: a shallow clone is ok because we only modify a top level field (Key)
			inner := protomarshal.ShallowClone(e.Route)
			_, name, _ := strings.Cut(parent.InternalName, "/")
			inner.ListenerKey = name
			if sec := string(parent.ParentSection); sec != "" {
				inner.Key = inner.GetKey() + "." + sec
			} else {
				inner.Key = inner.GetKey()
			}
			return ToResourceForGateway(parent.ParentGateway, ToAgwResource(AgwRoute{Route: inner}))
		},
		buildStatus,
	)
}

// ToResourceForGateway wraps an AgwResource with its associated Gateway.
func ToResourceForGateway(gw types.NamespacedName, resource any) AgwResource {
	return AgwResource{
		Resource: ToAgwResource(resource),
		Gateway:  gw,
	}
}

// Simplified TCP route collection function
func createTCPRouteCollection[T controllers.Object, ST any](
	routeCol krt.Collection[T],
	inputs gatewaycommon.RouteContextInputs,
	krtopts krt.OptionsBuilder,
	collectionName string,
	translator func(ctx gatewaycommon.RouteContext, obj T) (gatewaycommon.RouteContext, iter.Seq2[AgwTCPRoute, *gatewaycommon.Condition]),
	buildStatus func(status gatewayv1.RouteStatus) ST,
) (
	krt.StatusCollection[T, ST],
	krt.Collection[AgwResource],
) {
	return gatewaycommon.RouteStatusManyCollection(routeCol, inputs, krtopts, collectionName,
		translator,
		func(e AgwTCPRoute, parent gatewaycommon.RouteParentReference) AgwResource {
			inner := protomarshal.Clone(e.TCPRoute)
			_, name, _ := strings.Cut(parent.InternalName, "/")
			inner.ListenerKey = name
			if sec := string(parent.ParentSection); sec != "" {
				inner.Key = inner.GetKey() + "." + sec
			} else {
				inner.Key = inner.GetKey()
			}
			return ToResourceForGateway(parent.ParentGateway, ToAgwResource(AgwTCPRoute{TCPRoute: inner}))
		},
		buildStatus,
	)
}
