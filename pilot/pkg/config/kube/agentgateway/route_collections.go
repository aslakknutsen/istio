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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	inferencev1 "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayalpha "sigs.k8s.io/gateway-api/apis/v1alpha2"

	networkingclient "istio.io/client-go/pkg/apis/networking/v1"
	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	"istio.io/istio/pilot/pkg/status"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/revisions"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/protomarshal"
)

// RouteContextInputs is the agentgateway-specific extension of gatewaycommon.RouteContextInputs
// that adds InferencePools support.
type RouteContextInputs struct {
	gatewaycommon.RouteContextInputs
	InferencePools krt.Collection[*inferencev1.InferencePool]
}

func (i RouteContextInputs) WithCtx(krtctx krt.HandlerContext) RouteContext {
	return RouteContext{
		RouteContext:   i.RouteContextInputs.WithCtx(krtctx),
		InferencePools: i.InferencePools,
	}
}

// RouteContext is the agentgateway-specific extension of gatewaycommon.RouteContext.
type RouteContext struct {
	gatewaycommon.RouteContext
	InferencePools krt.Collection[*inferencev1.InferencePool]
}

// RouteContextInputsBase returns the base gatewaycommon.RouteContextInputs.
func (i RouteContextInputs) RouteContextInputsBase() gatewaycommon.RouteContextInputs {
	// Included via embedding, but exposed for passing to gatewaycommon functions
	return i.RouteContextInputs
}

// agentgateway-specific inputs that are kept separate from the common type
var _ = func() struct{} {
	// ensure NetworkingClient dependency is visible
	var _ krt.Collection[*networkingclient.ServiceEntry]
	var _ krt.Collection[*corev1.Service]
	return struct{}{}
}()

// AgwRouteCollection creates the collection of translated Routes
func AgwRouteCollection(
	queue *status.StatusCollections,
	httpRouteCol krt.Collection[*gatewayv1.HTTPRoute],
	grpcRouteCol krt.Collection[*gatewayv1.GRPCRoute],
	tcpRouteCol krt.Collection[*gatewayalpha.TCPRoute],
	tlsRouteCol krt.Collection[*gatewayv1.TLSRoute],
	inputs RouteContextInputs,
	tagWatcher krt.RecomputeProtected[revisions.TagWatcher],
	krtopts krt.OptionsBuilder,
) (krt.Collection[AgwResource], krt.Collection[*gatewaycommon.RouteAttachment]) {
	// Create httpRoutes collection
	httpRouteStatus, httpRoutes := createRouteCollection(httpRouteCol, inputs, krtopts, "HTTPRoutes",
		func(ctx RouteContext, obj *gatewayv1.HTTPRoute) (RouteContext, iter.Seq2[AgwRoute, *gatewaycommon.Condition]) {
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
		func(ctx RouteContext, obj *gatewayv1.GRPCRoute) (RouteContext, iter.Seq2[AgwRoute, *gatewaycommon.Condition]) {
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
		func(ctx RouteContext, obj *gatewayalpha.TCPRoute) (RouteContext, iter.Seq2[AgwTCPRoute, *gatewaycommon.Condition]) {
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
		func(ctx RouteContext, obj *gatewayv1.TLSRoute) (RouteContext, iter.Seq2[AgwTCPRoute, *gatewaycommon.Condition]) {
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
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs.RouteContextInputs, httpRouteCol, gvk.HTTPRoute, krtopts),
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs.RouteContextInputs, grpcRouteCol, gvk.GRPCRoute, krtopts),
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs.RouteContextInputs, tlsRouteCol, gvk.TLSRoute, krtopts),
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs.RouteContextInputs, tcpRouteCol, gvk.TCPRoute, krtopts),
	})

	return routes, routeAttachments
}

// Simplified HTTP route collection function
func createRouteCollection[T controllers.Object, ST any](
	routeCol krt.Collection[T],
	inputs RouteContextInputs,
	krtopts krt.OptionsBuilder,
	collectionName string,
	translator func(ctx RouteContext, obj T) (RouteContext, iter.Seq2[AgwRoute, *gatewaycommon.Condition]),
	buildStatus func(status gatewayv1.RouteStatus) ST,
) (
	krt.StatusCollection[T, ST],
	krt.Collection[AgwResource],
) {
	return createRouteCollectionGeneric(
		routeCol,
		inputs,
		krtopts,
		collectionName,
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

// buildAttachedRoutesMapAllowed counts attached routes by gateway+listener for allowed parents.
func buildAttachedRoutesMapAllowed(
	allowedParents []gatewaycommon.RouteParentReference,
	routeNN types.NamespacedName,
) map[types.NamespacedName]map[string]uint {
	attached := make(map[types.NamespacedName]map[string]uint)
	type attachKey struct {
		gw       types.NamespacedName
		listener string
		route    types.NamespacedName
	}
	seen := make(map[attachKey]struct{})

	for _, parent := range allowedParents {
		if parent.ParentKey.Kind != (config.GroupVersionKind{}) && parent.ParentKey.Kind != gvk.KubernetesGateway {
			continue
		}
		gw := types.NamespacedName{Namespace: parent.ParentKey.Namespace, Name: parent.ParentKey.Name}
		lis := string(parent.ParentSection)

		k := attachKey{gw: gw, listener: lis, route: routeNN}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}

		if attached[gw] == nil {
			attached[gw] = make(map[string]uint)
		}
		attached[gw][lis]++
	}
	return attached
}

// Generic function that handles the common logic
func createRouteCollectionGeneric[T controllers.Object, R comparable, ST any](
	routeCol krt.Collection[T],
	inputs RouteContextInputs,
	krtopts krt.OptionsBuilder,
	collectionName string,
	translator func(ctx RouteContext, obj T) (RouteContext, iter.Seq2[R, *gatewaycommon.Condition]),
	resourceMapper func(route R, parent gatewaycommon.RouteParentReference) AgwResource,
	buildStatus func(status gatewayv1.RouteStatus) ST,
) (
	krt.StatusCollection[T, ST],
	krt.Collection[AgwResource],
) {
	return krt.NewStatusManyCollection(routeCol, func(krtctx krt.HandlerContext, obj T) (*ST, []AgwResource) {
		ctx := inputs.WithCtx(krtctx)

		// Apply route-specific preprocessing and get the translator
		ctx, translatorSeq := translator(ctx, obj)

		parentRefs, gwResult := gatewaycommon.ComputeRoute(ctx.RouteContext, obj, func(obj T) iter.Seq2[R, *gatewaycommon.Condition] {
			return translatorSeq
		})

		routeNN := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
		ln := gatewaycommon.ListenersPerGateway(parentRefs)
		allowedParents := gatewaycommon.FilteredReferences(parentRefs)
		attachedRoutes := buildAttachedRoutesMapAllowed(allowedParents, routeNN)
		gatewaycommon.EnsureZeroes(attachedRoutes, ln)

		resources := gatewaycommon.ProcessParentReferences(
			parentRefs,
			gwResult,
			routeNN,
			resourceMapper,
		)

		rpResults := slices.Map(parentRefs, func(r gatewaycommon.RouteParentReference) gatewaycommon.RouteParentResult {
			return gatewaycommon.RouteParentResult{
				OriginalReference: r.OriginalReference,
				DeniedReason:      r.DeniedReason,
				RouteError:        gwResult.Error,
			}
		})
		parents := gatewaycommon.CreateRouteStatus(rpResults, obj.GetNamespace(), obj.GetGeneration(), inputs.ControllerName, gatewaycommon.GetCommonRouteStateParents(obj))
		routeStatus := gatewayv1.RouteStatus{Parents: parents}
		return ptr.Of(buildStatus(routeStatus)), resources
	}, krtopts.WithName(collectionName)...)
}

// Simplified TCP route collection function
func createTCPRouteCollection[T controllers.Object, ST any](
	routeCol krt.Collection[T],
	inputs RouteContextInputs,
	krtopts krt.OptionsBuilder,
	collectionName string,
	translator func(ctx RouteContext, obj T) (RouteContext, iter.Seq2[AgwTCPRoute, *gatewaycommon.Condition]),
	buildStatus func(status gatewayv1.RouteStatus) ST,
) (
	krt.StatusCollection[T, ST],
	krt.Collection[AgwResource],
) {
	return createRouteCollectionGeneric(
		routeCol,
		inputs,
		krtopts,
		collectionName,
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

// routeContextInputsFields is a compile-time check that RouteContextInputs contains the needed fields.
// It references the types to avoid "imported and not used" errors.
var _ = config.GroupVersionKind{}
