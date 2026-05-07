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
	"iter"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	coretypes "k8s.io/apimachinery/pkg/types"
)

// RouteStatusManyCollection builds desired Route status from Gateway API route objects and optional
// translated outputs per parent reference. Shared by reconcilers that emit route parent status.
func RouteStatusManyCollection[T controllers.Object, R comparable, O any, ST any](
	routeCol krt.Collection[T],
	inputs RouteContextInputs,
	krtopts krt.OptionsBuilder,
	collectionName string,
	translator func(ctx RouteContext, obj T) (RouteContext, iter.Seq2[R, *Condition]),
	resourceMapper func(route R, parent RouteParentReference) O,
	buildStatus func(status gatewayv1.RouteStatus) ST,
) (krt.StatusCollection[T, ST], krt.Collection[O]) {
	return krt.NewStatusManyCollection(routeCol, func(krtctx krt.HandlerContext, obj T) (*ST, []O) {
		ctx := inputs.WithCtx(krtctx)
		ctx, translatorSeq := translator(ctx, obj)

		parentRefs, gwResult := ComputeRoute(ctx, obj, func(obj T) iter.Seq2[R, *Condition] {
			return translatorSeq
		})

		routeNN := coretypes.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}
		ln := ListenersPerGateway(parentRefs)
		allowedParents := FilteredReferences(parentRefs)
		attachedRoutes := buildAttachedRoutesMapAllowed(allowedParents, routeNN)
		EnsureZeroes(attachedRoutes, ln)

		resources := ProcessParentReferences(
			parentRefs,
			gwResult,
			routeNN,
			resourceMapper,
		)

		rpResults := slices.Map(parentRefs, func(r RouteParentReference) RouteParentResult {
			return RouteParentResult{
				OriginalReference: r.OriginalReference,
				DeniedReason:      r.DeniedReason,
				RouteError:        gwResult.Error,
			}
		})
		parents := CreateRouteStatus(rpResults, obj.GetNamespace(), obj.GetGeneration(), inputs.ControllerName, GetCommonRouteStateParents(obj))
		routeStatus := gatewayv1.RouteStatus{Parents: parents}
		return ptr.Of(buildStatus(routeStatus)), resources
	}, krtopts.WithName(collectionName)...)
}

func buildAttachedRoutesMapAllowed(
	allowedParents []RouteParentReference,
	routeNN coretypes.NamespacedName,
) map[coretypes.NamespacedName]map[string]uint {
	attached := make(map[coretypes.NamespacedName]map[string]uint)
	type attachKey struct {
		gw       coretypes.NamespacedName
		listener string
		route    coretypes.NamespacedName
	}
	seen := make(map[attachKey]struct{})

	for _, parent := range allowedParents {
		if parent.ParentKey.Kind != (config.GroupVersionKind{}) && parent.ParentKey.Kind != gvk.KubernetesGateway {
			continue
		}
		gw := coretypes.NamespacedName{Namespace: parent.ParentKey.Namespace, Name: parent.ParentKey.Name}
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
