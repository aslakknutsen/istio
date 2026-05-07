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
	"iter"

	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	"istio.io/istio/pilot/pkg/status"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/revisions"
)

// registerRouteStatuses registers HTTPRoute and GRPCRoute status collections. Rule-level
// translation for gwxds happens in collectRoutes; here we only drive parent reference
// status (attachment, ref resolution) via gatewaycommon.RouteStatusManyCollection.
func registerRouteStatuses(
	queue *status.StatusCollections,
	httpRoutes krt.Collection[*gatewayv1.HTTPRoute],
	grpcRoutes krt.Collection[*gatewayv1.GRPCRoute],
	inputs gatewaycommon.RouteContextInputs,
	tagWatcher krt.RecomputeProtected[revisions.TagWatcher],
	opts krt.OptionsBuilder,
) {
	// Use string (not struct{}) for the discarded RouteStatusManyCollection outputs: krt.GetKey
	// must be defined for each emitted object (see krt/helpers.go).
	httpRouteStatus, _ := gatewaycommon.RouteStatusManyCollection(httpRoutes, inputs, opts, "gwxds/HTTPRoutes",
		func(ctx gatewaycommon.RouteContext, obj *gatewayv1.HTTPRoute) (gatewaycommon.RouteContext, iter.Seq2[string, *gatewaycommon.Condition]) {
			routeKey := obj.Namespace + "/" + obj.Name
			return ctx, func(yield func(string, *gatewaycommon.Condition) bool) {
				yield(routeKey, validateHTTPRouteBackends(ctx, obj))
			}
		},
		func(routeKey string, parent gatewaycommon.RouteParentReference) string {
			return routeKey + "/" + parent.InternalName
		},
		func(status gatewayv1.RouteStatus) gatewayv1.HTTPRouteStatus {
			return gatewayv1.HTTPRouteStatus{RouteStatus: status}
		},
	)
	status.RegisterStatus(queue, httpRouteStatus, GetStatus, tagWatcher.AccessUnprotected())

	grpcRouteStatus, _ := gatewaycommon.RouteStatusManyCollection(grpcRoutes, inputs, opts, "gwxds/GRPCRoutes",
		func(ctx gatewaycommon.RouteContext, obj *gatewayv1.GRPCRoute) (gatewaycommon.RouteContext, iter.Seq2[string, *gatewaycommon.Condition]) {
			routeKey := obj.Namespace + "/" + obj.Name
			return ctx, func(yield func(string, *gatewaycommon.Condition) bool) {
				yield(routeKey, validateGRPCRouteBackends(ctx, obj))
			}
		},
		func(routeKey string, parent gatewaycommon.RouteParentReference) string {
			return routeKey + "/" + parent.InternalName
		},
		func(status gatewayv1.RouteStatus) gatewayv1.GRPCRouteStatus {
			return gatewayv1.GRPCRouteStatus{RouteStatus: status}
		},
	)
	status.RegisterStatus(queue, grpcRouteStatus, GetStatus, tagWatcher.AccessUnprotected())
}

// joinedGatewayRouteAttachments aggregates per-route attachment markers for Gateway
// AttachedRoutes counts on Gateway status.
func joinedGatewayRouteAttachments(
	inputs gatewaycommon.RouteContextInputs,
	httpRoutes krt.Collection[*gatewayv1.HTTPRoute],
	grpcRoutes krt.Collection[*gatewayv1.GRPCRoute],
	opts krt.OptionsBuilder,
) krt.Collection[*gatewaycommon.RouteAttachment] {
	return krt.JoinCollection([]krt.Collection[*gatewaycommon.RouteAttachment]{
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs, httpRoutes, gvk.HTTPRoute, opts),
		gatewaycommon.GatewayRouteAttachmentCountCollection(inputs, grpcRoutes, gvk.GRPCRoute, opts),
	}, opts.WithName("gwxds/RouteAttachmentCounts")...)
}

// finalGatewayStatusWithAttachments is the gwxds equivalent of gateway.FinalGatewayStatusCollection,
// using gatewaycommon.RouteAttachment pointers (value type matches gateway.RouteAttachment).
func finalGatewayStatusWithAttachments(
	gatewayStatuses krt.StatusCollection[*gatewayv1.Gateway, gatewayv1.GatewayStatus],
	routeAttachments krt.Collection[*gatewaycommon.RouteAttachment],
	opts krt.OptionsBuilder,
) krt.StatusCollection[*gatewayv1.Gateway, gatewayv1.GatewayStatus] {
	routeAttachmentsIndex := krt.NewIndex(routeAttachments, "to", func(o *gatewaycommon.RouteAttachment) []types.NamespacedName {
		return []types.NamespacedName{o.To}
	})
	return krt.NewCollection(
		gatewayStatuses,
		func(
			ctx krt.HandlerContext, i krt.ObjectWithStatus[*gatewayv1.Gateway, gatewayv1.GatewayStatus],
		) *krt.ObjectWithStatus[*gatewayv1.Gateway, gatewayv1.GatewayStatus] {
			routes := routeAttachmentsIndex.Fetch(ctx, config.NamespacedName(i.Obj))
			counts := map[string]int32{}
			for _, r := range routes {
				counts[r.ListenerName]++
			}
			st := i.Status.DeepCopy()
			for idx, s := range st.Listeners {
				s.AttachedRoutes = counts[string(s.Name)]
				st.Listeners[idx] = s
			}
			return &krt.ObjectWithStatus[*gatewayv1.Gateway, gatewayv1.GatewayStatus]{
				Obj:    i.Obj,
				Status: *st,
			}
		}, opts.WithName("gwxds/GatewayFinalStatus")...)
}

func finalListenerSetStatusWithAttachments(
	listenerSetStatuses krt.StatusCollection[*gatewayv1.ListenerSet, gatewayv1.ListenerSetStatus],
	routeAttachments krt.Collection[*gatewaycommon.RouteAttachment],
	opts krt.OptionsBuilder,
) krt.StatusCollection[*gatewayv1.ListenerSet, gatewayv1.ListenerSetStatus] {
	routeAttachmentsIndex := krt.NewIndex(routeAttachments, "to", func(o *gatewaycommon.RouteAttachment) []types.NamespacedName {
		return []types.NamespacedName{o.To}
	})
	return krt.NewCollection(
		listenerSetStatuses,
		func(
			ctx krt.HandlerContext, i krt.ObjectWithStatus[*gatewayv1.ListenerSet, gatewayv1.ListenerSetStatus],
		) *krt.ObjectWithStatus[*gatewayv1.ListenerSet, gatewayv1.ListenerSetStatus] {
			routes := routeAttachmentsIndex.Fetch(ctx, config.NamespacedName(i.Obj))
			counts := map[string]int32{}
			for _, r := range routes {
				counts[r.ListenerName]++
			}
			st := i.Status.DeepCopy()
			for idx, s := range st.Listeners {
				s.AttachedRoutes = counts[string(s.Name)]
				st.Listeners[idx] = s
			}
			return &krt.ObjectWithStatus[*gatewayv1.ListenerSet, gatewayv1.ListenerSetStatus]{
				Obj:    i.Obj,
				Status: *st,
			}
		}, opts.WithName("gwxds/ListenerSetFinalStatus")...)
}
