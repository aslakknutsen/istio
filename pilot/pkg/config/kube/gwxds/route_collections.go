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

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	"istio.io/istio/pilot/pkg/status"
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
	emptyHTTP := func(yield func(struct{}, *gatewaycommon.Condition) bool) {}
	httpRouteStatus, _ := gatewaycommon.RouteStatusManyCollection(httpRoutes, inputs, opts, "gwxds/HTTPRoutes",
		func(ctx gatewaycommon.RouteContext, _ *gatewayv1.HTTPRoute) (gatewaycommon.RouteContext, iter.Seq2[struct{}, *gatewaycommon.Condition]) {
			return ctx, emptyHTTP
		},
		func(_ struct{}, _ gatewaycommon.RouteParentReference) struct{} { return struct{}{} },
		func(status gatewayv1.RouteStatus) gatewayv1.HTTPRouteStatus {
			return gatewayv1.HTTPRouteStatus{RouteStatus: status}
		},
	)
	status.RegisterStatus(queue, httpRouteStatus, GetStatus, tagWatcher.AccessUnprotected())

	emptyGRPC := func(yield func(struct{}, *gatewaycommon.Condition) bool) {}
	grpcRouteStatus, _ := gatewaycommon.RouteStatusManyCollection(grpcRoutes, inputs, opts, "gwxds/GRPCRoutes",
		func(ctx gatewaycommon.RouteContext, _ *gatewayv1.GRPCRoute) (gatewaycommon.RouteContext, iter.Seq2[struct{}, *gatewaycommon.Condition]) {
			return ctx, emptyGRPC
		},
		func(_ struct{}, _ gatewaycommon.RouteParentReference) struct{} { return struct{}{} },
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
