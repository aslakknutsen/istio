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

package agentgateway

import (
	corev1 "k8s.io/api/core/v1"
	inferencev1 "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	"istio.io/istio/pkg/kube/krt"
)

const (
	InferencePoolFieldManager = "istio.io/inference-pool-controller"
)

// InferencePoolCollection is a thin shim that delegates to gatewaycommon.InferencePoolCollection
// using the agentgateway-managed GatewayClasses.
func InferencePoolCollection(
	pools krt.Collection[*inferencev1.InferencePool],
	services krt.Collection[*corev1.Service],
	httpRoutes krt.Collection[*gatewayv1.HTTPRoute],
	gateways krt.Collection[*gatewayv1.Gateway],
	routesByInferencePool krt.Index[string, *gatewayv1.HTTPRoute],
	opts krt.OptionsBuilder,
) (krt.StatusCollection[*inferencev1.InferencePool, inferencev1.InferencePoolStatus], krt.Collection[gatewaycommon.InferencePool]) {
	return gatewaycommon.InferencePoolCollection(
		pools,
		services,
		httpRoutes,
		gateways,
		routesByInferencePool,
		gatewaycommon.WorkloadGatewayClasses,
		opts,
	)
}
