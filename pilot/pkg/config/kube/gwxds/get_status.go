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
	inferencev1 "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/ptr"
)

// GetStatus extracts the status subresource from Gateway API objects written by this controller.
func GetStatus[I, IS any](spec I) IS {
	switch t := any(spec).(type) {
	case *gatewayv1.HTTPRoute:
		return any(t.Status).(IS)
	case *gatewayv1.GRPCRoute:
		return any(t.Status).(IS)
	case *gatewayv1.Gateway:
		return any(t.Status).(IS)
	case *gatewayv1.GatewayClass:
		return any(t.Status).(IS)
	case *gatewayv1.BackendTLSPolicy:
		return any(t.Status).(IS)
	case *gatewayv1.ListenerSet:
		return any(t.Status).(IS)
	case *inferencev1.InferencePool:
		return any(t.Status).(IS)
	default:
		log.Fatalf("unknown type %T", t)
		return ptr.Empty[IS]()
	}
}
