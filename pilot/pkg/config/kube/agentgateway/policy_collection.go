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
	"github.com/agentgateway/agentgateway/api"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/krt"
)

// dummyCaCert is a sentinel value sent to agentgateway to signal that it should
// reject TLS connections because the BackendTLSPolicy had an invalid certificate config.
var dummyCaCert = []byte("invalid")

// BackendTLSPolicyInputs is a type alias for the neutral gatewaycommon inputs type.
type BackendTLSPolicyInputs = gatewaycommon.BackendTLSPolicyInputs

// AncestorBackend is a type alias for the neutral gatewaycommon type.
type AncestorBackend = gatewaycommon.AncestorBackend

// BuildAncestorBackends delegates to the gatewaycommon implementation.
var BuildAncestorBackends = gatewaycommon.BuildAncestorBackends

// BackendTLSPolicyCollection builds status + a collection of agentgateway Policy resources
// by delegating resolution to gatewaycommon and translating to api.Policy protos.
func BackendTLSPolicyCollection(
	inputs BackendTLSPolicyInputs,
	opts krt.OptionsBuilder,
) (krt.StatusCollection[*gatewayv1.BackendTLSPolicy, gatewayv1.PolicyStatus], krt.Collection[AgwResource]) {
	btlsStatus, resolved := gatewaycommon.BackendTLSPolicyCollection(inputs, opts)

	agwPolicies := krt.NewManyCollection(resolved, func(_ krt.HandlerContext, r gatewaycommon.ResolvedBackendTLS) []AgwResource {
		return translateResolvedBackendTLS(r)
	}, opts.WithName("BackendTLSAgwResources")...)

	return btlsStatus, agwPolicies
}

// translateResolvedBackendTLS converts a neutral ResolvedBackendTLS into agentgateway Policy protos.
func translateResolvedBackendTLS(r gatewaycommon.ResolvedBackendTLS) []AgwResource {
	policyTarget := resolvedTargetToAgwTarget(r.Target)
	if policyTarget == nil {
		return nil
	}

	caCert := r.CACert
	if r.Invalid {
		caCert = dummyCaCert
	}

	res := &api.BackendPolicySpec_BackendTLS{
		Root:                  caCert,
		Hostname:              &r.Hostname,
		VerifySubjectAltNames: r.SANs,
		Cert:                  r.ClientCert,
		Key:                   r.ClientKey,
	}

	policy := &api.Policy{
		Key:    r.Key,
		Target: policyTarget,
		Kind: &api.Policy_Backend{
			Backend: &api.BackendPolicySpec{
				Kind: &api.BackendPolicySpec_BackendTls{
					BackendTls: res,
				},
			},
		},
	}

	return []AgwResource{{
		Resource: ToAgwResource(policy),
		Gateway:  r.Gateway,
	}}
}

// resolvedTargetToAgwTarget converts a ResolvedBackendTLSTarget to an agentgateway PolicyTarget.
func resolvedTargetToAgwTarget(t gatewaycommon.ResolvedBackendTLSTarget) *api.PolicyTarget {
	svcTarget := &api.PolicyTarget_ServiceTarget{
		Namespace: t.Namespace,
		Hostname:  t.Hostname,
		Port:      t.Port,
	}
	switch t.Kind {
	case gvk.Service.Kind, gvk.InferencePool.Kind:
		return &api.PolicyTarget{Kind: &api.PolicyTarget_Service{Service: svcTarget}}
	default:
		return nil
	}
}
