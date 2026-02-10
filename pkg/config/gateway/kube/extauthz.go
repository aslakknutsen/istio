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

package kube

import "time"

// GEP5000ExtAuthzFilterPrefix is the prefix for Envoy HTTP filter names generated
// from XGatewayExternalService resources. The full filter name is
// "{prefix}/{namespace}/{name}" where namespace/name identify the CR.
// This avoids conflict with the existing AuthorizationPolicy CUSTOM ext_authz path.
const GEP5000ExtAuthzFilterPrefix = "envoy.filters.http.ext_authz"

// ExtAuthzFilterName returns the Envoy filter name for a given XGatewayExternalService.
// The name encodes the CR identity so that multiple ext_authz backends on the same
// route each get their own disabled HCM filter and per-route TypedPerFilterConfig entry.
func ExtAuthzFilterName(namespace, name string) string {
	return GEP5000ExtAuthzFilterPrefix + "/" + namespace + "/" + name
}

// ExtAuthzHCMFilterConfig holds the information needed to build a disabled HCM-level
// ext_authz filter. One is created per XGatewayExternalService CR.
type ExtAuthzHCMFilterConfig struct {
	// FilterName is the unique Envoy filter name (encodes CR namespace/name).
	FilterName string
	// FailOpen sets failure_mode_allow on the top-level ExtAuthz filter config.
	FailOpen bool
	// Priority controls ordering in the HCM filter chain. Lower values first.
	Priority int32
}

// ExtAuthzRouteRuleConfig holds per-route ext_authz configuration resolved from
// an XGatewayExternalService resource. This data is stored in the Extra field
// of a config.Config for a VirtualService, keyed by the istio HTTPRoute rule name.
type ExtAuthzRouteRuleConfig struct {
	// FilterName is the Envoy filter name to use in TypedPerFilterConfig.
	FilterName string
	// Host is the FQDN of the ext_authz backend service.
	Host string
	// Port is the port of the ext_authz backend service.
	Port int
	// Protocol is GRPC or HTTP.
	Protocol string
	// Timeout is the max time to wait for a backend response.
	Timeout time.Duration
	// Priority controls ordering. Lower values execute first.
	Priority int32
	// Data maps to ext_authz context_extensions.
	Data map[string]string
}
