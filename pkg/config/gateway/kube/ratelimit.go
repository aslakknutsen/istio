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

import (
	"strings"
	"time"
)

// GEP5000RateLimitFilterPrefix is the prefix for Envoy HTTP filter names generated
// from XGatewayExternalService resources of type RateLimit. The full filter name is
// "{prefix}/{namespace}/{name}" where namespace/name identify the CR.
const GEP5000RateLimitFilterPrefix = "envoy.filters.http.ratelimit"

// RateLimitFilterName returns the Envoy filter name for a given XGatewayExternalService
// of type RateLimit.
func RateLimitFilterName(namespace, name string) string {
	return GEP5000RateLimitFilterPrefix + "/" + namespace + "/" + name
}

// RateLimitHCMFilterConfig holds the information needed to build a disabled HCM-level
// ratelimit filter. One is created per XGatewayExternalService CR of type RateLimit.
// Unlike ext_authz, the ratelimit filter does NOT support per-route service overrides,
// so the RLS cluster must be set at the HCM level.
type RateLimitHCMFilterConfig struct {
	// FilterName is the unique Envoy filter name (encodes CR namespace/name).
	FilterName string
	// FailOpen when true sets failure_mode_deny=false on the RateLimit filter.
	FailOpen bool
	// Priority controls ordering in the HCM filter chain. Lower values first.
	Priority int32
	// Host is the FQDN of the RLS backend service (needed to build the cluster name).
	Host string
	// Port is the port of the RLS backend service.
	Port int
}

// RateLimitDescriptor represents a single descriptor entry for the RLS request.
type RateLimitDescriptor struct {
	// Key is the descriptor key sent to the RLS.
	Key string
	// Value is the static value. Empty if MetadataKey is set.
	Value string
	// MetadataFilterName is the filter name for dynamic metadata lookups.
	// Non-empty only for {metadata.<filter>.<path>} values.
	MetadataFilterName string
	// MetadataPath is the path segments for dynamic metadata lookups.
	MetadataPath []string
	// DefaultValue is the fallback value if metadata lookup fails.
	DefaultValue string
}

// RateLimitRouteRuleConfig holds per-route rate limit configuration resolved from
// an XGatewayExternalService resource. This data is stored in the Extra field
// of a config.Config for a VirtualService, keyed by the istio HTTPRoute rule name.
type RateLimitRouteRuleConfig struct {
	// FilterName is the Envoy filter name to use in TypedPerFilterConfig.
	FilterName string
	// Host is the FQDN of the RLS backend service.
	Host string
	// Port is the port of the RLS backend service.
	Port int
	// Timeout is the max time to wait for an RLS response.
	Timeout time.Duration
	// Priority controls ordering. Lower values execute first.
	Priority int32
	// Domain is the rate limit domain sent in RateLimitRequest.
	Domain string
	// Descriptors are the descriptor entries to include in the RLS request.
	Descriptors []RateLimitDescriptor
}

// ParseRateLimitData extracts the domain and descriptors from the XGatewayExternalService Data map.
// The "domain" key is extracted as the RLS domain. Other keys become descriptor entries.
// Values matching {metadata.<filter_name>.<path>} are parsed into dynamic metadata lookups.
func ParseRateLimitData(data map[string]string) (domain string, descriptors []RateLimitDescriptor) {
	domain = data["domain"]
	for k, v := range data {
		if k == "domain" {
			continue
		}
		desc := RateLimitDescriptor{Key: k}
		if strings.HasPrefix(v, "{metadata.") && strings.HasSuffix(v, "}") {
			// Parse {metadata.<filter_name>.<path_segment1>.<path_segment2>...}
			inner := v[len("{metadata.") : len(v)-1]
			parts := strings.SplitN(inner, ".", 2)
			if len(parts) == 2 {
				desc.MetadataFilterName = parts[0]
				desc.MetadataPath = strings.Split(parts[1], ".")
			} else {
				// Malformed -- treat as static value
				desc.Value = v
			}
		} else {
			desc.Value = v
		}
		descriptors = append(descriptors, desc)
	}
	return domain, descriptors
}
