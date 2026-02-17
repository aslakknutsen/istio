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
	"strconv"
	"time"
)

// TracingConfig holds the resolved tracing configuration from an
// XGatewayExternalService of type Tracing. Since tracing is an HCM-level
// setting (not a per-route filter), only Gateway targetRef is supported.
type TracingConfig struct {
	// Host is the FQDN of the OTLP collector.
	Host string
	// Port is the port of the OTLP collector.
	Port int
	// Protocol is GRPC or HTTP.
	Protocol string
	// Timeout is the max time to wait for the collector.
	Timeout time.Duration
	// SamplingRate is the percentage of requests to trace (0-100).
	// Nil means don't override the existing sampling config.
	SamplingRate *float64
	// ServiceName is the OTLP service name for spans.
	// Empty means don't override the existing service name.
	ServiceName string
	// CustomTags are additional literal tags to add to spans.
	CustomTags map[string]string
}

// ParseTracingData extracts tracing-specific fields from the Data map.
// "sampling_rate" and "service_name" are extracted as typed fields;
// remaining keys become custom tags.
func ParseTracingData(data map[string]string) (samplingRate *float64, serviceName string, customTags map[string]string) {
	customTags = make(map[string]string)
	for k, v := range data {
		switch k {
		case "sampling_rate":
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				samplingRate = &f
			}
		case "service_name":
			serviceName = v
		default:
			customTags[k] = v
		}
	}
	return samplingRate, serviceName, customTags
}
