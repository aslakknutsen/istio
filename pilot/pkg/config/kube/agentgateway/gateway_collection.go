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
	"github.com/agentgateway/agentgateway/api"

	"istio.io/istio/pilot/pkg/util/protoconv"
)

// AgwRoute is a wrapper type that contains the route on the gateway, as well as the status for the route.
// A Route is a special resource that represents a route for an HTTP listener, which has different semantics
// than a TCP route and needs to be tracked separately.
type AgwRoute struct {
	*api.Route
}

func (g AgwRoute) ResourceName() string {
	return g.Key
}

func (g AgwRoute) Equals(other AgwRoute) bool {
	return protoconv.Equals(g, other)
}

// AgwTCPRoute is a wrapper type that contains the tcp route on the gateway, as well as the status for the tcp route.
// A TCPRoute is a special resource that represents a route for a TCP listener, which has different semantics than an
// HTTP route and needs to be tracked separately.
type AgwTCPRoute struct {
	*api.TCPRoute
}

func (g AgwTCPRoute) ResourceName() string {
	return g.Key
}

func (g AgwTCPRoute) Equals(other AgwTCPRoute) bool {
	return protoconv.Equals(g, other)
}

// AgwBind is a wrapper type that contains the bind on the gateway, as well as the status for the bind.
// A Bind is a special resource that represents the binding of a route to a listener. It is used to track
// the attached routes for a listener, which is information that is not available until route processing.
type AgwBind struct {
	*api.Bind
}

func (g AgwBind) ResourceName() string {
	return g.Key
}

func (g AgwBind) Equals(other AgwBind) bool {
	return protoconv.Equals(g, other)
}

// AgwListener is a wrapper type that contains the listener on the gateway, as well as the status for the listener.
type AgwListener struct {
	*api.Listener
}

func (g AgwListener) ResourceName() string {
	return g.Key
}

func (g AgwListener) Equals(other AgwListener) bool {
	return protoconv.Equals(g, other)
}
