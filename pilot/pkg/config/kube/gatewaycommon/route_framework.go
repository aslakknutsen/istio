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

package gatewaycommon

import (
	"fmt"
	"iter"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	inferencev1 "sigs.k8s.io/gateway-api-inference-extension/api/v1"

	networkingclient "istio.io/client-go/pkg/apis/networking/v1"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
)

// RouteContextInputs is the set of collection dependencies shared by all route translators. Build
// once per route collection and reuse across all route types.
type RouteContextInputs struct {
	Grants         ReferenceGrants
	RouteParents   RouteParents
	ControllerName string
	DomainSuffix   string
	Services       krt.Collection[*corev1.Service]
	Namespaces     krt.Collection[*corev1.Namespace]
	ServiceEntries krt.Collection[*networkingclient.ServiceEntry]
	// InferencePools is optional; use an empty static collection when unused.
	InferencePools krt.Collection[*inferencev1.InferencePool]
}

func (i RouteContextInputs) WithCtx(krtctx krt.HandlerContext) RouteContext {
	return RouteContext{
		Krt:                krtctx,
		RouteContextInputs: i,
	}
}

// RouteContext is a RouteContextInputs bound to a specific krt.HandlerContext.
type RouteContext struct {
	Krt krt.HandlerContext
	RouteContextInputs
}

// TypedResource is a GVK + namespaced name pair.
type TypedResource struct {
	Kind config.GroupVersionKind
	Name types.NamespacedName
}

func (n TypedResource) String() string {
	return n.Kind.String() + "/" + n.Name.String()
}

// RouteAttachment records that a route is attached to a specific gateway listener.
type RouteAttachment struct {
	From TypedResource
	// To is assumed to be a Gateway
	To           types.NamespacedName
	ListenerName string
}

func (r RouteAttachment) ResourceName() string {
	return r.From.Kind.String() + "/" + r.From.Name.String() + "/" + r.To.String() + "/" + r.ListenerName
}

func (r RouteAttachment) Equals(other RouteAttachment) bool {
	return r.From == other.From && r.To == other.To && r.ListenerName == other.ListenerName
}

// IsNil works around comparing generic types to nil.
func IsNil[O comparable](o O) bool {
	var t O
	return o == t
}

// ConversionResult holds the output of converting route rules for a single Kubernetes route object.
type ConversionResult[O any] struct {
	Error  *Condition
	Routes []O
}

// GatewayRouteAttachmentCountCollection builds a collection that tracks which listeners each
// route is attached to, for aggregating AttachedRoutes counts in Gateway status.
func GatewayRouteAttachmentCountCollection[T controllers.Object](
	inputs RouteContextInputs,
	col krt.Collection[T],
	kind config.GroupVersionKind,
	opts krt.OptionsBuilder,
) krt.Collection[*RouteAttachment] {
	return krt.NewManyCollection(col, func(krtctx krt.HandlerContext, obj T) []*RouteAttachment {
		ctx := inputs.WithCtx(krtctx)
		from := TypedResource{
			Kind: kind,
			Name: config.NamespacedName(obj),
		}

		parentRefs := extractParentReferenceInfo(ctx, inputs.RouteParents, obj)
		return slices.MapFilter(FilteredReferences(parentRefs), func(e RouteParentReference) **RouteAttachment {
			if e.ParentKey.Kind != gvk.KubernetesGateway {
				return nil
			}
			return ptr.Of(&RouteAttachment{
				From: from,
				To: types.NamespacedName{
					Name:      e.ParentKey.Name,
					Namespace: e.ParentKey.Namespace,
				},
				ListenerName: string(e.ParentSection),
			})
		})
	}, opts.WithName(kind.Kind+"/count")...)
}

// buildGatewayRoutes holds common logic to build a set of routes with v1/alpha2 semantics.
func buildGatewayRoutes[T any](convertRules func() T) T {
	return convertRules()
}

// ComputeRoute holds the common route building logic shared amongst all route types.
func ComputeRoute[T controllers.Object, O comparable](
	ctx RouteContext,
	obj T,
	translator func(obj T) iter.Seq2[O, *Condition],
) ([]RouteParentReference, ConversionResult[O]) {
	parentRefs := extractParentReferenceInfo(ctx, ctx.RouteParents, obj)

	convertRules := func() ConversionResult[O] {
		res := ConversionResult[O]{}
		for vs, err := range translator(obj) {
			if err != nil && IsNil(vs) {
				res.Error = err
				return ConversionResult[O]{Error: err}
			}
			if err != nil {
				res.Error = err
			}
			res.Routes = append(res.Routes, vs)
		}
		return res
	}
	gwResult := buildGatewayRoutes(convertRules)

	return parentRefs, gwResult
}

// ListenersPerGateway returns the set of listener sectionNames referenced for each parent Gateway,
// regardless of whether they are allowed.
func ListenersPerGateway(parentRefs []RouteParentReference) map[types.NamespacedName]map[string]struct{} {
	l := make(map[types.NamespacedName]map[string]struct{})
	for _, p := range parentRefs {
		if p.ParentKey.Kind != gvk.KubernetesGateway {
			continue
		}
		gw := types.NamespacedName{Namespace: p.ParentKey.Namespace, Name: p.ParentKey.Name}
		if l[gw] == nil {
			l[gw] = make(map[string]struct{})
		}
		l[gw][string(p.ParentSection)] = struct{}{}
	}
	return l
}

// EnsureZeroes pre-populates AttachedRoutes with explicit 0 entries for every referenced listener,
// so writers that "replace" rather than "merge" will correctly set zero.
func EnsureZeroes(
	attached map[types.NamespacedName]map[string]uint,
	ln map[types.NamespacedName]map[string]struct{},
) {
	for gw, set := range ln {
		if attached[gw] == nil {
			attached[gw] = make(map[string]uint)
		}
		for lis := range set {
			if _, ok := attached[gw][lis]; !ok {
				attached[gw][lis] = 0
			}
		}
	}
}

// ProcessParentReferences processes filtered parent references and builds resources per gateway.
// It emits exactly one ParentStatus per Gateway (aggregate across listeners).
// The resourceMapper converts a route object into an output resource R for a given parent.
// If no listeners are allowed, the Accepted reason is:
//   - NotAllowedByListeners  => when the parent Gateway is cross-namespace w.r.t. the route
//   - NoMatchingListenerHostname => otherwise
func ProcessParentReferences[T any, R any](
	parentRefs []RouteParentReference,
	gwResult ConversionResult[T],
	routeNN types.NamespacedName,
	resourceMapper func(T, RouteParentReference) R,
) []R {
	resources := make([]R, 0, len(parentRefs))

	// Build the "allowed" set from FilteredReferences (listener-scoped).
	allowed := make(map[string]struct{})
	for _, p := range FilteredReferences(parentRefs) {
		k := fmt.Sprintf("%s/%s/%s/%s", p.ParentKey.Namespace, p.ParentKey.Name, p.ParentKey.Kind, string(p.ParentSection))
		allowed[k] = struct{}{}
	}

	// Aggregate per Gateway for status; also track whether any raw parent was cross-namespace.
	type gwAgg struct {
		anyAllowed bool
		rep        RouteParentReference
	}
	agg := make(map[types.NamespacedName]*gwAgg)
	crossNS := sets.New[types.NamespacedName]()
	denied := make(map[types.NamespacedName]*ParentError)

	for _, p := range parentRefs {
		gwNN := p.ParentGateway
		if _, ok := agg[gwNN]; !ok {
			agg[gwNN] = &gwAgg{anyAllowed: false, rep: p}
		}
		if p.ParentKey.Namespace != routeNN.Namespace {
			crossNS.Insert(gwNN)
		}
		if p.DeniedReason != nil {
			denied[gwNN] = p.DeniedReason
		}
	}

	for _, parent := range parentRefs {
		gwNN := parent.ParentGateway
		listener := string(parent.ParentSection)
		keyStr := fmt.Sprintf("%s/%s/%s/%s", parent.ParentKey.Namespace, parent.ParentKey.Name, parent.ParentKey.Kind, listener)
		_, isAllowed := allowed[keyStr]

		if isAllowed {
			if a := agg[gwNN]; a != nil {
				a.anyAllowed = true
			}
		}
		// Only attach resources when listener is allowed. Even if ResolvedRefs is false,
		// we still attach so any DirectResponse policy can return 5xx as required.
		if !isAllowed {
			continue
		}
		routes := gwResult.Routes
		for i := range routes {
			resources = append(resources, resourceMapper(routes[i], parent))
		}
	}

	return resources
}
