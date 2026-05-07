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
	"fmt"

	"go.uber.org/atomic"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	inferencev1 "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1beta1"

	networkingclient "istio.io/client-go/pkg/apis/networking/v1"
	"istio.io/istio/pilot/pkg/config/kube/gatewaycommon"
	kubesecrets "istio.io/istio/pilot/pkg/credentials/kube"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	kubecontroller "istio.io/istio/pilot/pkg/serviceregistry/kube/controller"
	"istio.io/istio/pilot/pkg/status"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pilot/pkg/xds"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/schema/gvr"
	gwxdsapi "istio.io/istio/pkg/gwxdsapi"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/kubetypes"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/revisions"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
)

var gwxdsLog = log.RegisterScope("gwxds", "gwxds controller")

// GwXdsResource is the top-level resource served to a gwxds-capable proxy.
// It wraps gwxdsapi.Resource and implements xds.IntoProto so the krtxds
// machinery can distribute it as a typed proto Any.
type GwXdsResource struct {
	Resource *gwxdsapi.Resource
	Gateway  types.NamespacedName
}

// IntoProto returns the underlying proto message for xDS serialisation.
func (r GwXdsResource) IntoProto() *gwxdsapi.Resource { return r.Resource }

// ResourceName returns the KRT stable key for a GwXdsResource.
func (r GwXdsResource) ResourceName() string { return r.Resource.Key }

// XDSResourceName returns the xDS resource name as seen by the proxy.
func (r GwXdsResource) XDSResourceName() string { return r.Resource.Key }

// Equals implements KRT equality for delta computation.
func (r GwXdsResource) Equals(other GwXdsResource) bool {
	return r.Gateway == other.Gateway && protoconv.Equals(r.Resource, other.Resource)
}

// GwXdsInputs holds all informer collections the gwxds controller needs.
type GwXdsInputs struct {
	Namespaces         krt.Collection[*corev1.Namespace]
	Services           krt.Collection[*corev1.Service]
	Secrets            krt.Collection[*corev1.Secret]
	ConfigMaps         krt.Collection[*corev1.ConfigMap]
	GatewayClasses     krt.Collection[*gatewayv1.GatewayClass]
	Gateways           krt.Collection[*gatewayv1.Gateway]
	HTTPRoutes         krt.Collection[*gatewayv1.HTTPRoute]
	GRPCRoutes         krt.Collection[*gatewayv1.GRPCRoute]
	ListenerSets       krt.Collection[*gatewayv1.ListenerSet]
	ReferenceGrants    krt.Collection[*gateway.ReferenceGrant]
	ServiceEntries     krt.Collection[*networkingclient.ServiceEntry]
	BackendTLSPolicies krt.Collection[*gatewayv1.BackendTLSPolicy]
	InferencePools     krt.Collection[*inferencev1.InferencePool]
}

// Controller is the gwxds controller. It consumes gatewaycommon collections and
// produces GwXdsResource objects for distribution to gwxds-capable proxies.
type Controller struct {
	stop chan struct{}

	gatewayContext krt.RecomputeProtected[*atomic.Pointer[gatewaycommon.GatewayContext]]
	tagWatcher     krt.RecomputeProtected[revisions.TagWatcher]

	outputs krt.Collection[GwXdsResource]

	Registrations []xds.Registration

	// status drives asynchronous Gateway API status updates when this reconciler is the status leader.
	status *status.StatusCollections

	domainSuffix string
	clusterID    cluster.ID
}

// NewController creates and starts a new gwxds Controller.
func NewController(
	kc kube.Client,
	waitForCRD func(class schema.GroupVersionResource, stop <-chan struct{}) bool,
	options kubecontroller.Options,
) *Controller {
	stop := make(chan struct{})
	opts := krt.NewOptionsBuilder(stop, "gwxds", options.KrtDebugger)

	tw := revisions.NewTagWatcher(kc, options.Revision, options.SystemNamespace)
	c := &Controller{
		stop:           stop,
		domainSuffix:   options.DomainSuffix,
		clusterID:      options.ClusterID,
		status:         &status.StatusCollections{},
		tagWatcher:     krt.NewRecomputeProtected(tw, false, opts.WithName("gwxds/tagWatcher")...),
		gatewayContext: krt.NewRecomputeProtected(atomic.NewPointer[gatewaycommon.GatewayContext](nil), false, opts.WithName("gwxds/gatewayContext")...),
	}
	tw.AddHandler(func(s sets.String) {
		c.tagWatcher.TriggerRecomputation()
	})

	inputs := c.buildInputs(kc, options.Revision, opts)
	c.buildCollections(inputs, options.DomainSuffix, opts)
	return c
}

// Reconcile updates the gateway context. Called by the Istiod push-context machinery once per push.
// It implements model.GwXdsReconciler.
func (c *Controller) Reconcile(ps *model.PushContext) {
	ctx := gatewaycommon.NewGatewayContext(ps, c.clusterID)
	c.gatewayContext.Modify(func(i **atomic.Pointer[gatewaycommon.GatewayContext]) {
		(*i).Store(&ctx)
	})
	c.gatewayContext.MarkSynced()
}

func (c *Controller) buildInputs(
	kc kube.Client,
	revision string,
	opts krt.OptionsBuilder,
) *GwXdsInputs {
	inRevision := func(obj any) bool {
		object, ok := obj.(interface{ GetLabels() map[string]string })
		if !ok {
			return true
		}
		return config.LabelsInRevision(object.GetLabels(), revision)
	}
	filter := kclient.Filter{
		ObjectFilter: kubetypes.ComposeFilters(kc.ObjectFilter(), inRevision),
	}
	filterForGateway := kclient.Filter{ObjectFilter: kc.ObjectFilter()}

	return &GwXdsInputs{
		Namespaces: krt.WrapClient(
			kclient.NewFiltered[*corev1.Namespace](kc, kubetypes.Filter{ObjectFilter: kc.ObjectFilter()}),
			opts.WithName("gwxds/Namespaces")...,
		),
		Services: krt.WrapClient(
			kclient.NewFiltered[*corev1.Service](kc, kubetypes.Filter{ObjectFilter: kc.ObjectFilter()}),
			opts.WithName("gwxds/Services")...,
		),
		Secrets: krt.WrapClient(
			kclient.NewFiltered[*corev1.Secret](kc, kubetypes.Filter{
				FieldSelector: kubesecrets.SecretsFieldSelector,
				ObjectFilter:  kc.ObjectFilter(),
			}),
			opts.WithName("gwxds/Secrets")...,
		),
		ConfigMaps: krt.WrapClient(
			kclient.NewFiltered[*corev1.ConfigMap](kc, kubetypes.Filter{ObjectFilter: kc.ObjectFilter()}),
			opts.WithName("gwxds/ConfigMaps")...,
		),
		GatewayClasses: krt.WrapClient(
			kclient.NewFiltered[*gatewayv1.GatewayClass](kc, kubetypes.Filter{ObjectFilter: filterForGateway.ObjectFilter}),
			opts.WithName("gwxds/GatewayClasses")...,
		),
		Gateways: krt.WrapClient(
			kclient.NewFiltered[*gatewayv1.Gateway](kc, kubetypes.Filter{ObjectFilter: filterForGateway.ObjectFilter}),
			opts.WithName("gwxds/Gateways")...,
		),
		HTTPRoutes: krt.WrapClient(
			kclient.NewFiltered[*gatewayv1.HTTPRoute](kc, kubetypes.Filter{ObjectFilter: filter.ObjectFilter}),
			opts.WithName("gwxds/HTTPRoutes")...,
		),
		ListenerSets: krt.WrapClient(
			kclient.NewFiltered[*gatewayv1.ListenerSet](kc, kubetypes.Filter{ObjectFilter: filter.ObjectFilter}),
			opts.WithName("gwxds/ListenerSets")...,
		),
		ReferenceGrants: krt.WrapClient(
			kclient.NewFiltered[*gateway.ReferenceGrant](kc, kubetypes.Filter{ObjectFilter: filter.ObjectFilter}),
			opts.WithName("gwxds/ReferenceGrants")...,
		),
		ServiceEntries: krt.WrapClient(
			kclient.NewFiltered[*networkingclient.ServiceEntry](kc, kubetypes.Filter{ObjectFilter: filter.ObjectFilter}),
			opts.WithName("gwxds/ServiceEntries")...,
		),
		BackendTLSPolicies: krt.WrapClient(
			kclient.NewFiltered[*gatewayv1.BackendTLSPolicy](kc, kubetypes.Filter{ObjectFilter: filter.ObjectFilter}),
			opts.WithName("gwxds/BackendTLSPolicies")...,
		),
		GRPCRoutes: krt.WrapClient(
			kclient.NewFiltered[*gatewayv1.GRPCRoute](kc, kubetypes.Filter{ObjectFilter: filter.ObjectFilter}),
			opts.WithName("gwxds/GRPCRoutes")...,
		),
		InferencePools: krt.WrapClient(
			kclient.NewFiltered[*inferencev1.InferencePool](kc, kubetypes.Filter{ObjectFilter: filter.ObjectFilter}),
			opts.WithName("gwxds/InferencePools")...,
		),
	}
}

// fetchClass resolves a GatewayClass owned by the gwxds controller.
// It returns nil for any class not in gatewaycommon.GwXdsClasses so that
// unrelated Gateway objects are silently ignored.
func fetchClass(ctx krt.HandlerContext, gatewayClasses krt.Collection[gatewaycommon.GatewayClass], gc gatewayv1.ObjectName) *gatewaycommon.GatewayClass {
	bc, f := gatewaycommon.GwXdsClasses[gc]
	if !f {
		return nil
	}
	class := krt.FetchOne(ctx, gatewayClasses, krt.FilterKey(string(gc)))
	if class == nil {
		return &gatewaycommon.GatewayClass{Name: string(gc), Controller: bc}
	}
	return class
}

func (c *Controller) buildCollections(inputs *GwXdsInputs, domainSuffix string, opts krt.OptionsBuilder) {
	gatewayClassStatus, gatewayClasses := gatewaycommon.GatewayClassesCollection(inputs.GatewayClasses, opts)
	status.RegisterStatus(c.status, gatewayClassStatus, GetStatus, c.tagWatcher.AccessUnprotected())

	refGrantsCol := gatewaycommon.ReferenceGrantsCollection(inputs.ReferenceGrants, opts)
	refGrants := gatewaycommon.BuildReferenceGrants(refGrantsCol)

	listenerSetStatus, listenerSets := gatewaycommon.ListenerSetCollection(
		inputs.ListenerSets,
		inputs.Gateways,
		gatewayClasses,
		inputs.Namespaces,
		refGrants,
		inputs.ConfigMaps,
		inputs.Secrets,
		domainSuffix,
		c.gatewayContext,
		c.tagWatcher,
		fetchClass,
		opts,
	)
	status.RegisterStatus(c.status, listenerSetStatus, GetStatus, c.tagWatcher.AccessUnprotected())

	gatewayInitialStatus, gateways := gatewaycommon.GatewayCollection(
		inputs.Gateways,
		listenerSets,
		gatewayClasses,
		inputs.Namespaces,
		refGrants,
		inputs.ConfigMaps,
		inputs.Secrets,
		domainSuffix,
		c.gatewayContext,
		c.tagWatcher,
		fetchClass,
		opts,
	)

	routeParents := gatewaycommon.BuildRouteParents(gateways)

	routeInputs := gatewaycommon.RouteContextInputs{
		Grants:         refGrants,
		RouteParents:   routeParents,
		ControllerName: constants.ManagedGwXdsController,
		DomainSuffix:   domainSuffix,
		Services:       inputs.Services,
		Namespaces:     inputs.Namespaces,
		ServiceEntries: inputs.ServiceEntries,
		InferencePools: inputs.InferencePools,
	}

	registerRouteStatuses(c.status, inputs.HTTPRoutes, inputs.GRPCRoutes, routeInputs, c.tagWatcher, opts)

	routeAttachments := joinedGatewayRouteAttachments(routeInputs, inputs.HTTPRoutes, inputs.GRPCRoutes, opts)
	gatewayFinalStatus := c.buildFinalGatewayStatus(gatewayInitialStatus, routeAttachments, opts)
	status.RegisterStatus(c.status, gatewayFinalStatus, GetStatus, c.tagWatcher.AccessUnprotected())

	// Build BackendTLS resolved policies and index them by backend NamespacedName.
	ancestorBackends := gatewaycommon.BuildAncestorBackends(inputs.HTTPRoutes, inputs.GRPCRoutes, opts)
	backendTLSStatus, resolvedTLS := gatewaycommon.BackendTLSPolicyCollection(gatewaycommon.BackendTLSPolicyInputs{
		BackendTLSPolicies: inputs.BackendTLSPolicies,
		ConfigMaps:         inputs.ConfigMaps,
		Secrets:            inputs.Secrets,
		Services:           inputs.Services,
		Gateways:           inputs.Gateways,
		AncestorBackends:   ancestorBackends,
		ControllerName:     constants.ManagedGwXdsController,
		DomainSuffix:       domainSuffix,
	}, opts)
	status.RegisterStatus(c.status, backendTLSStatus, GetStatus, c.tagWatcher.AccessUnprotected())

	if features.EnableGatewayAPIInferenceExtension {
		httpRoutesByInferencePool := krt.NewIndex(inputs.HTTPRoutes, "gwxds-inferencepool-route", gatewaycommon.IndexHTTPRouteByInferencePool)
		inferencePoolStatus, _ := gatewaycommon.InferencePoolCollection(
			inputs.InferencePools,
			inputs.Services,
			inputs.HTTPRoutes,
			inputs.Gateways,
			httpRoutesByInferencePool,
			gatewaycommon.GwXdsClasses,
			opts,
		)
		status.RegisterStatus(c.status, inferencePoolStatus, GetStatus, c.tagWatcher.AccessUnprotected())
	}

	// Index resolved TLS policies by "namespace/expanded-hostname" for O(1) lookup per backend.
	tlsByBackend := krt.NewIndex(resolvedTLS, "gwxds-tls-by-backend", func(r gatewaycommon.ResolvedBackendTLS) []string {
		return []string{r.Target.Namespace + "/" + r.Target.Hostname}
	})

	// Build a GwXdsResource per GatewayListener, bundling all attached HTTPRoutes.
	httproutesByListener := buildHTTPRouteIndex(inputs.HTTPRoutes, routeInputs, gateways, opts)

	gwResources := krt.NewCollection(gateways, func(krtctx krt.HandlerContext, gl *gatewaycommon.GatewayListener) *GwXdsResource {
		gwListener := GatewayListenerToGwListener(gl)
		if gwListener == nil {
			return nil
		}

		lookup := BackendLookup{
			DomainSuffix: domainSuffix,
			PoolByKey: func(key string) *inferencev1.InferencePool {
				return ptr.Flatten(krt.FetchOne(krtctx, inputs.InferencePools,
					krt.FilterKey(key)))
			},
			// TLSByHost receives "namespace/expanded-hostname" matching the index key.
			TLSByHost: func(key string) *gatewaycommon.ResolvedBackendTLS {
				matches := tlsByBackend.Fetch(krtctx, key)
				if len(matches) == 0 {
					return nil
				}
				return &matches[0]
			},
		}

		routes := collectRoutes(krtctx, gl, inputs.HTTPRoutes, httproutesByListener, domainSuffix, lookup)
		if routes == nil {
			routes = []*gwxdsapi.Route{}
		}

		res := &gwxdsapi.Resource{
			Key:      gl.Name,
			Listener: gwListener,
			Routes:   routes,
		}
		return &GwXdsResource{
			Resource: res,
			Gateway:  gl.ParentGateway,
		}
	}, opts.WithName("gwxds/GwXdsResources")...)

	c.outputs = gwResources
	extractGateway := func(r GwXdsResource) types.NamespacedName { return r.Gateway }
	c.Registrations = append(c.Registrations,
		xds.PerGatewayCollection[GwXdsResource, *gwxdsapi.Resource](gwResources, extractGateway, opts),
	)
}

// buildHTTPRouteIndex creates an index from listener-name → attached HTTPRoutes.
//
// Two index keys are emitted per parentRef:
//   - "ns/gw-name.sectionName" when sectionName is set — targets the specific listener.
//   - "ns/gw-name" when sectionName is absent — the route attaches to all listeners on
//     that gateway (Gateway API spec §5.4). collectRoutes queries both keys so that
//     routes without a sectionName are picked up by every listener of the gateway.
func buildHTTPRouteIndex(
	httproutes krt.Collection[*gatewayv1.HTTPRoute],
	inputs gatewaycommon.RouteContextInputs,
	gateways krt.Collection[*gatewaycommon.GatewayListener],
	opts krt.OptionsBuilder,
) krt.Index[string, *gatewayv1.HTTPRoute] {
	_ = gateways // reserved for future cross-reference filtering
	_ = inputs   // reserved for future attachment filtering

	return krt.NewIndex(httproutes, "gwxds-listener", func(hr *gatewayv1.HTTPRoute) []string {
		var keys []string
		for _, pr := range hr.Spec.ParentRefs {
			ns := hr.Namespace
			if pr.Namespace != nil {
				ns = string(*pr.Namespace)
			}
			gwName := types.NamespacedName{Namespace: ns, Name: string(pr.Name)}
			if pr.SectionName != nil {
				// Targets a specific listener.
				keys = append(keys, gatewaycommon.InternalGatewayName(gwName.Namespace, gwName.Name, string(*pr.SectionName)))
			} else {
				// No sectionName: attaches to all listeners. Index under the bare gateway key;
				// collectRoutes will query this key in addition to the per-listener key.
				keys = append(keys, gatewaycommon.InternalGatewayName(gwName.Namespace, gwName.Name, ""))
			}
		}
		return keys
	})
}

// collectRoutes gathers all GwRoute objects for a single GatewayListener.
//
// It fetches routes indexed under the exact listener key (gl.Name, which has the
// "ns/gw.listener" form) and also under the bare gateway key ("ns/gw", no listener
// suffix) to pick up routes whose parentRef has no sectionName.
func collectRoutes(
	krtctx krt.HandlerContext,
	gl *gatewaycommon.GatewayListener,
	httproutes krt.Collection[*gatewayv1.HTTPRoute],
	idx krt.Index[string, *gatewayv1.HTTPRoute],
	domainSuffix string,
	lookup BackendLookup,
) []*gwxdsapi.Route {
	// Fetch routes that explicitly name this listener via sectionName.
	exact := krt.Fetch(krtctx, httproutes, krt.FilterIndex(idx, gl.Name))
	// Fetch routes that reference the parent gateway without a sectionName (wildcard attach).
	gwKey := gatewaycommon.InternalGatewayName(gl.ParentGateway.Namespace, gl.ParentGateway.Name, "")
	wildcard := krt.Fetch(krtctx, httproutes, krt.FilterIndex(idx, gwKey))

	// Merge and deduplicate by route NamespacedName so a route with both a matching
	// sectionName and a matching gateway name is not counted twice.
	seen := make(map[types.NamespacedName]struct{}, len(exact)+len(wildcard))
	var merged []*gatewayv1.HTTPRoute
	for _, hr := range append(exact, wildcard...) {
		k := types.NamespacedName{Namespace: hr.Namespace, Name: hr.Name}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		merged = append(merged, hr)
	}

	var out []*gwxdsapi.Route
	for _, hr := range merged {
		hs := slices.Map(hr.Spec.Hostnames, func(h gatewayv1.Hostname) gatewayv1.Hostname { return h })
		for i, rule := range hr.Spec.Rules {
			key := fmt.Sprintf("%s/%s/%d", hr.Namespace, hr.Name, i)
			out = append(out, HTTPRouteRuleToGwRoute(key, gl.Name, hr.Namespace, hs, rule, lookup))
		}
	}
	return out
}

func (c *Controller) buildFinalGatewayStatus(
	gatewayStatuses krt.StatusCollection[*gatewayv1.Gateway, gatewayv1.GatewayStatus],
	routeAttachments krt.Collection[*gatewaycommon.RouteAttachment],
	opts krt.OptionsBuilder,
) krt.StatusCollection[*gatewayv1.Gateway, gatewayv1.GatewayStatus] {
	routeAttachmentsIndex := krt.NewIndex(routeAttachments, "to", func(o *gatewaycommon.RouteAttachment) []types.NamespacedName {
		return []types.NamespacedName{o.To}
	})
	return krt.NewCollection(
		gatewayStatuses,
		func(ctx krt.HandlerContext, i krt.ObjectWithStatus[*gatewayv1.Gateway, gatewayv1.GatewayStatus],
		) *krt.ObjectWithStatus[*gatewayv1.Gateway, gatewayv1.GatewayStatus] {
			attached := routeAttachmentsIndex.Fetch(ctx, config.NamespacedName(i.Obj))
			counts := map[string]int32{}
			for _, r := range attached {
				counts[r.ListenerName]++
			}
			st := i.Status.DeepCopy()
			for li, s := range st.Listeners {
				s.AttachedRoutes = counts[string(s.Name)]
				st.Listeners[li] = s
			}
			return &krt.ObjectWithStatus[*gatewayv1.Gateway, gatewayv1.GatewayStatus]{
				Obj:    i.Obj,
				Status: *st,
			}
		}, opts.WithName("gwxds/GatewayFinalStatus")...)
}

// SetStatusWrite enables or disables writing Gateway API status when this reconciler holds the status leader lock.
func (c *Controller) SetStatusWrite(enabled bool, statusManager *status.Manager) {
	if enabled && features.EnableGatewayAPIStatus && statusManager != nil {
		var q status.Queue = statusManager.CreateGenericController(func(status status.Manipulator, context any) {
			status.SetInner(context)
		})
		c.status.SetQueue(q)
	} else {
		c.status.UnsetQueue()
	}
}

// Run starts background processes. Call close(stop) to tear down.
func (c *Controller) Run(stop <-chan struct{}) {
	tw := c.tagWatcher.AccessUnprotected()
	go tw.Run(stop)
	go func() {
		kube.WaitForCacheSync("gwxds tag watcher", stop, tw.HasSynced)
		c.tagWatcher.MarkSynced()
	}()

	go func() {
		<-stop
		close(c.stop)
	}()
}

// HasSynced reports whether all collections have synced.
func (c *Controller) HasSynced() bool {
	return c.outputs != nil
}

// gwxdsSupportedGVRs enumerates the GVRs watched by this controller.
var gwxdsSupportedGVRs = sets.New(
	gvr.Namespace,
	gvr.Service,
	gvr.Secret,
	gvr.ConfigMap,
	gvr.GatewayClass,
	gvr.KubernetesGateway,
	gvr.HTTPRoute,
	gvr.GRPCRoute,
	gvr.ListenerSet,
	gvr.ReferenceGrant,
	gvr.ServiceEntry,
	gvr.BackendTLSPolicy,
	gvr.InferencePool,
)

// SupportedGVRs returns the set of GVRs watched by the gwxds controller.
func (c *Controller) SupportedGVRs() sets.Set[schema.GroupVersionResource] {
	return gwxdsSupportedGVRs
}
