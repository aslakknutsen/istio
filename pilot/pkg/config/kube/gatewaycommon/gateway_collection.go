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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"go.uber.org/atomic"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayalpha "sigs.k8s.io/gateway-api/apis/v1alpha2"

	istio "istio.io/api/networking/v1alpha3"
	"istio.io/api/annotation"
	kubecreds "istio.io/istio/pilot/pkg/credentials/kube"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/model/kstatus"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/config/schema/gvk"
	schematypes "istio.io/istio/pkg/config/schema/kubetypes"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/maps"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/revisions"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
)

// addressTypeOverride is an annotation that overrides the address type reported in Gateway status.
const addressTypeOverride = "networking.istio.io/address-type"

var supportedProtocols = sets.New(
	gatewayv1.HTTPProtocolType,
	gatewayv1.HTTPSProtocolType,
	gatewayv1.TLSProtocolType,
	gatewayv1.TCPProtocolType,
	gatewayv1.ProtocolType(protocol.HBONE))

// dummyTLS is a sentinel value sent to proxy instances to signal that they should reject TLS
// connections due to invalid config.
var dummyTLS = &TLSInfo{
	Cert: []byte("invalid"),
	Key:  []byte("invalid"),
}

// SecretReference holds a reference to a Kubernetes secret along with extracted TLS info.
type SecretReference struct {
	Source types.NamespacedName
	Kind   string
	Info   TLSInfo
}

// GatewayListener is the neutral intermediate representation of a single Gateway listener after
// resolving TLS credentials and hostname/namespace access rules.
type GatewayListener struct {
	Name string
	// ParentGateway is the Gateway this listener belongs to
	ParentGateway types.NamespacedName
	// ParentObject is the actual real parent (could be a ListenerSet)
	ParentObject ParentKey
	ParentInfo   ParentInfo
	TLSInfo      *TLSInfo
	Valid        bool
}

func (g GatewayListener) ResourceName() string {
	return g.Name
}

func (g GatewayListener) Equals(other GatewayListener) bool {
	if (g.TLSInfo != nil) != (other.TLSInfo != nil) {
		return false
	}
	if g.TLSInfo != nil {
		if !bytes.Equal(g.TLSInfo.Cert, other.TLSInfo.Cert) ||
			!bytes.Equal(g.TLSInfo.Key, other.TLSInfo.Key) ||
			!bytes.Equal(g.TLSInfo.CaCert, other.TLSInfo.CaCert) {
			return false
		}
	}
	return g.Valid == other.Valid &&
		g.Name == other.Name &&
		g.ParentGateway == other.ParentGateway &&
		g.ParentObject == other.ParentObject &&
		g.ParentInfo.Equals(other.ParentInfo)
}

// ListenerSet is the neutral intermediate representation of a single ListenerSet listener.
type ListenerSet struct {
	Name string `json:"name"`
	// +krtEqualsTodo include parent gateway identity in equality check
	Parent types.NamespacedName `json:"parent"`
	// +krtEqualsTodo ensure parent metadata differences trigger equality
	ParentInfo    ParentInfo           `json:"parentInfo"`
	TLSInfo       *TLSInfo             `json:"tlsInfo"`
	GatewayParent types.NamespacedName `json:"gatewayParent"`
	Valid         bool                 `json:"valid"`
}

func (g ListenerSet) ResourceName() string {
	return g.Name
}

func (g ListenerSet) Equals(other ListenerSet) bool {
	if (g.TLSInfo != nil) != (other.TLSInfo != nil) {
		return false
	}
	if g.TLSInfo != nil {
		if !bytes.Equal(g.TLSInfo.Cert, other.TLSInfo.Cert) ||
			!bytes.Equal(g.TLSInfo.Key, other.TLSInfo.Key) ||
			!bytes.Equal(g.TLSInfo.CaCert, other.TLSInfo.CaCert) {
			return false
		}
	}
	return g.Name == other.Name &&
		g.Parent == other.Parent &&
		g.ParentInfo.Equals(other.ParentInfo) &&
		g.GatewayParent == other.GatewayParent &&
		g.Valid == other.Valid
}

// RouteParents holds information about things routes can reference as parents.
type RouteParents struct {
	gatewayIndex krt.Index[ParentKey, *GatewayListener]
}

func (p RouteParents) fetch(ctx krt.HandlerContext, pk ParentKey) []*ParentInfo {
	return slices.Map(p.gatewayIndex.Fetch(ctx, pk), func(gw *GatewayListener) *ParentInfo {
		return &gw.ParentInfo
	})
}

// BuildRouteParents constructs a RouteParents index over the given GatewayListener collection.
func BuildRouteParents(gateways krt.Collection[*GatewayListener]) RouteParents {
	idx := krt.NewIndex(gateways, "parent", func(o *GatewayListener) []ParentKey {
		return []ParentKey{o.ParentObject}
	})
	return RouteParents{
		gatewayIndex: idx,
	}
}

// ListenerSetCollection builds the collection of ListenerSets.
//
// fetchClass determines which GatewayClass objects are owned by the calling
// controller. Pass FetchAgentgatewayClass for the agentgateway controller and
// FetchGwXdsClass for the gwxds controller.
func ListenerSetCollection(
	listenerSets krt.Collection[*gatewayv1.ListenerSet],
	gateways krt.Collection[*gatewayv1.Gateway],
	gatewayClasses krt.Collection[GatewayClass],
	namespaces krt.Collection[*corev1.Namespace],
	grants ReferenceGrants,
	configMaps krt.Collection[*corev1.ConfigMap],
	secrets krt.Collection[*corev1.Secret],
	domainSuffix string,
	gatewayContext krt.RecomputeProtected[*atomic.Pointer[GatewayContext]],
	tagWatcher krt.RecomputeProtected[revisions.TagWatcher],
	fetchClass ClassFetcher,
	opts krt.OptionsBuilder,
) (
	krt.StatusCollection[*gatewayv1.ListenerSet, gatewayv1.ListenerSetStatus],
	krt.Collection[ListenerSet],
) {
	statusCol, gw := krt.NewStatusManyCollection(listenerSets,
		func(ctx krt.HandlerContext, obj *gatewayv1.ListenerSet) (*gatewayv1.ListenerSetStatus, []ListenerSet) {
			context := gatewayContext.Get(ctx).Load()
			if context == nil {
				return nil, nil
			}
			if !tagWatcher.Get(ctx).IsMine(obj.ObjectMeta) {
				return nil, nil
			}
			result := []ListenerSet{}
			ls := obj.Spec
			status := obj.Status.DeepCopy()

			p := ls.ParentRef
			if NormalizeReference(p.Group, p.Kind, gvk.KubernetesGateway) != gvk.KubernetesGateway {
				return nil, nil
			}

			pns := ptr.OrDefault(p.Namespace, gatewayv1.Namespace(obj.Namespace))
			parentGwObj := ptr.Flatten(krt.FetchOne(ctx, gateways, krt.FilterKey(string(pns)+"/"+string(p.Name))))
			if parentGwObj == nil {
				return nil, nil
			}

			class := fetchClass(ctx, gatewayClasses, parentGwObj.Spec.GatewayClassName)
			if class == nil {
				return nil, nil
			}

			controllerName := class.Controller
			classInfo, f := ClassInfos[controllerName]
			if !f {
				return nil, nil
			}

			if !classInfo.SupportsListenerSet {
				reportUnsupportedListenerSet(class.Name, status, obj)
				return status, nil
			}

			if !NamespaceAcceptedByAllowListeners(obj.Namespace, parentGwObj, func(s string) *corev1.Namespace {
				return ptr.Flatten(krt.FetchOne(ctx, namespaces, krt.FilterKey(s)))
			}) {
				reportNotAllowedListenerSet(status, obj)
				return status, nil
			}

			gatewayServices, err := extractGatewayServices(domainSuffix, parentGwObj, classInfo)
			if len(gatewayServices) == 0 && err != nil {
				reportListenerSetStatus(context, parentGwObj, obj, status, gatewayServices, nil, err)
				return status, nil
			}

			servers := []*istio.Server{}
			for i, l := range ls.Listeners {
				port, portErr := detectListenerPortNumber(l)
				l.Port = port
				standardListener := ConvertListenerSetToListener(l)
				originalStatus := slices.Map(status.Listeners, convertListenerSetStatusToStandardStatus)
				server, tlsInfo, updatedStatus, programmed := buildListener(ctx, secrets, configMaps, grants, namespaces,
					obj, originalStatus, parentGwObj.Spec, standardListener, i, controllerName, portErr)
				status.Listeners = slices.Map(updatedStatus, convertStandardStatusToListenerSetStatus(l))

				servers = append(servers, server)

				if controllerName == constants.ManagedGatewayMeshController || controllerName == constants.ManagedGatewayEastWestController {
					continue
				}
				name := InternalGatewayName(obj.Namespace, obj.Name, string(l.Name))

				allowed, _ := generateSupportedKinds(standardListener)
				pri := ParentInfo{
					ParentGateway:    config.NamespacedName(parentGwObj),
					InternalName:     obj.Namespace + "/" + name,
					AllowedKinds:     allowed,
					Hostnames:        server.Hosts,
					OriginalHostname: string(ptr.OrEmpty(l.Hostname)),
					SectionName:      l.Name,
					Port:             l.Port,
					Protocol:         l.Protocol,
					TLSPassthrough:   l.TLS != nil && l.TLS.Mode != nil && *l.TLS.Mode == gatewayv1.TLSModePassthrough,
				}

				res := ListenerSet{
					Name:          name,
					Valid:         programmed,
					TLSInfo:       tlsInfo,
					Parent:        config.NamespacedName(obj),
					GatewayParent: config.NamespacedName(parentGwObj),
					ParentInfo:    pri,
				}
				result = append(result, res)
			}

			reportListenerSetStatus(context, parentGwObj, obj, status, gatewayServices, servers, err)
			return status, result
		}, opts.WithName("ListenerSets")...)

	return statusCol, gw
}

// ClassFetcher is a function that resolves a GatewayClass by name for a
// particular controller. It returns nil when the class is not owned by that
// controller and the Gateway should be ignored.
type ClassFetcher func(ctx krt.HandlerContext, gatewayClasses krt.Collection[GatewayClass], gc gatewayv1.ObjectName) *GatewayClass

// GatewayCollection builds the collection of GatewayListeners. It translates from the Kubernetes
// Gateway API types to the neutral GatewayListener IR and computes Gateway status.
//
// fetchClass determines which GatewayClass objects are owned by the calling
// controller. Pass FetchAgentgatewayClass for the agentgateway controller and
// FetchGwXdsClass for the gwxds controller.
func GatewayCollection(
	gateways krt.Collection[*gatewayv1.Gateway],
	listenerSets krt.Collection[ListenerSet],
	gatewayClasses krt.Collection[GatewayClass],
	namespaces krt.Collection[*corev1.Namespace],
	grants ReferenceGrants,
	configMaps krt.Collection[*corev1.ConfigMap],
	secrets krt.Collection[*corev1.Secret],
	domainSuffix string,
	gatewayContext krt.RecomputeProtected[*atomic.Pointer[GatewayContext]],
	tagWatcher krt.RecomputeProtected[revisions.TagWatcher],
	fetchClass ClassFetcher,
	opts krt.OptionsBuilder,
) (
	krt.StatusCollection[*gatewayv1.Gateway, gatewayv1.GatewayStatus],
	krt.Collection[*GatewayListener],
) {
	listenerIndex := krt.NewIndex(listenerSets, "gatewayParent", func(o ListenerSet) []types.NamespacedName {
		return []types.NamespacedName{o.GatewayParent}
	})
	gwstatus, gw := krt.NewStatusManyCollection(gateways, func(ctx krt.HandlerContext, obj *gatewayv1.Gateway) (*gatewayv1.GatewayStatus, []*GatewayListener) {
		context := gatewayContext.Get(ctx).Load()
		if context == nil {
			return nil, nil
		}
		if !tagWatcher.Get(ctx).IsMine(obj.ObjectMeta) {
			return nil, nil
		}
		result := []*GatewayListener{}
		kgw := obj.Spec
		status := obj.Status.DeepCopy()

		class := fetchClass(ctx, gatewayClasses, kgw.GatewayClassName)
		if class == nil {
			return nil, nil
		}

		controllerName := class.Controller
		classInfo, f := ClassInfos[controllerName]
		if !f {
			return nil, nil
		}
		if classInfo.DisableRouteGeneration {
			return status, nil
		}
		servers := []*istio.Server{}

		log.Debugf("translating Gateway gw_name: %s, resource_version: %s", obj.GetName(), obj.GetResourceVersion())

		gatewayServices, err := extractGatewayServices(domainSuffix, obj, classInfo)
		if len(gatewayServices) == 0 && err != nil {
			log.Errorf("failed to translate gwv1", "name", obj.GetName(), "namespace", obj.GetNamespace(), "err", err.Error.Message)
			reportGatewayStatus(context, obj, status, classInfo, gatewayServices, servers, 0, err.Error)
			return status, nil
		}
		var gatewayErr *ConfigError
		if err != nil {
			gatewayErr = err.Error
		}

		for i, l := range kgw.Listeners {
			server, tlsInfo, updatedStatus, programmed := buildListener(
				ctx, secrets, configMaps, grants, namespaces, obj, status.Listeners, kgw, l, i, controllerName, nil)
			status.Listeners = updatedStatus

			servers = append(servers, server)

			allowed, _ := generateSupportedKinds(l)

			name := InternalGatewayName(obj.Namespace, obj.Name, string(l.Name))
			pri := ParentInfo{
				ParentGateway:          config.NamespacedName(obj),
				ParentGatewayClassName: string(obj.Spec.GatewayClassName),
				InternalName:           InternalGatewayName(obj.Namespace, name, ""),
				AllowedKinds:           allowed,
				Hostnames:              server.Hosts,
				OriginalHostname:       string(ptr.OrEmpty(l.Hostname)),
				SectionName:            l.Name,
				Port:                   l.Port,
				Protocol:               l.Protocol,
				TLSPassthrough:         l.TLS != nil && l.TLS.Mode != nil && *l.TLS.Mode == gatewayv1.TLSModePassthrough,
			}

			res := &GatewayListener{
				Name:          name,
				Valid:         programmed,
				TLSInfo:       tlsInfo,
				ParentGateway: config.NamespacedName(obj),
				ParentObject: ParentKey{
					Kind:      gvk.KubernetesGateway,
					Name:      obj.Name,
					Namespace: obj.Namespace,
				},
				ParentInfo: pri,
			}
			result = append(result, res)
		}
		listenersFromSets := listenerIndex.Fetch(ctx, config.NamespacedName(obj))
		for _, ls := range listenersFromSets {
			result = append(result, &GatewayListener{
				Name:          ls.Name,
				ParentGateway: config.NamespacedName(obj),
				ParentObject: ParentKey{
					Kind:      gvk.ListenerSet,
					Name:      ls.Parent.Name,
					Namespace: ls.Parent.Namespace,
				},
				TLSInfo:    ls.TLSInfo,
				ParentInfo: ls.ParentInfo,
				Valid:      ls.Valid,
			})
		}

		reportGatewayStatus(context, obj, status, classInfo, gatewayServices, servers, len(listenersFromSets), gatewayErr)
		return status, result
	}, opts.WithName("KubernetesGateway")...)

	return gwstatus, gw
}

// InternalGatewayName returns the name of the internal Gateway corresponding to the
// specified gwv1-api Gateway and listener. If the listener is not specified, returns the
// internal name without the listener suffix.
// Format: gwNs/gwName.listener
func InternalGatewayName(gwNamespace, gwName, lName string) string {
	if lName == "" {
		return fmt.Sprintf("%s/%s", gwNamespace, gwName)
	}
	return fmt.Sprintf("%s/%s.%s", gwNamespace, gwName, lName)
}

func detectListenerPortNumber(l gatewayv1.ListenerEntry) (gatewayv1.PortNumber, error) {
	if l.Port != 0 {
		return l.Port, nil
	}
	switch l.Protocol {
	case gatewayv1.HTTPProtocolType:
		return 80, nil
	case gatewayv1.HTTPSProtocolType:
		return 443, nil
	}
	return 0, fmt.Errorf("protocol %v requires a port to be set", l.Protocol)
}

func convertStandardStatusToListenerSetStatus(l gatewayv1.ListenerEntry) func(e gatewayv1.ListenerStatus) gatewayv1.ListenerEntryStatus {
	return func(e gatewayv1.ListenerStatus) gatewayv1.ListenerEntryStatus {
		return gatewayv1.ListenerEntryStatus(e)
	}
}

func convertListenerSetStatusToStandardStatus(e gatewayv1.ListenerEntryStatus) gatewayv1.ListenerStatus {
	return gatewayv1.ListenerStatus(e)
}

// SecretAllowed checks whether a reference to a Secret from the given gateway namespace is
// permitted by existing ReferenceGrants.
func SecretAllowed(
	refs ReferenceGrants,
	ctx krt.HandlerContext,
	kind config.GroupVersionKind,
	resourceName types.NamespacedName,
	namespace string,
) bool {
	from := Reference{Kind: kind, Namespace: gatewayv1.Namespace(namespace)}
	to := Reference{Kind: gvk.Secret, Namespace: gatewayv1.Namespace(resourceName.Namespace)}
	pair := ReferencePair{From: from, To: to}
	grants := krt.FetchOrList(ctx, refs.Collection, krt.FilterIndex(refs.Index, pair))
	for _, g := range grants {
		if g.AllowAll || g.AllowedName == resourceName.Name {
			return true
		}
	}
	return false
}

// GetCommonRouteInfo extracts parent references, hostnames, and GVK from a route resource.
func GetCommonRouteInfo(spec any) ([]gatewayv1.ParentReference, []gatewayv1.Hostname, config.GroupVersionKind) {
	switch t := spec.(type) {
	case *gatewayalpha.TCPRoute:
		return t.Spec.ParentRefs, nil, gvk.TCPRoute
	case *gatewayv1.TLSRoute:
		return t.Spec.ParentRefs, t.Spec.Hostnames, gvk.TLSRoute
	case *gatewayv1.HTTPRoute:
		return t.Spec.ParentRefs, t.Spec.Hostnames, gvk.HTTPRoute
	case *gatewayv1.GRPCRoute:
		return t.Spec.ParentRefs, t.Spec.Hostnames, gvk.GRPCRoute
	default:
		log.Fatalf("unknown type %T", t)
		return nil, nil, config.GroupVersionKind{}
	}
}

// GetCommonRouteStateParents extracts the current status parents from a route object.
func GetCommonRouteStateParents(spec any) []gatewayv1.RouteParentStatus {
	switch t := spec.(type) {
	case *gatewayalpha.TCPRoute:
		return t.Status.Parents
	case *gatewayv1.TLSRoute:
		return t.Status.Parents
	case *gatewayv1.HTTPRoute:
		return t.Status.Parents
	case *gatewayv1.GRPCRoute:
		return t.Status.Parents
	default:
		log.Fatalf("unknown type %T", t)
		return nil
	}
}

// --- buildListener and TLS helpers ---

// buildListener constructs the listener components of a listener in a Gateway spec.
func buildListener(
	ctx krt.HandlerContext,
	secrets krt.Collection[*corev1.Secret],
	configMaps krt.Collection[*corev1.ConfigMap],
	grants ReferenceGrants,
	namespaces krt.Collection[*corev1.Namespace],
	obj controllers.Object,
	status []gatewayv1.ListenerStatus,
	gw gatewayv1.GatewaySpec,
	l gatewayv1.Listener,
	listenerIndex int,
	controllerName gatewayv1.GatewayController,
	portErr error,
) (*istio.Server, *TLSInfo, []gatewayv1.ListenerStatus, bool) {
	listenerConditions := map[string]*Condition{
		string(gatewayv1.ListenerConditionAccepted): {
			Reason:  string(gatewayv1.ListenerReasonAccepted),
			Message: "No errors found",
		},
		string(gatewayv1.ListenerConditionProgrammed): {
			Reason:  string(gatewayv1.ListenerReasonProgrammed),
			Message: "No errors found",
		},
		string(gatewayv1.ListenerConditionConflicted): {
			Reason:  string(gatewayv1.ListenerReasonNoConflicts),
			Message: "No errors found",
			Status:  kstatus.StatusFalse,
		},
		string(gatewayv1.ListenerConditionResolvedRefs): {
			Reason:  string(gatewayv1.ListenerReasonResolvedRefs),
			Message: "No errors found",
		},
	}

	ok := true
	gwTLS := resolveGatewayTLS(l.Port, gw.TLS)
	tlsInfo, err := buildTLS(ctx, secrets, configMaps, grants, gwTLS, l.TLS, obj)
	if err == nil && tlsInfo != nil {
		err = validateTLS(tlsInfo)
	}
	if err != nil {
		listenerConditions[string(gatewayv1.ListenerConditionResolvedRefs)].Error = err
		listenerConditions[string(gatewayv1.GatewayConditionProgrammed)].Error = &ConfigError{
			Reason:  string(gatewayv1.GatewayReasonInvalid),
			Message: "Bad TLS configuration",
		}
		ok = false
	}
	if portErr != nil {
		listenerConditions[string(gatewayv1.ListenerConditionAccepted)].Error = &ConfigError{
			Reason:  string(gatewayv1.ListenerReasonUnsupportedProtocol),
			Message: portErr.Error(),
		}
		ok = false
	}

	hostnames := buildHostnameMatch(ctx, obj.GetNamespace(), namespaces, l)
	_, perr := listenerProtocolToIstio(controllerName, l.Protocol)
	if perr != nil {
		listenerConditions[string(gatewayv1.ListenerConditionAccepted)].Error = &ConfigError{
			Reason:  string(gatewayv1.ListenerReasonUnsupportedProtocol),
			Message: perr.Error(),
		}
		ok = false
	}

	server := &istio.Server{
		Port: &istio.Port{
			Name:   "default",
			Number: uint32(l.Port),
		},
		Hosts: hostnames,
	}

	updatedStatus := reportListenerCondition(listenerIndex, l, obj, status, listenerConditions)
	return server, tlsInfo, updatedStatus, ok
}

func listenerProtocolToIstio(name gatewayv1.GatewayController, p gatewayv1.ProtocolType) (string, error) {
	switch p {
	case gatewayv1.HTTPProtocolType:
		return string(p), nil
	case gatewayv1.HTTPSProtocolType:
		return string(p), nil
	case gatewayv1.TLSProtocolType:
		return string(p), nil
	case gatewayv1.TCPProtocolType:
		if !features.EnableAlphaGatewayAPI {
			return "", fmt.Errorf("protocol %q is supported, but only when %v=true is configured", p, features.EnableAlphaGatewayAPIName)
		}
		return string(p), nil
	case gatewayv1.ProtocolType(protocol.HBONE):
		if name != constants.ManagedGatewayMeshController && name != constants.ManagedGatewayEastWestController {
			return "", fmt.Errorf("protocol %q is only supported for waypoint proxies", p)
		}
		return string(p), nil
	}
	up := gatewayv1.ProtocolType(strings.ToUpper(string(p)))
	if supportedProtocols.Contains(up) {
		return "", fmt.Errorf("protocol %q is unsupported. hint: %q (uppercase) may be supported", p, up)
	}
	return "", fmt.Errorf("protocol %q is unsupported", p)
}

func buildHostnameMatch(ctx krt.HandlerContext, localNamespace string, namespaces krt.Collection[*corev1.Namespace], l gatewayv1.Listener) []string {
	hostname := "*"
	if l.Hostname != nil {
		hostname = string(*l.Hostname)
	}

	resp := []string{}
	for _, ns := range namespacesFromSelectorKrt(ctx, localNamespace, namespaces, l.AllowedRoutes) {
		if len(ns) > 0 {
			resp = append(resp, fmt.Sprintf("%s/%s", ns, hostname))
		}
	}

	if len(resp) == 0 {
		return []string{"~/" + hostname}
	}
	return resp
}

func namespacesFromSelectorKrt(
	ctx krt.HandlerContext,
	localNamespace string,
	namespaceCol krt.Collection[*corev1.Namespace],
	lr *gatewayv1.AllowedRoutes,
) []string {
	if lr == nil || lr.Namespaces == nil || lr.Namespaces.From == nil || *lr.Namespaces.From == gatewayv1.NamespacesFromSame {
		return []string{localNamespace}
	}
	if *lr.Namespaces.From == gatewayv1.NamespacesFromAll {
		return []string{"*"}
	}

	if lr.Namespaces.Selector == nil {
		return []string{"*"}
	}

	ls, err := metav1.LabelSelectorAsSelector(lr.Namespaces.Selector)
	if err != nil {
		return nil
	}
	namespaces := []string{}
	namespaceObjects := krt.Fetch(ctx, namespaceCol)
	for _, ns := range namespaceObjects {
		if ls.Matches(toNamespaceSet(ns.Name, ns.Labels)) {
			namespaces = append(namespaces, ns.Name)
		}
	}
	sort.Strings(namespaces)
	return namespaces
}

func resolveGatewayTLS(port gatewayv1.PortNumber, gw *gatewayv1.GatewayTLSConfig) *gatewayv1.TLSConfig {
	if gw == nil || gw.Frontend == nil {
		return nil
	}
	f := gw.Frontend
	pp := slices.FindFunc(f.PerPort, func(portConfig gatewayv1.TLSPortConfig) bool {
		return portConfig.Port == port
	})
	if pp != nil {
		return &pp.TLS
	}
	return &f.Default
}

func buildTLS(
	ctx krt.HandlerContext,
	secrets krt.Collection[*corev1.Secret],
	configMaps krt.Collection[*corev1.ConfigMap],
	grants ReferenceGrants,
	gatewayTLS *gatewayv1.TLSConfig,
	tlsCfg *gatewayv1.ListenerTLSConfig,
	gw controllers.Object,
) (*TLSInfo, *ConfigError) {
	if tlsCfg == nil {
		return nil, nil
	}
	mode := gatewayv1.TLSModeTerminate
	if tlsCfg.Mode != nil {
		mode = *tlsCfg.Mode
	}
	namespace := gw.GetNamespace()
	switch mode {
	case gatewayv1.TLSModeTerminate:
		if len(tlsCfg.CertificateRefs) != 1 {
			return dummyTLS, &ConfigError{Reason: InvalidTLS, Message: "exactly 1 certificateRefs should be present for TLS termination"}
		}
		tlsRes, err := buildSecretReference(ctx, tlsCfg.CertificateRefs[0], gw, secrets)
		if err != nil {
			return dummyTLS, err
		}
		sameNamespace := tlsRes.Source.Namespace == namespace
		objectKind := schematypes.GvkFromObject(gw)
		if !sameNamespace && !SecretAllowed(grants, ctx, objectKind, tlsRes.Source, namespace) {
			return dummyTLS, &ConfigError{
				Reason: InvalidListenerRefNotPermitted,
				Message: fmt.Sprintf(
					"certificateRef %v/%v not accessible to a Gateway in namespace %q (missing a ReferenceGrant?)",
					tlsCfg.CertificateRefs[0].Name, tlsRes.Source.Namespace, namespace,
				),
			}
		}

		if gatewayTLS != nil && gatewayTLS.Validation != nil && len(gatewayTLS.Validation.CACertificateRefs) > 0 {
			if len(gatewayTLS.Validation.CACertificateRefs) > 1 {
				return dummyTLS, &ConfigError{
					Reason:  InvalidTLS,
					Message: "only one caCertificateRef is supported",
				}
			}
			caCertRef := gatewayTLS.Validation.CACertificateRefs[0]
			cred, err := buildCaCertificateReference(ctx, caCertRef, gw, configMaps, secrets)
			if err != nil {
				return dummyTLS, err
			}
			sameNamespace := cred.Source.Namespace == namespace
			isSecret := cred.Kind == gvk.Secret.Kind
			if isSecret && !sameNamespace && !SecretAllowed(grants, ctx, schematypes.GvkFromObject(gw), cred.Source, namespace) {
				return dummyTLS, &ConfigError{
					Reason: InvalidListenerRefNotPermitted,
					Message: fmt.Sprintf(
						"caCertificateRef %v/%v not accessible to a Gateway in namespace %q (missing a ReferenceGrant?)",
						cred.Source.Namespace, caCertRef.Name, namespace,
					),
				}
			}
			tlsRes.Info.CaCert = cred.Info.CaCert
		}
		return &tlsRes.Info, nil
	case gatewayv1.TLSModePassthrough:
		return nil, nil
	}
	return nil, nil
}

func buildCaCertificateReference(
	ctx krt.HandlerContext,
	ref gatewayv1.ObjectReference,
	gw controllers.Object,
	configMaps krt.Collection[*corev1.ConfigMap],
	secrets krt.Collection[*corev1.Secret],
) (*SecretReference, *ConfigError) {
	namespace := ptr.OrDefault((*string)(ref.Namespace), gw.GetNamespace())
	name := string(ref.Name)
	res := SecretReference{
		Source: types.NamespacedName{
			Namespace: namespace,
			Name:      name,
		},
		Info: TLSInfo{},
	}

	switch NormalizeReference(&ref.Group, &ref.Kind, config.GroupVersionKind{}) {
	case gvk.ConfigMap:
		res.Kind = gvk.ConfigMap.Kind
		cm := ptr.Flatten(krt.FetchOne(ctx, configMaps, krt.FilterObjectName(res.Source)))
		if cm == nil {
			return nil, &ConfigError{
				Reason:  InvalidTLS,
				Message: fmt.Sprintf("invalid CA certificate reference, configmap %v not found", res.Source),
			}
		}
		certInfo, err := kubecreds.ExtractRootFromString(cm.Data)
		if err != nil {
			return nil, &ConfigError{
				Reason:  InvalidTLS,
				Message: fmt.Sprintf("invalid CA certificate reference %v, %v", plainObjectReferenceString(ref), err),
			}
		}
		res.Info.CaCert = certInfo.Cert
	case gvk.Secret:
		res.Kind = gvk.Secret.Kind
		scrt := ptr.Flatten(krt.FetchOne(ctx, secrets, krt.FilterObjectName(res.Source)))
		if scrt == nil {
			return nil, &ConfigError{
				Reason:  InvalidTLS,
				Message: fmt.Sprintf("invalid CA certificate reference, secret %v not found", res.Source),
			}
		}
		certInfo, err := kubecreds.ExtractRoot(scrt.Data)
		if err != nil {
			return nil, &ConfigError{
				Reason:  InvalidTLS,
				Message: fmt.Sprintf("invalid CA certificate reference %v, %v", plainObjectReferenceString(ref), err),
			}
		}
		res.Info.CaCert = certInfo.Cert
	default:
		return nil, &ConfigError{
			Reason:  InvalidTLS,
			Message: fmt.Sprintf("invalid CA certificate reference %v, only secret and configmap are allowed", plainObjectReferenceString(ref)),
		}
	}

	return &res, nil
}

func buildSecretReference(
	ctx krt.HandlerContext,
	ref gatewayv1.SecretObjectReference,
	gw controllers.Object,
	secrets krt.Collection[*corev1.Secret],
) (*SecretReference, *ConfigError) {
	if NormalizeReference(ref.Group, ref.Kind, gvk.Secret) != gvk.Secret {
		return nil, &ConfigError{
			Reason:  InvalidTLS,
			Message: fmt.Sprintf("invalid certificate reference %v, only secret is allowed", secretObjectReferenceString(ref)),
		}
	}

	secret := types.NamespacedName{
		Name:      string(ref.Name),
		Namespace: ptr.OrDefault((*string)(ref.Namespace), gw.GetNamespace()),
	}

	scrt := ptr.Flatten(krt.FetchOne(ctx, secrets, krt.FilterObjectName(secret)))
	if scrt == nil {
		return nil, &ConfigError{
			Reason:  InvalidTLS,
			Message: fmt.Sprintf("invalid certificate reference %v, secret not found", secretObjectReferenceString(ref)),
		}
	}
	certInfo, err := kubecreds.ExtractCertInfo(scrt)
	if err != nil {
		return nil, &ConfigError{
			Reason:  InvalidTLS,
			Message: fmt.Sprintf("invalid certificate reference %v, %v", secretObjectReferenceString(ref), err),
		}
	}
	res := SecretReference{
		Source: secret,
		Kind:   gvk.Secret.Kind,
		Info: TLSInfo{
			Cert: certInfo.Cert,
			Key:  certInfo.Key,
		},
	}
	return &res, nil
}

func plainObjectReferenceString(ref gatewayv1.ObjectReference) string {
	return fmt.Sprintf("%s/%s/%s.%s", ref.Group, ref.Kind, ref.Name, ptr.OrEmpty(ref.Namespace))
}

func secretObjectReferenceString(ref gatewayv1.SecretObjectReference) string {
	return fmt.Sprintf("%s/%s/%s.%s",
		ptr.OrEmpty(ref.Group),
		ptr.OrEmpty(ref.Kind),
		ref.Name,
		ptr.OrEmpty(ref.Namespace))
}

func validateTLS(certInfo *TLSInfo) *ConfigError {
	if _, err := tls.X509KeyPair(certInfo.Cert, certInfo.Key); err != nil {
		return &ConfigError{
			Reason:  InvalidTLS,
			Message: fmt.Sprintf("invalid certificate reference, the certificate is malformed: %v", err),
		}
	}
	if certInfo.CaCert != nil {
		if !x509.NewCertPool().AppendCertsFromPEM(certInfo.Cert) {
			return &ConfigError{
				Reason:  InvalidTLS,
				Message: "invalid CA certificate reference, the bundle is malformed",
			}
		}
	}
	return nil
}

// --- Status reporting helpers ---

func extractGatewayServices(domainSuffix string, kgw *gatewayv1.Gateway, info ClassInfo) ([]string, *Condition) {
	if IsManaged(&kgw.Spec) {
		name := model.GetOrDefault(kgw.Annotations[annotation.GatewayNameOverride.Name], GetDefaultName(kgw.Name, &kgw.Spec, info.DisableNameSuffix))
		return []string{fmt.Sprintf("%s.%s.svc.%v", name, kgw.Namespace, domainSuffix)}, nil
	}
	gatewayServices := []string{}
	skippedAddresses := []string{}
	for _, addr := range kgw.Spec.Addresses {
		if addr.Type != nil && *addr.Type != gatewayv1.HostnameAddressType {
			skippedAddresses = append(skippedAddresses, addr.Value)
			continue
		}
		fqdn := addr.Value
		if !strings.Contains(fqdn, ".") {
			fqdn = fmt.Sprintf("%s.%s.svc.%s", fqdn, kgw.Namespace, domainSuffix)
		}
		gatewayServices = append(gatewayServices, fqdn)
	}
	if len(skippedAddresses) > 0 {
		return gatewayServices, &Condition{
			Status: metav1.ConditionFalse,
			Error: &ConfigError{
				Reason:  InvalidAddress,
				Message: fmt.Sprintf("only Hostname is supported, ignoring %v", skippedAddresses),
			},
		}
	}
	if _, f := kgw.Annotations[annotation.NetworkingServiceType.Name]; f {
		return gatewayServices, &Condition{
			Status: metav1.ConditionFalse,
			Error: &ConfigError{
				Reason:  DeprecateFieldUsage,
				Message: fmt.Sprintf("annotation %v is deprecated, use Spec.Infrastructure.Routeability", annotation.NetworkingServiceType.Name),
			},
		}
	}
	return gatewayServices, nil
}

func reportGatewayStatus(
	r *GatewayContext,
	obj *gatewayv1.Gateway,
	gs *gatewayv1.GatewayStatus,
	classInfo ClassInfo,
	gatewayServices []string,
	servers []*istio.Server,
	listenerSetCount int,
	gatewayErr *ConfigError,
) {
	internal, internalIP, external, pending, warnings, allUsable := r.ResolveGatewayInstances(obj.Namespace, gatewayServices, servers)

	gatewayConditions := map[string]*Condition{
		string(gatewayv1.GatewayConditionAccepted): {
			Reason:  string(gatewayv1.GatewayReasonAccepted),
			Message: "Resource accepted",
		},
		string(gatewayv1.GatewayConditionProgrammed): {
			Reason:  string(gatewayv1.GatewayReasonProgrammed),
			Message: "Resource programmed",
		},
	}
	if gatewayErr != nil {
		gatewayConditions[string(gatewayv1.GatewayConditionAccepted)].Error = gatewayErr
	}

	const AttachedListenerSets = "AttachedListenerSets"
	if obj.Spec.AllowedListeners != nil {
		gatewayConditions[AttachedListenerSets] = &Condition{
			Reason:  "ListenersAttached",
			Message: "At least one ListenerSet is attached",
		}
		if !features.EnableAlphaGatewayAPI {
			gatewayConditions[AttachedListenerSets].Error = &ConfigError{
				Reason: "Unsupported",
				Message: fmt.Sprintf("AllowedListeners is configured, but ListenerSets are not enabled (set %v=true)",
					features.EnableAlphaGatewayAPIName),
			}
		} else if listenerSetCount == 0 {
			gatewayConditions[AttachedListenerSets].Error = &ConfigError{
				Reason:  "NoListenersAttached",
				Message: "AllowedListeners is configured, but no ListenerSets are attached",
			}
		}
	}

	setProgrammedCondition(gatewayConditions, internal, gatewayServices, warnings, allUsable)

	addressesToReport := external
	if len(addressesToReport) == 0 {
		wantAddressType := classInfo.AddressType
		if override, ok := obj.Annotations[addressTypeOverride]; ok {
			wantAddressType = gatewayv1.AddressType(override)
		}
		if wantAddressType != gatewayv1.HostnameAddressType {
			addressesToReport = internalIP
		}
		if wantAddressType != gatewayv1.IPAddressType {
			for _, hostport := range internal {
				svchost, _, _ := net.SplitHostPort(hostport)
				if !slices.Contains(pending, svchost) && !slices.Contains(addressesToReport, svchost) {
					addressesToReport = append(addressesToReport, svchost)
				}
			}
		}
	}
	if len(addressesToReport) > 0 {
		gs.Addresses = make([]gatewayv1.GatewayStatusAddress, 0, len(addressesToReport))
		for _, addr := range addressesToReport {
			var addrType gatewayv1.AddressType
			if _, err := netip.ParseAddr(addr); err == nil {
				addrType = gatewayv1.IPAddressType
			} else {
				addrType = gatewayv1.HostnameAddressType
			}
			gs.Addresses = append(gs.Addresses, gatewayv1.GatewayStatusAddress{
				Value: addr,
				Type:  &addrType,
			})
		}
	}
	haveListeners := getListenerNames(&obj.Spec)
	listeners := make([]gatewayv1.ListenerStatus, 0, len(gs.Listeners))
	for _, l := range gs.Listeners {
		if haveListeners.Contains(l.Name) {
			haveListeners.Delete(l.Name)
			listeners = append(listeners, l)
		}
	}
	gs.Listeners = listeners
	gs.Conditions = SetConditions(obj.Generation, gs.Conditions, gatewayConditions)
}

func setProgrammedCondition(gatewayConditions map[string]*Condition, internal []string, gatewayServices []string, warnings []string, allUsable bool) {
	if len(internal) > 0 {
		msg := fmt.Sprintf("Resource programmed, assigned to service(s) %s", humanReadableJoin(internal))
		gatewayConditions[string(gatewayv1.GatewayConditionProgrammed)].Message = msg
	}

	if len(gatewayServices) == 0 {
		gatewayConditions[string(gatewayv1.GatewayConditionProgrammed)].Error = &ConfigError{
			Reason:  InvalidAddress,
			Message: "Failed to assign to any requested addresses",
		}
	} else if len(warnings) > 0 {
		var msg string
		var reason string
		if len(internal) != 0 {
			msg = fmt.Sprintf("Assigned to service(s) %s, but failed to assign to all requested addresses: %s",
				humanReadableJoin(internal), strings.Join(warnings, "; "))
		} else {
			msg = fmt.Sprintf("Failed to assign to any requested addresses: %s", strings.Join(warnings, "; "))
		}
		if allUsable {
			reason = string(gatewayv1.GatewayReasonAddressNotAssigned)
		} else {
			reason = string(gatewayv1.GatewayReasonAddressNotUsable)
		}
		gatewayConditions[string(gatewayv1.GatewayConditionProgrammed)].Error = &ConfigError{
			Reason:  reason,
			Message: msg,
		}
	}
}

func reportListenerSetStatus(
	r *GatewayContext,
	parentGwObj *gatewayv1.Gateway,
	obj *gatewayv1.ListenerSet,
	gs *gatewayv1.ListenerSetStatus,
	gatewayServices []string,
	servers []*istio.Server,
	cond *Condition,
) {
	internal, _, _, _, warnings, allUsable := r.ResolveGatewayInstances(parentGwObj.Namespace, gatewayServices, servers)

	gatewayConditions := map[string]*Condition{
		string(gatewayv1.GatewayConditionAccepted): {
			Reason:  string(gatewayv1.GatewayReasonAccepted),
			Message: "Resource accepted",
		},
		string(gatewayv1.GatewayConditionProgrammed): {
			Reason:  string(gatewayv1.GatewayReasonProgrammed),
			Message: "Resource programmed",
		},
	}
	if cond != nil && cond.Error != nil {
		cond.Error.Message = "Parent not accepted: " + cond.Error.Message
		gatewayConditions[string(gatewayv1.GatewayConditionAccepted)].Error = cond.Error
	}

	setProgrammedCondition(gatewayConditions, internal, gatewayServices, warnings, allUsable)

	gs.Conditions = SetConditions(obj.Generation, gs.Conditions, gatewayConditions)
}

func reportUnsupportedListenerSet(class string, status *gatewayv1.ListenerSetStatus, obj *gatewayv1.ListenerSet) {
	gatewayConditions := map[string]*Condition{
		string(gatewayv1.GatewayConditionAccepted): {
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.GatewayReasonAccepted),
			Error: &ConfigError{
				Reason:  string(gatewayv1.ListenerSetReasonNotAllowed),
				Message: fmt.Sprintf("The %q GatewayClass does not support ListenerSet", class),
			},
		},
		string(gatewayv1.GatewayConditionProgrammed): {
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.GatewayReasonProgrammed),
			Error: &ConfigError{
				Reason:  string(gatewayv1.ListenerSetReasonNotAllowed),
				Message: fmt.Sprintf("The %q GatewayClass does not support ListenerSet", class),
			},
		},
	}
	status.Listeners = nil
	status.Conditions = SetConditions(obj.Generation, status.Conditions, gatewayConditions)
}

func reportNotAllowedListenerSet(status *gatewayv1.ListenerSetStatus, obj *gatewayv1.ListenerSet) {
	gatewayConditions := map[string]*Condition{
		string(gatewayv1.GatewayConditionAccepted): {
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.GatewayReasonAccepted),
			Error: &ConfigError{
				Reason:  string(gatewayv1.ListenerSetReasonNotAllowed),
				Message: "The parent Gateway does not allow this reference; check the 'spec.allowedRoutes'",
			},
		},
		string(gatewayv1.GatewayConditionProgrammed): {
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.GatewayReasonProgrammed),
			Error: &ConfigError{
				Reason:  string(gatewayv1.ListenerSetReasonNotAllowed),
				Message: "The parent Gateway does not allow this reference; check the 'spec.allowedRoutes'",
			},
		},
	}
	status.Listeners = nil
	status.Conditions = SetConditions(obj.Generation, status.Conditions, gatewayConditions)
}

func humanReadableJoin(ss []string) string {
	switch len(ss) {
	case 0:
		return ""
	case 1:
		return ss[0]
	case 2:
		return ss[0] + " and " + ss[1]
	default:
		return strings.Join(ss[:len(ss)-1], ", ") + ", and " + ss[len(ss)-1]
	}
}

func getListenerNames(spec *gatewayv1.GatewaySpec) sets.Set[gatewayv1.SectionName] {
	res := sets.New[gatewayv1.SectionName]()
	for _, l := range spec.Listeners {
		res.Insert(l.Name)
	}
	return res
}

func toRouteKind(g config.GroupVersionKind) gatewayv1.RouteGroupKind {
	return gatewayv1.RouteGroupKind{Group: (*gatewayv1.Group)(&g.Group), Kind: gatewayv1.Kind(g.Kind)}
}

func routeGroupKindEqual(rgk1, rgk2 gatewayv1.RouteGroupKind) bool {
	return rgk1.Kind == rgk2.Kind && getGroup(rgk1) == getGroup(rgk2)
}

func getGroup(rgk gatewayv1.RouteGroupKind) gatewayv1.Group {
	return ptr.OrDefault(rgk.Group, gatewayv1.GroupName)
}

// --- Condition helpers ---

// SetConditions sets the existingConditions with the new conditions.
func SetConditions(generation int64, existingConditions []metav1.Condition, conditions map[string]*Condition) []metav1.Condition {
	for _, k := range slices.Sort(maps.Keys(conditions)) {
		cond := conditions[k]
		setter := kstatus.UpdateConditionIfChanged
		if cond.SetOnce != "" {
			setter = func(conditions []metav1.Condition, condition metav1.Condition) []metav1.Condition {
				return kstatus.CreateCondition(conditions, condition, cond.SetOnce)
			}
		}
		if cond.Error != nil {
			existingConditions = setter(existingConditions, metav1.Condition{
				Type:               k,
				Status:             kstatus.InvertStatus(cond.Status),
				ObservedGeneration: generation,
				LastTransitionTime: metav1.Now(),
				Reason:             cond.Error.Reason,
				Message:            cond.Error.Message,
			})
		} else {
			status := cond.Status
			if status == "" {
				status = kstatus.StatusTrue
			}
			existingConditions = setter(existingConditions, metav1.Condition{
				Type:               k,
				Status:             status,
				ObservedGeneration: generation,
				LastTransitionTime: metav1.Now(),
				Reason:             cond.Reason,
				Message:            cond.Message,
			})
		}
	}
	return existingConditions
}

func generateSupportedKinds(l gatewayv1.Listener) ([]gatewayv1.RouteGroupKind, bool) {
	supported := []gatewayv1.RouteGroupKind{}
	switch l.Protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		supported = []gatewayv1.RouteGroupKind{
			toRouteKind(gvk.HTTPRoute),
			toRouteKind(gvk.GRPCRoute),
		}
	case gatewayv1.TCPProtocolType:
		supported = []gatewayv1.RouteGroupKind{toRouteKind(gvk.TCPRoute)}
	case gatewayv1.TLSProtocolType:
		supported = []gatewayv1.RouteGroupKind{toRouteKind(gvk.TLSRoute)}
		if l.TLS != nil && l.TLS.Mode != nil && *l.TLS.Mode == gatewayv1.TLSModeTerminate {
			supported = append(supported, toRouteKind(gvk.TCPRoute))
		}
	}
	if l.AllowedRoutes != nil && len(l.AllowedRoutes.Kinds) > 0 {
		intersection := []gatewayv1.RouteGroupKind{}
		for _, s := range supported {
			for _, kind := range l.AllowedRoutes.Kinds {
				if routeGroupKindEqual(s, kind) {
					intersection = append(intersection, s)
					break
				}
			}
		}
		return intersection, len(intersection) == len(l.AllowedRoutes.Kinds)
	}
	return supported, true
}

func reportListenerCondition(
	index int,
	l gatewayv1.Listener,
	obj controllers.Object,
	statusListeners []gatewayv1.ListenerStatus,
	conditions map[string]*Condition,
) []gatewayv1.ListenerStatus {
	for index >= len(statusListeners) {
		statusListeners = append(statusListeners, gatewayv1.ListenerStatus{})
	}
	cond := statusListeners[index].Conditions
	supported, valid := generateSupportedKinds(l)
	if !valid {
		conditions[string(gatewayv1.ListenerConditionResolvedRefs)] = &Condition{
			Reason:  string(gatewayv1.ListenerReasonInvalidRouteKinds),
			Status:  metav1.ConditionFalse,
			Message: "Invalid route kinds",
		}
	}
	statusListeners[index] = gatewayv1.ListenerStatus{
		Name:           l.Name,
		AttachedRoutes: 0,
		SupportedKinds: supported,
		Conditions:     SetConditions(obj.GetGeneration(), cond, conditions),
	}
	return statusListeners
}

// FilterInPlaceByIndex filters a slice in place, keeping only elements at indices where keep returns true.
func FilterInPlaceByIndex[E any](s []E, keep func(int) bool) []E {
	i := 0
	for j := 0; j < len(s); j++ {
		if keep(j) {
			s[i] = s[j]
			i++
		}
	}
	clear(s[i:])
	return s[:i]
}

// RouteParentResult holds the result of a route for a specific parent.
type RouteParentResult struct {
	OriginalReference gatewayv1.ParentReference
	DeniedReason      *ParentError
	RouteError        *Condition
}

// CreateRouteStatus builds the RouteParentStatus slice from route parent results.
func CreateRouteStatus(
	parentResults []RouteParentResult,
	objectNamespace string,
	generation int64,
	controllerName string,
	currentParents []gatewayv1.RouteParentStatus,
) []gatewayv1.RouteParentStatus {
	parents := slices.Clone(currentParents)
	parentIndexes := map[string]int{}
	for idx, p := range parents {
		if p.ControllerName != gatewayv1.GatewayController(controllerName) {
			continue
		}
		rs := parentRefStringWithNS(p.ParentRef, objectNamespace)
		if _, f := parentIndexes[rs]; f {
			log.Warnf("invalid route detected: duplicate parent: %v", rs)
		} else {
			parentIndexes[rs] = idx
		}
	}

	seen := map[gatewayv1.ParentReference][]RouteParentResult{}
	successCount := map[gatewayv1.ParentReference]int{}
	for _, incoming := range parentResults {
		if incoming.DeniedReason == nil {
			successCount[incoming.OriginalReference]++
		}
		seen[incoming.OriginalReference] = append(seen[incoming.OriginalReference], incoming)
	}

	const (
		rankNoErrors = iota
		rankNotAllowed
		rankNoHostname
		rankParentRefConflict
		rankNotAccepted
	)

	rankError := func(result RouteParentResult) int {
		if result.DeniedReason == nil {
			return rankNoErrors
		}
		switch result.DeniedReason.Reason {
		case ParentErrorNotAllowed:
			return rankNotAllowed
		case ParentErrorNoHostname:
			return rankNoHostname
		case ParentErrorParentRefConflict:
			return rankParentRefConflict
		case ParentErrorNotAccepted:
			return rankNotAccepted
		}
		return rankNoErrors
	}

	report := map[gatewayv1.ParentReference]RouteParentResult{}
	for ref, results := range seen {
		if len(results) == 0 {
			continue
		}
		toReport := results[0]
		mostSevere := rankError(toReport)
		for _, result := range results[1:] {
			rank := rankError(result)
			if rank < mostSevere {
				mostSevere = rank
				toReport = result
			} else if rank == mostSevere && toReport.DeniedReason != nil && result.DeniedReason != nil {
				toReport.DeniedReason.Message += "; " + result.DeniedReason.Message
			}
		}
		report[ref] = toReport
	}

	var toAppend []gatewayv1.RouteParentStatus
	for k, gw := range report {
		msg := "Route was valid"
		if successCount[k] > 1 {
			msg = fmt.Sprintf("Route was valid, bound to %d parents", successCount[k])
		}
		conds := map[string]*Condition{
			string(gatewayv1.RouteConditionAccepted): {
				Reason:  string(gatewayv1.RouteReasonAccepted),
				Message: msg,
			},
			string(gatewayv1.RouteConditionResolvedRefs): {
				Reason:  string(gatewayv1.RouteReasonResolvedRefs),
				Message: "All references resolved",
			},
		}
		if gw.RouteError != nil {
			conds[string(gatewayv1.RouteConditionResolvedRefs)] = gw.RouteError
		}
		if gw.DeniedReason != nil {
			conds[string(gatewayv1.RouteConditionAccepted)].Error = &ConfigError{
				Reason:  ConfigErrorReason(gw.DeniedReason.Reason),
				Message: gw.DeniedReason.Message,
			}
		}

		myRef := parentRefStringWithNS(gw.OriginalReference, objectNamespace)
		var currentConditions []metav1.Condition
		cs := slices.FindFunc(currentParents, func(s gatewayv1.RouteParentStatus) bool {
			return parentRefStringWithNS(s.ParentRef, objectNamespace) == myRef &&
				s.ControllerName == gatewayv1.GatewayController(controllerName)
		})
		if cs != nil {
			currentConditions = cs.Conditions
		}
		ns := gatewayv1.RouteParentStatus{
			ParentRef:      gw.OriginalReference,
			ControllerName: gatewayv1.GatewayController(controllerName),
			Conditions:     SetConditions(generation, currentConditions, conds),
		}
		if idx, f := parentIndexes[myRef]; f {
			parents[idx] = ns
			delete(parentIndexes, myRef)
		} else {
			toAppend = append(toAppend, ns)
		}
	}

	sort.SliceStable(toAppend, func(i, j int) bool {
		return parentRefStringWithNS(toAppend[i].ParentRef, objectNamespace) > parentRefStringWithNS(toAppend[j].ParentRef, objectNamespace)
	})
	parents = append(parents, toAppend...)

	toDelete := sets.New(maps.Values(parentIndexes)...)
	parents = FilterInPlaceByIndex(parents, func(i int) bool {
		_, f := toDelete[i]
		return !f
	})

	if parents == nil {
		return []gatewayv1.RouteParentStatus{}
	}
	return parents
}

func parentRefStringWithNS(ref gatewayv1.ParentReference, objectNamespace string) string {
	ns := objectNamespace
	if ref.Namespace != nil {
		ns = string(*ref.Namespace)
	}
	g := gvk.KubernetesGateway.Group
	if ref.Group != nil {
		g = string(*ref.Group)
	}
	k := gvk.KubernetesGateway.Kind
	if ref.Kind != nil {
		k = string(*ref.Kind)
	}
	var sn string
	if ref.SectionName != nil {
		sn = string(*ref.SectionName)
	}
	var port int
	if ref.Port != nil {
		port = int(*ref.Port)
	}
	return fmt.Sprintf("%s/%s/%s/%s/%d.%s", g, k, ref.Name, sn, port, ns)
}
