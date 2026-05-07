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

package gatewaycommon

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	inferencev1 "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
)

// InferencePool holds the gateway parents that reference an InferencePool, used for status tracking.
type InferencePool struct {
	PoolName       string
	Namespace      string
	GatewayParents sets.Set[types.NamespacedName]
}

func (i InferencePool) ResourceName() string {
	return i.Namespace + "/" + i.PoolName
}

// InferencePoolCollection builds KRT collections for InferencePool status tracking.
//
// managedClasses is the map of GatewayClass name → GatewayController for the calling
// reconciler (workload proxy classes and/or gwxds when applicable). It is used both for:
//   - checking whether an HTTPRoute's parent status is owned by us (via controller name)
//   - deciding whether an existing Gateway is managed by us (via class name)
func InferencePoolCollection(
	pools krt.Collection[*inferencev1.InferencePool],
	services krt.Collection[*corev1.Service],
	httpRoutes krt.Collection[*gatewayv1.HTTPRoute],
	gateways krt.Collection[*gatewayv1.Gateway],
	routesByInferencePool krt.Index[string, *gatewayv1.HTTPRoute],
	managedClasses map[gatewayv1.ObjectName]gatewayv1.GatewayController,
	opts krt.OptionsBuilder,
) (krt.StatusCollection[*inferencev1.InferencePool, inferencev1.InferencePoolStatus], krt.Collection[InferencePool]) {
	managedControllers := managedClassesToControllerSet(managedClasses)
	return krt.NewStatusCollection(pools,
		func(
			ctx krt.HandlerContext,
			pool *inferencev1.InferencePool,
		) (*inferencev1.InferencePoolStatus, *InferencePool) {
			routeList := routesByInferencePool.Fetch(ctx, pool.Namespace+"/"+pool.Name)
			gatewayParents := findGatewayParents(pool, routeList, managedControllers)

			var inferencePool *InferencePool
			if len(gatewayParents) > 0 {
				inferencePool = createInferencePoolObject(pool, gatewayParents)
			}

			status := calculateInferencePoolStatus(pool, gatewayParents, services, gateways, routeList, managedControllers, managedClasses)
			return status, inferencePool
		}, opts.WithName("InferenceExtension")...)
}

// IndexHTTPRouteByInferencePool returns the index keys for HTTPRoutes that reference an InferencePool backend.
func IndexHTTPRouteByInferencePool(o *gatewayv1.HTTPRoute) []string {
	var keys []string
	for _, rule := range o.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			if isInferencePoolBackendRef(backendRef.BackendRef) {
				backendRefNamespace := o.Namespace
				if ptr.OrEmpty(backendRef.BackendRef.Namespace) != "" {
					backendRefNamespace = string(*backendRef.BackendRef.Namespace)
				}
				key := backendRefNamespace + "/" + string(backendRef.Name)
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// managedClassesToControllerSet builds a set of GatewayController names from a class map.
func managedClassesToControllerSet(classes map[gatewayv1.ObjectName]gatewayv1.GatewayController) sets.Set[gatewayv1.GatewayController] {
	s := sets.New[gatewayv1.GatewayController]()
	for _, ctrl := range classes {
		s.Insert(ctrl)
	}
	return s
}

func routeReferencesInferencePool(route *gatewayv1.HTTPRoute, pool *inferencev1.InferencePool) bool {
	for _, rule := range route.Spec.Rules {
		for _, backendRef := range rule.BackendRefs {
			if !isInferencePoolBackendRef(backendRef.BackendRef) {
				continue
			}
			if string(backendRef.BackendRef.Name) != pool.ObjectMeta.Name {
				continue
			}
			backendRefNamespace := route.Namespace
			if ptr.OrEmpty(backendRef.BackendRef.Namespace) != "" {
				backendRefNamespace = string(*backendRef.BackendRef.Namespace)
			}
			if backendRefNamespace == pool.Namespace {
				return true
			}
		}
	}
	return false
}

func findGatewayParents(
	pool *inferencev1.InferencePool,
	routeList []*gatewayv1.HTTPRoute,
	managedControllers sets.Set[gatewayv1.GatewayController],
) sets.Set[types.NamespacedName] {
	gatewayParents := sets.New[types.NamespacedName]()
	for _, route := range routeList {
		if !routeReferencesInferencePool(route, pool) {
			continue
		}
		for _, parentStatus := range route.Status.Parents {
			if !managedControllers.Contains(parentStatus.ControllerName) {
				continue
			}
			gatewayNamespace := route.Namespace
			if ptr.OrEmpty(parentStatus.ParentRef.Namespace) != "" {
				gatewayNamespace = string(*parentStatus.ParentRef.Namespace)
			}
			gatewayParents.Insert(types.NamespacedName{
				Name:      string(parentStatus.ParentRef.Name),
				Namespace: gatewayNamespace,
			})
		}
	}
	return gatewayParents
}

func createInferencePoolObject(pool *inferencev1.InferencePool, gatewayParents sets.Set[types.NamespacedName]) *InferencePool {
	return &InferencePool{
		PoolName:       pool.Name,
		Namespace:      pool.Namespace,
		GatewayParents: gatewayParents,
	}
}

func filterUsedConditions(conditions []metav1.Condition, usedConditions ...inferencev1.InferencePoolConditionType) []metav1.Condition {
	var result []metav1.Condition
	for _, condition := range conditions {
		if slices.Contains(usedConditions, inferencev1.InferencePoolConditionType(condition.Type)) {
			result = append(result, condition)
		}
	}
	return result
}

func calculateSingleParentStatus(
	pool *inferencev1.InferencePool,
	gatewayParent types.NamespacedName,
	services krt.Collection[*corev1.Service],
	existingParents []inferencev1.ParentStatus,
	routeList []*gatewayv1.HTTPRoute,
	managedControllers sets.Set[gatewayv1.GatewayController],
) inferencev1.ParentStatus {
	var existingConditions []metav1.Condition
	for _, existingParent := range existingParents {
		if string(existingParent.ParentRef.Name) == gatewayParent.Name &&
			string(existingParent.ParentRef.Namespace) == gatewayParent.Namespace {
			existingConditions = existingParent.Conditions
			break
		}
	}

	filteredConditions := filterUsedConditions(existingConditions,
		inferencev1.InferencePoolConditionAccepted,
		inferencev1.InferencePoolConditionResolvedRefs)

	acceptedStatus := calculateAcceptedStatus(pool, gatewayParent, routeList, managedControllers)
	resolvedRefsStatus := calculateResolvedRefsStatus(pool, services)

	return inferencev1.ParentStatus{
		ParentRef: inferencev1.ParentReference{
			Group:     (*inferencev1.Group)(&gvk.Gateway.Group),
			Kind:      inferencev1.Kind(gvk.Gateway.Kind),
			Namespace: inferencev1.Namespace(gatewayParent.Namespace),
			Name:      inferencev1.ObjectName(gatewayParent.Name),
		},
		Conditions: SetConditions(pool.Generation, filteredConditions, map[string]*Condition{
			string(inferencev1.InferencePoolConditionAccepted):     acceptedStatus,
			string(inferencev1.InferencePoolConditionResolvedRefs): resolvedRefsStatus,
		}),
	}
}

func calculateAcceptedStatus(
	pool *inferencev1.InferencePool,
	gatewayParent types.NamespacedName,
	routeList []*gatewayv1.HTTPRoute,
	managedControllers sets.Set[gatewayv1.GatewayController],
) *Condition {
	for _, route := range routeList {
		if !routeReferencesInferencePool(route, pool) {
			continue
		}
		for _, parentStatus := range route.Status.Parents {
			if !managedControllers.Contains(parentStatus.ControllerName) {
				continue
			}
			gatewayNamespace := route.Namespace
			if ptr.OrEmpty(parentStatus.ParentRef.Namespace) != "" {
				gatewayNamespace = string(*parentStatus.ParentRef.Namespace)
			}
			if string(parentStatus.ParentRef.Name) == gatewayParent.Name && gatewayNamespace == gatewayParent.Namespace {
				for _, parentCondition := range parentStatus.Conditions {
					if parentCondition.Type == string(gatewayv1.RouteConditionAccepted) {
						if parentCondition.Status == metav1.ConditionTrue {
							return &Condition{
								Reason:  string(inferencev1.InferencePoolReasonAccepted),
								Status:  metav1.ConditionTrue,
								Message: "Referenced by an HTTPRoute accepted by the parentRef Gateway",
							}
						}
						return &Condition{
							Reason: string(inferencev1.InferencePoolReasonHTTPRouteNotAccepted),
							Status: metav1.ConditionFalse,
							Message: fmt.Sprintf("Referenced HTTPRoute %s/%s not accepted by Gateway %s/%s: %s",
								route.Namespace, route.Name, gatewayParent.Namespace, gatewayParent.Name, parentCondition.Message),
						}
					}
				}
				return &Condition{
					Reason:  string(inferencev1.InferencePoolReasonAccepted),
					Status:  metav1.ConditionUnknown,
					Message: "Referenced by an HTTPRoute unknown parentRef Gateway status",
				}
			}
		}
	}
	return &Condition{
		Reason: string(inferencev1.InferencePoolReasonHTTPRouteNotAccepted),
		Status: metav1.ConditionFalse,
		Message: fmt.Sprintf("No HTTPRoute found referencing this InferencePool with Gateway %s/%s as parent",
			gatewayParent.Namespace, gatewayParent.Name),
	}
}

func calculateResolvedRefsStatus(
	pool *inferencev1.InferencePool,
	services krt.Collection[*corev1.Service],
) *Condition {
	kind := string(pool.Spec.EndpointPickerRef.Kind)
	if kind == "" {
		kind = gvk.Service.Kind
	}
	if kind != gvk.Service.Kind {
		return &Condition{
			Reason:  string(inferencev1.InferencePoolReasonInvalidExtensionRef),
			Status:  metav1.ConditionFalse,
			Message: "Unsupported ExtensionRef kind " + kind,
		}
	}
	name := string(pool.Spec.EndpointPickerRef.Name)
	if name == "" {
		return &Condition{
			Reason:  string(inferencev1.InferencePoolReasonInvalidExtensionRef),
			Status:  metav1.ConditionFalse,
			Message: "ExtensionRef not defined",
		}
	}
	svc := ptr.Flatten(services.GetKey(fmt.Sprintf("%s/%s", pool.Namespace, name)))
	if svc == nil {
		return &Condition{
			Reason:  string(inferencev1.InferencePoolReasonInvalidExtensionRef),
			Status:  metav1.ConditionFalse,
			Message: "Referenced ExtensionRef not found " + name,
		}
	}
	return &Condition{
		Reason:  string(inferencev1.InferencePoolReasonResolvedRefs),
		Status:  metav1.ConditionTrue,
		Message: "Referenced ExtensionRef resolved successfully",
	}
}

func isDefaultStatusParent(parent inferencev1.ParentStatus) bool {
	return string(parent.ParentRef.Kind) == "Status" && parent.ParentRef.Name == "default"
}

func isManagedGatewayByClass(
	gateways krt.Collection[*gatewayv1.Gateway],
	namespace, name string,
	managedClasses map[gatewayv1.ObjectName]gatewayv1.GatewayController,
) bool {
	gtw := ptr.Flatten(gateways.GetKey(fmt.Sprintf("%s/%s", namespace, name)))
	if gtw == nil {
		return false
	}
	_, ok := managedClasses[gtw.Spec.GatewayClassName]
	return ok
}

func calculateInferencePoolStatus(
	pool *inferencev1.InferencePool,
	gatewayParents sets.Set[types.NamespacedName],
	services krt.Collection[*corev1.Service],
	gateways krt.Collection[*gatewayv1.Gateway],
	routeList []*gatewayv1.HTTPRoute,
	managedControllers sets.Set[gatewayv1.GatewayController],
	managedClasses map[gatewayv1.ObjectName]gatewayv1.GatewayController,
) *inferencev1.InferencePoolStatus {
	existingParents := pool.Status.DeepCopy().Parents
	finalParents := []inferencev1.ParentStatus{}

	// Keep parents owned by other controllers, discard our stale entries.
	for _, existingParent := range existingParents {
		gtwName := string(existingParent.ParentRef.Name)
		gtwNamespace := pool.Namespace
		if existingParent.ParentRef.Namespace != "" {
			gtwNamespace = string(existingParent.ParentRef.Namespace)
		}
		parentKey := types.NamespacedName{Name: gtwName, Namespace: gtwNamespace}

		isCurrentlyOurs := gatewayParents.Contains(parentKey)
		if !isCurrentlyOurs &&
			!isManagedGatewayByClass(gateways, gtwNamespace, gtwName, managedClasses) &&
			!isDefaultStatusParent(existingParent) {
			finalParents = append(finalParents, existingParent)
		}
	}

	for gatewayParent := range gatewayParents {
		parentStatus := calculateSingleParentStatus(pool, gatewayParent, services, existingParents, routeList, managedControllers)
		finalParents = append(finalParents, parentStatus)
	}

	return &inferencev1.InferencePoolStatus{Parents: finalParents}
}

func isInferencePoolBackendRef(backendRef gatewayv1.BackendRef) bool {
	return ptr.OrEmpty(backendRef.Group) == gatewayv1.Group(gvk.InferencePool.Group) &&
		ptr.OrEmpty(backendRef.Kind) == gatewayv1.Kind(gvk.InferencePool.Kind)
}
