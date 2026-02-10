# GEP-5000 ExtAuth with XGatewayExternalService

Manual test setup for the GEP-5000 ext_authz implementation using
`XGatewayExternalService`.

## Prerequisites

- A cluster with Istio installed with `PILOT_ENABLE_ALPHA_GATEWAY_API=true`
- Gateway API experimental CRDs:
  ```bash
  kubectl apply --server-side -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.1/experimental-install.yaml
  ```
- The `XGatewayExternalService` CRD applied (from the gateway-api fork, not yet upstream)

## Setup

```bash
# Deploy the ext-authz backend (reuses the existing sample server)
kubectl apply -f ../ext-authz.yaml

# Deploy the httpbin backend
kubectl apply -f httpbin.yaml

# Deploy Gateway and HTTPRoutes
kubectl apply -f gateway.yaml
```

This creates a Gateway with two HTTPRoutes, both pointing to httpbin:

| Host | HTTPRoute | Purpose |
|------|-----------|---------|
| `httpbin.example.com` | `httpbin-route` | Target for ext-authz policy |
| `noauth.example.com` | `httpbin-noauth` | No ext-authz, used as control |

## Enable ext_authz

Two policy variants are provided. Use one or the other.

**Option A: Target the HTTPRoute** (ext_authz applies only to `httpbin-route`):

```bash
kubectl apply -f ext-authz-policy-httproute.yaml
```

**Option B: Target the Gateway** (ext_authz applies to all routes on the gateway):

```bash
kubectl apply -f ext-authz-policy-gateway.yaml
```

To disable, delete whichever one you applied:

```bash
kubectl delete -f ext-authz-policy-httproute.yaml
# or
kubectl delete -f ext-authz-policy-gateway.yaml
```

## Test

```bash
GATEWAY_IP=$(kubectl get gateway ext-authz-gateway -o jsonpath='{.status.addresses[0].value}')

# httpbin.example.com -- protected by ext-authz (when policy is applied)
# Denied (no allow header) -- expect 403
curl -v -H "Host: httpbin.example.com" http://$GATEWAY_IP/get

# Allowed -- expect 200
curl -v -H "Host: httpbin.example.com" -H "x-ext-authz: allow" http://$GATEWAY_IP/get

# noauth.example.com -- never protected by HTTPRoute-targeted policy
# Should always return 200 regardless of headers
curl -v -H "Host: noauth.example.com" http://$GATEWAY_IP/get
```

When using **Option A** (HTTPRoute target), only `httpbin.example.com` is
protected. `noauth.example.com` should always return 200.

When using **Option B** (Gateway target), both hosts are protected.

The sample ext-authz server allows requests containing `x-ext-authz: allow`
and denies everything else. See `../README.md` for details.

## Verify status

```bash
kubectl get xgatewayexternalservices -o yaml
```

The `status.ancestors` section should show `Accepted: True` when the
targetRef resolves to an existing Gateway or HTTPRoute.
