# GEP-5000 ExtAuth & RateLimit with XGatewayExternalService

Manual test setup for the GEP-5000 implementation using
`XGatewayExternalService` for both `ExtAuth` and `RateLimit` types.

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
| `httpbin.example.com` | `httpbin-route` | Target for policies |
| `noauth.example.com` | `httpbin-noauth` | No policies, used as control |

## ExtAuth

Two policy variants are provided. Use one or the other.

**Option A: Target the HTTPRoute** (ext_authz applies only to `httpbin-route`):

```bash
kubectl apply -f ext-authz-policy-httproute.yaml
```

**Option B: Target the Gateway** (ext_authz applies to all routes on the gateway):

```bash
kubectl apply -f ext-authz-policy-gateway.yaml
```

To disable:

```bash
kubectl delete -f ext-authz-policy-httproute.yaml
# or
kubectl delete -f ext-authz-policy-gateway.yaml
```

### Test ExtAuth

```bash
GATEWAY_IP=$(kubectl get gateway ext-authz-gateway -o jsonpath='{.status.addresses[0].value}')

# Denied (no allow header) -- expect 403
curl -v -H "Host: httpbin.example.com" http://$GATEWAY_IP/get

# Allowed -- expect 200
curl -v -H "Host: httpbin.example.com" -H "x-ext-authz: allow" http://$GATEWAY_IP/get

# noauth.example.com -- not protected by HTTPRoute-targeted policy
curl -v -H "Host: noauth.example.com" http://$GATEWAY_IP/get
```

## RateLimit

### Deploy Limitador (RLS backend)

```bash
kubectl apply -f limitador.yaml
```

Wait for Limitador to be ready:

```bash
kubectl wait --for=condition=available deployment/limitador --timeout=60s
```

### Enable rate limiting

**Option A: Target the HTTPRoute:**

```bash
kubectl apply -f ratelimit-policy-httproute.yaml
```

**Option B: Target the Gateway:**

```bash
kubectl apply -f ratelimit-policy-gateway.yaml
```

To disable:

```bash
kubectl delete -f ratelimit-policy-httproute.yaml
# or
kubectl delete -f ratelimit-policy-gateway.yaml
```

### Test RateLimit

```bash
GATEWAY_IP=$(kubectl get gateway ext-authz-gateway -o jsonpath='{.status.addresses[0].value}')

# Send requests rapidly -- after the limit is hit, expect 429 Too Many Requests
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" -H "Host: httpbin.example.com" http://$GATEWAY_IP/get
done
```

With the default Limitador config, the `httpbin-ratelimit` domain allows 5
requests per minute. Requests beyond that should return 429.

## Using both ExtAuth and RateLimit together

You can apply both policies simultaneously. ext_authz runs first (lower in the
HCM filter chain), and rate limiting runs after:

```bash
kubectl apply -f ext-authz-policy-httproute.yaml
kubectl apply -f ratelimit-policy-httproute.yaml
```

## Verify status

```bash
kubectl get xgatewayexternalservices -o yaml
```

The `status.ancestors` section should show `Accepted: True` when the
targetRef resolves to an existing Gateway or HTTPRoute.
