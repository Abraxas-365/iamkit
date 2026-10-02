# Reverse proxy, TLS and CORS

Use a stable public HTTPS origin matching `JWT_ISSUER`. IAMKit listens HTTP behind
your trusted TLS terminator. Ready-made setups: [Compose with Traefik or
Caddy](deployment.md#compose-with-tls) and the [Helm chart](deployment.md#kubernetes-helm).

## Forwarded headers

By default IAMKit takes the client address from the TCP connection, so behind
a proxy every request seems to come from the proxy: per-IP rate limits are
then shared by all clients, and request logs show the proxy. Set
`IAMKIT_TRUSTED_PROXIES` to the proxies' addresses (IPs or CIDRs,
comma-separated):

- From those addresses only, the client is the first valid address of
  `X-Forwarded-For`, and `X-Forwarded-Proto`/`X-Forwarded-Host` are read.
- From any other address, forwarded headers are ignored and the socket address
  is the client — a client reaching IAMKit directly cannot pick its own address.
- The edge proxy must **replace** `X-Forwarded-For` with the address it saw,
  not append to what the client sent (Traefik and Caddy do so when they trust
  no upstream; nginx: `proxy_set_header X-Forwarded-For $remote_addr;`). With
  several hops, every inner proxy must keep the value the edge set.

List only addresses that cannot be reached by clients: the proxy network of
the Compose files, or the ingress controller's pod range in Kubernetes. An
invalid entry stops start-up. Check the result in the request log (`ip=`):
it must be the client's public address, and must not change when the client
sends its own `X-Forwarded-For`.

## Routing

- App origin: forward `/identity/`, `/oauth/` and `/.well-known/` if your app owns
  the login/consent integration. Preserve Secure cookies and redirects.
- Console origin: static SPA plus `/management/` reverse proxy.
- Automation/provisioning: restrict `/api/`, `/management/` and `/scim/` network
  reachability as appropriate to their callers; authentication is still required.
- Never rewrite federation callback paths away from the registered URI.

Do not cache authenticated responses, token responses or challenge requests.
Do not log Authorization/X-API-Key, cookies, codes or body fields containing secrets.
Use request size/time limits and ingress abuse controls. TLS termination does not
make publicly forwarded management routes a safe signup API.

## CORS

`CORS_ALLOWED_ORIGINS` is a comma-separated allowlist. Empty means no CORS
middleware. When set, credentials are enabled and allowed headers include
Content-Type, Authorization, X-API-Key and X-IAMKit-Console. Avoid wildcard/untrusted
origins. CORS governs browser access, not non-browser authorization.

Console cookie mutations additionally require `X-IAMKit-Console: 1` and reject
cross-site fetches. Federation/authorization cookies are Secure and browser-bound.
Same-origin proxying avoids many cross-site cookie constraints; test the actual
browser flow, not only curl with manually copied cookies.

## Verify

Check HTTPS issuer discovery, cookie Secure/HttpOnly/SameSite/path attributes,
callback round-trip and origin rejection. Confirm 401 without credentials and 403
without permissions. Test forwarded-IP behavior under the real ingress before
relying on per-IP rate limits (`deploy/compose/smoke.sh` does both checks for
the Compose files). Your reverse-proxy configuration depends on the hosting
platform; record and test it alongside your deployment manifest.
