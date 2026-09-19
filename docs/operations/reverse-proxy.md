# Reverse proxy, TLS and CORS

Use a stable public HTTPS origin matching `JWT_ISSUER`. IAMKit listens HTTP behind
your trusted TLS terminator. Forward the original host and appropriate forwarding
headers, but do not assume arbitrary client-supplied proxy headers are trustworthy.
Configure trusted hops at the edge and validate which client IP IAMKit actually sees.

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
relying on per-IP rate limits. Your reverse-proxy configuration depends on the
hosting platform; record and test it alongside your deployment manifest.
