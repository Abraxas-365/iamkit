# @iamkit/node

Server-side IAMKit SDK for Node.js (≥ 20): verify access tokens, protect
routes, run OAuth flows as a confidential client, sign machine users in with
keys, verify webhooks and actions, and call the management API.

```sh
npm install @iamkit/node
```

| Area | Exports |
| --- | --- |
| Access tokens | `createJwtVerifier` (offline, JWKS), `createIntrospectionVerifier` (online), `createKeySet`, `hasPermission`, `hasMFA`, `isImpersonated` |
| Middleware (Express/Connect) | `authenticate`, `requirePermissions`, `requireOrganization`, `requireMFA`, `claimsOf` |
| OAuth / OIDC | `OAuthClient` (authorize URL, code + PKCE, refresh, revoke, UserInfo, introspection, client_credentials, device flow, token exchange, impersonation, end-session URL), `createPKCE`, `randomToken`, `verifyIdToken`, `verifyLogoutToken` |
| Machine users | `KeyLogin` (RFC 7523 JWT-bearer grant), `IdentityClient.exchangeAccessToken` (`ik_pat_`) |
| Identity API | `IdentityClient` (login, MFA, refresh, logout, profile, organizations, service-account token) |
| Webhooks and actions | `verifyWebhook`, `verifyAction`, `verifySignature`, `deny`, `Conditions` |
| Typed REST clients | `createManagementClient`, `createApiClient`, `createIAMKitClient` (from `@iamkit/api`) |
| Errors | `IAMKitError` (`status`, `code`, `message`, `details`) |

## Protect an API

```ts
import express from "express";
import { authenticate, claimsOf, createJwtVerifier, requireOrganization, requirePermissions } from "@iamkit/node";

const verifier = createJwtVerifier({
  issuer: "https://iam.example.com",
  audience: "https://api.example.com",
  environmentId: process.env.IAMKIT_ENVIRONMENT!,
  applicationId: process.env.IAMKIT_APPLICATION!,
  resourceId: process.env.IAMKIT_RESOURCE!,
});

const app = express();
app.get(
  "/orgs/:org/invoices",
  authenticate(verifier),
  requireOrganization((req) => (req as express.Request).params.org),
  requirePermissions("invoices:read"),
  (req, res) => res.json({ user: claimsOf(req)!.sub }),
);
```

Create one verifier per process: it caches the signing keys (10 minutes,
refetched on an unknown `kid` at most every 30 s). Offline verification does
not see logout or suspension before the token expires; use
`createIntrospectionVerifier({ ...same, baseUrl })` where that must take effect
at once — it fails closed when IAMKit is unreachable (503).

## Sign users in (authorization code + PKCE)

```ts
import { OAuthClient, createPKCE, randomToken, verifyIdToken, createKeySet } from "@iamkit/node";

const oauth = new OAuthClient({ baseUrl: "https://iam.example.com", clientId, clientSecret });
const pkce = createPKCE();
const state = randomToken();
const nonce = randomToken();
// keep pkce.verifier, state and nonce in the server session, then redirect:
const url = oauth.authorizationUrl({ redirectUri, state, nonce, codeChallenge: pkce.challenge, scopes: ["email", "offline_access"] });

// on the callback, after comparing state:
const tokens = await oauth.exchangeCode(code, redirectUri, pkce.verifier);
const keys = createKeySet({ issuer: "https://iam.example.com" });
const user = await verifyIdToken(tokens.id_token!, { issuer: "https://iam.example.com", clientId, keys, nonce });
```

Client authentication is `client_secret_basic` with `clientSecret`, or
`auth: { method: "client_secret_post" | "private_key_jwt" | "none", … }`.
`private_key_jwt` signs a fresh one-minute assertion per request with your PEM
(RSA or EC) and `kid`.

## Services and machine users

```ts
// Service account: client_credentials with its secret or a registered key.
const tokens = await new OAuthClient({ baseUrl, clientId: serviceAccountId, clientSecret: "ik_svc_…" }).clientCredentials();

// Machine user key: no OAuth client, a fresh assertion per token.
const login = new KeyLogin({ baseUrl, userId, kid, privateKey: pem });
const { access_token } = await login.token({ organizationId, applicationId, resourceId });
```

## Webhooks and actions

Verify the raw body before parsing it (for Express use `express.raw({ type: "application/json" })`):

```ts
import { verifyWebhook, verifyAction, deny, Conditions } from "@iamkit/node";

app.post("/iamkit/events", express.raw({ type: "application/json" }), (req, res) => {
  const event = verifyWebhook(process.env.WEBHOOK_SECRET!, req.headers, req.body);
  // dedupe on event.id; deliveries are at least once
  res.sendStatus(204);
});

app.post("/iamkit/actions", express.raw({ type: "application/json" }), (req, res) => {
  const input = verifyAction(process.env.ACTION_SECRET!, req.headers, req.body);
  if (input.condition === Conditions.PreSignIn && blocked(input.user?.email)) {
    return res.json(deny("Your account is under review."));
  }
  res.sendStatus(204);
});
```

Both throw `WebhookError` (status 401, code `SIGNATURE`, `TIMESTAMP` or
`SECRET`); answer 401 then.

## Management API

```ts
import { createManagementClient } from "@iamkit/node";

const iam = createManagementClient({ baseUrl: "https://iam.example.com", key: process.env.IAMKIT_KEY! });
const { data, error } = await iam.GET("/management/v1/environments/{environment}/users", {
  params: { path: { environment } },
});
```

Requests are typed from the OpenAPI document (`@iamkit/api`).

## Develop

```sh
npm ci && npm run typecheck && npm test && npm run build
```
