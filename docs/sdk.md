# Go SDK reference

`github.com/Abraxas-365/iamkit/sdk` is a separate Go module — pin it independently from the
server. All four clients refuse to follow HTTP redirects (`CheckRedirect` returns
`http.ErrUseLastResponse`) so a credential is never silently forwarded to another host. Errors
come back as `sdk/apierror.Error` (management/identity/SCIM) or `authclient.OAuthError`
(OAuth-protocol calls), both distinct from the server-side `internal/errx` used inside IAMKit
itself.

```sh
go get github.com/Abraxas-365/iamkit/sdk
```

## `sdk/iamclient` — management API

For your product's own trusted backend: provisioning users, organizations, applications,
resources, grants, roles, service accounts, federation connections, and reading inventories.
Requires an `ik_mgmt_...` operator credential — **never** ship this into a browser or mobile app.

```go
client := iamclient.Client{BaseURL: "https://your-iamkit-host", Key: mgmtKey}
env, err := client.Environment(envID)

created, err := env.CreateUser(ctx, iamclient.CreateUser{
    Email: "alice@example.com", Name: "Alice", Password: "a-long-initial-password",
})
user, err := env.User(ctx, created.ID)
err = env.UpdateUser(ctx, created.ID, iamclient.UserPatch{ /* ... */ })
```

Every `Environment` method maps 1:1 to a `/management/v1/environments/{id}/...` route
documented in [API guide](api.md) — see `sdk/iamclient/environment.go`,
`sdk/iamclient/administration.go` and `sdk/iamclient/operations.go` for the full method list
(users, organizations, memberships, org units/positions, applications, resources, grants,
roles, service accounts, sessions, federation connections/external identities, impersonation,
provisioning credentials/links, org chart/delete-impact reads).

For an endpoint that doesn't yet have a typed wrapper, call it directly:

```go
var out map[string]any
err := client.Do(ctx, "GET", "/environments/"+envID+"/audit-events", nil, &out)
```

## `sdk/authclient` — identity API (end users and machines)

For login, refresh, profile, OTP challenges, OAuth token exchange, and token validation. No
management credential involved.

```go
auth := authclient.Client{BaseURL: "https://your-iamkit-host"}

pair, err := auth.Login(ctx, authclient.PasswordLogin{
    LoginContext: authclient.LoginContext{EnvironmentID: env, OrganizationID: org, ApplicationID: app, ResourceID: resource},
    Email: "alice@example.com", Password: "...",
})
// pair.AccessToken, pair.RefreshToken, pair.ExpiresIn

pair, err = auth.Refresh(ctx, boundary, pair.RefreshToken) // rotates; replay revokes the family

profile, err := auth.Profile(ctx, pair.AccessToken, env, audience)
err = auth.Logout(ctx, pair.AccessToken, env, audience)
```

**Machine tokens** (for service accounts, `ik_svc_...`):
```go
pair, err := auth.MachineToken(ctx, svcSecret)
```

**Email OTP challenges** (`purpose` is `"login"`, `"email_verification"` or `"password_reset"`):
```go
ch, err := auth.InitiateChallenge(ctx, env, "alice@example.com", "login")
pair, err := auth.VerifyChallenge(ctx, authclient.ChallengeVerification{ /* challenge_id, code, boundary IDs */ })
```

### Validating tokens: online vs. offline

Two ways to check an access token, with a real tradeoff — see
[Concepts → token purposes](concepts.md#token-purposes) for what's actually inside a token.

**Online — `Introspect`** reflects logout/revocation immediately, costs a round trip per call:
```go
claims, err := auth.Introspect(ctx, token, issuer, audience, environment, application, resource)
```

**Offline — `Validate`** is a pure JWT/JWKS check, no network call per request, but cannot see
revocation before the token's own 15-minute expiry:
```go
claims, err := authclient.Validate(rawToken, rsaPublicKey, issuer, audience, environment, application, resource)
```
Fetch `rsaPublicKey` once from `GET /.well-known/jwks.json` and cache it; don't refetch per
request.

### OAuth/PKCE (`authclient.OAuthClient`)

For applications doing a standard authorization-code + PKCE flow against `/oauth/*` instead of
calling `/identity/v1/login` directly (see [Recipes](recipes.md#recipe-let-an-application-use-its-own-oauthoidc-login-screen)):
```go
verifier, challenge, err := authclient.NewPKCE()
// ... redirect user to /oauth/authorize with code_challenge=challenge ...
oc := authclient.OAuthClient{BaseURL: "https://your-iamkit-host", ClientID: clientID}
tokens, err := oc.Exchange(ctx, code, redirectURI, verifier)
tokens, err = oc.Refresh(ctx, tokens.RefreshToken)
err = oc.Revoke(ctx, tokens.AccessToken)
```

## `sdk/authclient/fiberauth` — Fiber middleware

Wraps either validation strategy above into request middleware for your own resource server. See
[Recipes → protect your Fiber API](recipes.md#recipe-protect-your-fiber-api-with-permission-checks)
for a complete example. Summary:

```go
app.Use("/invoices", fiberauth.Authenticate(validate)) // validate: func(ctx, token) (*authclient.Claims, error)
app.Get("/invoices", fiberauth.RequirePermissions("invoices:read"), handler)
app.Get("/org-only", fiberauth.RequireOrganization(expectedOrgID), handler)
```
`fiberauth.Claims(c)` retrieves the validated claims inside a handler. `RequireOrganization`
only ever passes for `purpose: "application"` tokens (see
[Concepts → token purposes](concepts.md#token-purposes)) — machine tokens carry no organization
and are always rejected by it.

## `sdk/scimclient` — SCIM provisioning API

For your identity provider integration code (or a script emulating one) talking to
`/scim/v2/Users`. Requires an `ik_scim_...` provisioning credential, scoped to one organization
connection (see [Recipes → SCIM](recipes.md#recipe-provision-users-automatically-from-your-identity-provider-scim)).

```go
scim := scimclient.Client{BaseURL: "https://your-iamkit-host", Secret: scimSecret}

created, err := scim.Create(ctx, scimclient.User{UserName: "alice@example.com", DisplayName: "Alice"})
user, err := scim.Get(ctx, created.ID)
list, err := scim.List(ctx, `userName eq "alice@example.com"`, 1, 20)
updated, err := scim.Replace(ctx, created.ID, scimclient.User{ /* full replacement */ })
patched, err := scim.Patch(ctx, created.ID, []scimclient.Operation{{Op: "replace", Path: "active", Value: false}})
err = scim.Delete(ctx, created.ID) // deactivates, per SCIM semantics
```

## `sdk/apierror` — error handling

Both `iamclient` and `authclient`/`scimclient` return `*apierror.Error` on non-2xx responses,
decoded from the server's `{"error":{...}}` envelope (see
[Concepts → errors are classified](concepts.md#errors-are-classified-not-just-http-codes)):

```go
var apiErr *apierror.Error
if errors.As(err, &apiErr) {
    switch apiErr.Code { /* branch on machine-readable code, not Message text */ }
}
```

OAuth-protocol calls (`authclient.OAuthClient`) instead return `*authclient.OAuthError`
(`{error, error_description}`), matching RFC 6749's error shape rather than IAMKit's own
envelope — the two are not interchangeable.
