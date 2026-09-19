# IAMKit Go SDK

Go client libraries for integrating with IAMKit's identity and access management APIs.
See the [current SDK reference](../docs/reference/sdk/go.md) for version selection,
API-family boundaries and typed-list response compatibility notes.

```
go get github.com/Abraxas-365/iamkit/sdk
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐
│  User's Browser  │────▶│  Your App Backend │────▶│   IAMKit     │
│                  │     │  (has ik_mgmt_ key)│    │              │
│  - signup form   │     │  - POST /users     │    │  Management  │
│  - login form    │     │  - POST /orgs      │    │  API         │
│                  │     │  - POST /grants    │    │              │
└────────┬─────────┘     └──────────────────┘     └──────────────┘
         │                                               ▲
         │  Direct (no middleman)                        │
         └───────────────────────────────────────────────┘
            - POST /identity/v1/login
            - POST /identity/v1/federation/start
            - POST /identity/v1/challenges
            - GET  /identity/v1/me
```

The SDK has **four client packages** with distinct API authority:

| Package | Credential | Use case |
|---------|-----------|----------|
| `iamclient` | `ik_mgmt_*` | Backend → Management API (users, orgs, resources, grants) |
| `authclient` | User tokens / `ik_svc_*` | Identity API (login, tokens, profile, federation) |
| `apiclient` | JWT with explicit IAM permissions | Permission-scoped `/api/v1` management |
| `scimclient` | `ik_scim_*` | SCIM 2.0 provisioning (enterprise user sync) |

Plus framework integrations:
- `authclient/fiberauth` — Fiber v2 middleware for token validation
- `authclient/httpauth` — framework-neutral `net/http` middleware for token validation

---

## iamclient — Management API

Used by your **app backend** to manage users, organizations, resources, and permissions. Requires a management API key (`ik_mgmt_*`).

### Setup

```go
import "github.com/Abraxas-365/iamkit/sdk/iamclient"

client := iamclient.New("http://localhost:8080", "ik_mgmt_...",
    iamclient.WithHTTPClient(myHTTPClient), // optional
)
```

### Workspace Operations

These operations don't require an environment scope:

```go
// Operator management
me, _ := client.Me(ctx)
client.SetPassword(ctx, "new-secure-password")
client.Logout(ctx)

// API keys
key, _ := client.CreateKey(ctx, "720h")     // expires in 30 days
key, _ = client.CreateKey(ctx, "never")      // never expires
keys, _ := client.Keys(ctx)
client.RevokeKey(ctx, key.ID)

// Operators
op, _ := client.Delegate(ctx, "admin@co.com", "admin", "720h")
ops, _ := client.Operators(ctx)
client.DisableOperator(ctx, op.ID)

// Projects & environments
proj, _ := client.CreateProject(ctx, "My SaaS")
env, _  := client.CreateEnvironment(ctx, proj.ID, "Production")
projects, _ := client.Projects(ctx)
envs, _     := client.Environments(ctx, proj.ID)
```

### Environment-Scoped Operations

Most operations are scoped to an environment:

```go
env := client.Environment("env-uuid")
```

#### Complete Setup Flow

```go
// 1. Create a user
user, _ := env.CreateUser(ctx, iamclient.CreateUser{
    Email:    "alice@example.com",
    Name:     "Alice",
    Password: "secure-password-123",
})

// 2. Create an organization
org, _ := env.CreateOrganization(ctx, "Acme Corp")

// 3. Add user to organization
env.AddMember(ctx, iamclient.Membership{
    OrganizationID: org.ID,
    UserID:         user.ID,
    Role:           "admin",
})

// 4. Create an application + resource
app, _ := env.CreateApplication(ctx, iamclient.Application{
    Name: "Dashboard",
})
res, _ := env.CreateResource(ctx, iamclient.Resource{
    Name:        "Billing API",
    Audience:    "billing.myapp.com",
    Permissions: []string{"invoices:read", "invoices:write", "payments:create"},
})

// 5. Bind resource to application
env.BindResource(ctx, app.ID, res.ID)

// 6. Grant permissions
env.PutGrant(ctx, iamclient.Grant{
    OrganizationID: org.ID,
    UserID:         user.ID,
    ResourceID:     res.ID,
    Permissions:    []string{"invoices:read", "invoices:write"},
})
```

#### Users

```go
users, _ := env.Users(ctx)
user, _  := env.User(ctx, "user-id")
env.UpdateUser(ctx, "user-id", iamclient.UserPatch{Name: ptr("New Name")})
env.SuspendUser(ctx, "user-id")
```

#### Organizations & Members

```go
orgs, _ := env.Organizations(ctx)
org, _  := env.Organization(ctx, "org-id")
members, _ := env.Members(ctx, "org-id")
env.RemoveMember(ctx, "org-id", "user-id")
env.SetMemberProfile(ctx, "org-id", "user-id", iamclient.MemberProfile{
    OrgUnitID: ptr("unit-id"),
    ManagerID: ptr("manager-id"),
})
```

#### Organization Structure

```go
// Org units (departments, teams, etc.)
unit, _ := env.CreateOrgUnit(ctx, "org-id", iamclient.OrgUnit{Name: "Engineering", Kind: "department"})
units, _ := env.OrgUnits(ctx, "org-id")
env.UpdateOrgUnit(ctx, "org-id", unit.ID, iamclient.OrgUnit{Name: "Platform", Kind: "department"})
env.DeleteOrgUnit(ctx, "org-id", unit.ID)
tree, _ := env.OrgUnitTree(ctx, "org-id")
ancestors, _ := env.OrgUnitAncestors(ctx, "org-id", unit.ID)
descendants, _ := env.OrgUnitDescendants(ctx, "org-id", unit.ID)
impact, _ := env.OrgUnitDeleteImpact(ctx, "org-id", unit.ID)
chart, _ := env.OrgChart(ctx, "org-id")

// Positions
pos, _ := env.CreatePosition(ctx, "org-id", iamclient.Position{Name: "Tech Lead", Code: "TL"})
positions, _ := env.Positions(ctx, "org-id")
env.UpdatePosition(ctx, "org-id", pos.ID, iamclient.Position{Name: "Staff Engineer", Code: "SE"})
env.DeletePosition(ctx, "org-id", pos.ID)

// Position assignments
asgn, _ := env.AssignPosition(ctx, "org-id", iamclient.PositionAssignment{
    PositionID: pos.ID,
    UserID:     "user-id",
})
assignments, _ := env.PositionAssignments(ctx, "org-id")
env.UnassignPosition(ctx, "org-id", asgn.ID)
```

#### Resources & Applications

```go
resources, _ := env.Resources(ctx)
res, _ := env.Resource(ctx, "res-id")
env.UpdateResource(ctx, "res-id", iamclient.Resource{...})
apps, _ := env.Applications(ctx)
app, _ := env.Application(ctx, "app-id")
env.UpdateApplication(ctx, "app-id", iamclient.Application{...})
env.BindResource(ctx, "app-id", "res-id")
env.UnbindResource(ctx, "app-id", "res-id")
appRes, _ := env.ApplicationResources(ctx, "app-id")
```

#### Roles & Grants

```go
// Roles (reusable permission bundles)
role, _ := env.CreateRole(ctx, iamclient.Role{
    Name:        "Billing Admin",
    ResourceID:  "res-id",
    Permissions: []string{"invoices:read", "invoices:write", "payments:create"},
})
roles, _ := env.Roles(ctx)
env.UpdateRole(ctx, role.ID, iamclient.Role{...})
env.DeleteRole(ctx, role.ID)

// Role assignments
env.AssignRole(ctx, iamclient.RoleAssignment{
    OrganizationID: "org-id",
    UserID:         "user-id",
    RoleID:         role.ID,
})
assignments, _ := env.RoleAssignments(ctx)
env.UnassignRole(ctx, iamclient.RoleAssignment{RoleID: role.ID, OrganizationID: "org-id", UserID: "user-id"})

// Direct grants
grant, _ := env.PutGrant(ctx, iamclient.Grant{...})
grants, _ := env.Grants(ctx)
g, _ := env.Grant(ctx, "grant-id")
env.DeleteGrant(ctx, "grant-id")
```

#### Service Accounts

```go
sa, _ := env.CreateServiceAccount(ctx, iamclient.ServiceAccount{
    Name:          "CI Pipeline",
    ApplicationID: "app-id",
    ResourceID:    "res-id",
    Permissions:   []string{"deploy:execute"},
    ExpiresIn:     "720h",  // or "never"
})
// sa.Secret is the ik_svc_ credential — store securely
accounts, _ := env.ServiceAccounts(ctx)
env.RevokeServiceAccount(ctx, sa.ID)
```

#### OAuth Clients

```go
cred, _ := env.CreateOAuthClient(ctx, iamclient.OAuthClient{
    ApplicationID: "app-id",
    ResourceID:    "res-id",
    RedirectURIs:  []string{"https://app.example/callback"},
    Public:        true,  // for SPAs using PKCE
})
clients, _ := env.OAuthClients(ctx)
env.DisableOAuthClient(ctx, cred.ClientID)
```

#### Federation (SSO)

```go
fed, _ := env.CreateFederation(ctx, iamclient.Federation{
    Name:      "Google",
    Issuer:    "https://accounts.google.com",
    ClientID:  "google-client-id",
    SecretEnv: "GOOGLE_CLIENT_SECRET",
})
connections, _ := env.FederationConnections(ctx)
conn, _ := env.FederationConnection(ctx, fed.ID)
identities, _ := env.FederationIdentities(ctx, fed.ID)
env.DisableFederation(ctx, fed.ID)
env.LinkExternalIdentity(ctx, iamclient.ExternalIdentity{
    ConnectionID: fed.ID, UserID: "user-id", Subject: "google-sub",
})
env.UnlinkExternalIdentity(ctx, fed.ID, "user-id")
```

#### Provisioning Credentials

```go
cred, _ := env.CreateProvisioningCredential(ctx, iamclient.Credential{})
creds, _ := env.ProvisioningCredentials(ctx)
env.RevokeProvisioningCredential(ctx, cred.ID)
```

#### Impersonation, Sessions & Audit

```go
tokens, _ := env.Impersonate(ctx, iamclient.Impersonation{
    OrganizationID: "org-id",
    ApplicationID:  "app-id",
    ResourceID:     "res-id",
    UserID:         "user-id",
    Reason:         "Customer support ticket #1234",
})
sessions, _ := env.Sessions(ctx)
env.RevokeSession(ctx, "session-id")
events, _ := env.AuditEvents(ctx)
```

---

## authclient — Identity API

Used by **frontends** and **backends** for user authentication. No management credential needed for login flows.

### Setup

```go
import "github.com/Abraxas-365/iamkit/sdk/authclient"

client := authclient.New("http://localhost:8080",
    authclient.WithHTTPClient(myHTTPClient), // optional
)
```

### Password Login

```go
tokens, err := client.Login(ctx, authclient.PasswordLogin{
    LoginContext: authclient.LoginContext{
        EnvironmentID:  "env-uuid",
        OrganizationID: "org-uuid",
        ApplicationID:  "app-uuid",
        ResourceID:     "res-uuid",
    },
    Email:    "alice@example.com",
    Password: "password",
})
// tokens.AccessToken, tokens.RefreshToken
```

### Token Refresh

```go
newTokens, _ := client.Refresh(ctx, authclient.LoginContext{...}, tokens.RefreshToken)
```

### Machine Tokens (Service Accounts)

```go
tokens, _ := client.MachineToken(ctx, "ik_svc_...")
```

### Email Challenges (OTP)

```go
challenge, _ := client.InitiateChallenge(ctx, "env-uuid", "alice@example.com", "login")
// User receives email with code
tokens, _ := client.VerifyChallenge(ctx, authclient.ChallengeVerification{
    LoginContext: authclient.LoginContext{...},
    ChallengeID:  challenge.ID,
    Code:         "123456",
    Purpose:      "login",
})
```

### SSO Federation

```go
result, _ := client.StartFederation(ctx, authclient.FederationStart{
    LoginContext: authclient.LoginContext{
        EnvironmentID:  "env-uuid",
        OrganizationID: "org-uuid",
        ApplicationID:  "app-uuid",
        ResourceID:     "res-uuid",
    },
    ConnectionID: "google-connection-uuid",
})
// Redirect user to result.AuthorizationURL
// IAMKit handles the callback and issues tokens
```

### Profile & Organizations

```go
profile, _ := client.Profile(ctx, accessToken, "env-uuid", "audience")
client.UpdateProfile(ctx, accessToken, "env-uuid", "audience", "New Name")
orgs, _ := client.Organizations(ctx, accessToken, "env-uuid", "audience")
```

### Self-Service Membership

```go
client.AddMember(ctx, accessToken, authclient.AddMemberRequest{
    EnvironmentID: "env-uuid",
    Audience:      "audience",
    UserID:        "user-uuid",
})
```

### Logout

```go
client.Logout(ctx, accessToken, "env-uuid", "audience")
```

### Token Validation

#### Offline (JWT, no network call)

```go
claims, err := authclient.Validate(
    rawJWT,
    publicKey,       // *rsa.PublicKey from IAMKit's JWKS
    "https://iam.example",  // expected issuer
    "billing.myapp.com",    // expected audience
    "env-uuid",
    "app-uuid",
    "res-uuid",
)
if claims.HasPermission("invoices:read") { ... }
```

#### Online (checks revocation)

```go
claims, err := client.Introspect(ctx, accessToken,
    "https://iam.example",  // issuer
    "billing.myapp.com",    // audience
    "env-uuid", "app-uuid", "res-uuid",
)
```

### Fiber v2 Middleware

```go
import "github.com/Abraxas-365/iamkit/sdk/authclient/fiberauth"

// With offline validation
app.Use(fiberauth.Authenticate(func(ctx context.Context, token string) (*authclient.Claims, error) {
    return authclient.Validate(token, pubKey, issuer, audience, env, app, resource)
}))

// With online introspection
app.Use(fiberauth.Authenticate(func(ctx context.Context, token string) (*authclient.Claims, error) {
    return client.Introspect(ctx, token, issuer, audience, env, app, resource)
}))

// Protect routes
app.Get("/invoices", fiberauth.RequirePermissions("invoices:read"), handler)
app.Get("/org/:id/data", fiberauth.RequireOrganization(orgID), handler)

// Access claims in handlers
func handler(c *fiber.Ctx) error {
    claims := fiberauth.Claims(c)
    fmt.Println(claims.Subject, claims.Permissions)
}
```

### net/http Middleware (framework-neutral)

Use this instead of `fiberauth` for stdlib `net/http`, chi, gorilla/mux, or
any router built on `http.Handler` (gin and echo can wrap it via their own
`gin.WrapH`/`echo.WrapMiddleware` adapters). Same claims type, same JSON
error format, same `Authenticate`/`RequirePermissions`/`RequireOrganization`
shape as `fiberauth`.

```go
import "github.com/Abraxas-365/iamkit/sdk/authclient/httpauth"

validate := func(ctx context.Context, token string) (*authclient.Claims, error) {
    return client.Introspect(ctx, token, issuer, audience, env, app, resource) // or authclient.Validate for offline
}

// Direct handler wrapping
mux := http.NewServeMux()
mux.Handle("/invoices", httpauth.Authenticate(validate,
    httpauth.RequireOrganization(
        httpauth.RequirePermissions(invoicesHandler, "invoices:read"),
        orgID,
    ),
))

// Middleware-chain style (chi, gorilla/mux, etc.)
r.Use(httpauth.Middleware(validate))
r.With(
    httpauth.RequireOrganizationMiddleware(orgID),
    httpauth.RequirePermissionsMiddleware("invoices:read"),
).Get("/invoices", invoicesHandler)

// Access claims in handlers
func invoicesHandler(w http.ResponseWriter, r *http.Request) {
    claims := httpauth.Claims(r)
    fmt.Println(claims.Subject, claims.Permissions)
}
```

### OAuth2 / PKCE

```go
oauth := authclient.NewOAuth("http://localhost:8080", "client-id", "client-secret",
    authclient.WithOAuthHTTPClient(myHTTPClient),
)

// For public clients (SPAs), generate PKCE parameters
verifier, challenge, _ := authclient.NewPKCE()

// Exchange authorization code for tokens
tokens, _ := oauth.Exchange(ctx, code, "https://app.example/callback", verifier)

// Refresh
newTokens, _ := oauth.Refresh(ctx, tokens.RefreshToken)

// Revoke
oauth.Revoke(ctx, tokens.AccessToken)
```

---

## scimclient — SCIM 2.0 Provisioning

Used by enterprise identity providers to sync users. Requires a provisioning credential (`ik_scim_*`).

```go
import "github.com/Abraxas-365/iamkit/sdk/scimclient"

client := scimclient.New("http://localhost:8080", "ik_scim_...",
    scimclient.WithHTTPClient(myHTTPClient),
)

// Create
user, _ := client.Create(ctx, scimclient.User{
    UserName:    "alice@example.com",
    DisplayName: "Alice",
})

// Read
user, _ = client.Get(ctx, user.ID)
list, _ := client.List(ctx, `userName eq "alice@example.com"`, 1, 10)

// Update
user, _ = client.Replace(ctx, user.ID, scimclient.User{...})
user, _ = client.Patch(ctx, user.ID, []scimclient.Operation{
    {Op: "replace", Path: "displayName", Value: "Alice Smith"},
})

// Delete
client.Delete(ctx, user.ID)
```

---

## Error Handling

All clients return typed errors for API failures:

```go
import "github.com/Abraxas-365/iamkit/sdk/apierror"

_, err := client.Login(ctx, input)
var apiErr *apierror.Error
if errors.As(err, &apiErr) {
    fmt.Printf("Code: %s, Message: %s, HTTP: %d\n",
        apiErr.Code, apiErr.Message, apiErr.HTTPStatus)
}
```

OAuth endpoints return `*authclient.OAuthError` instead:

```go
var oauthErr *authclient.OAuthError
if errors.As(err, &oauthErr) {
    fmt.Printf("%s: %s\n", oauthErr.Code, oauthErr.Description)
}
```
