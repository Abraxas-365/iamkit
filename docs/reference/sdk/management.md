# Management and scoped Go clients

Construct `iamclient.New(baseURL, managementKey, iamclient.WithHTTPClient(client))`
for operator administration. `Environment(environmentID)` supplies typed entity
methods. `CreateProject`, `CreateEnvironment`, `CreateUser`, `AddMember`,
`BindResource`, `PutGrant` and integration helpers mirror management operations.
Use `context.WithTimeout` and check every returned error before using an ID.
Invitations: `Invite`, `Invitations(ctx, org, status)` (status filtered
client-side on the first page), `Invitation`, `ResendInvitation` and
`RevokeInvitation`; the issued token is returned only by `Invite` and resend.
Hosted login: `OAuthClient.HostedLogin` at creation, `UpdateOAuthClient(ctx, id,
OAuthClientPatch{HostedLogin: &on})`, branding with `LoginSettings` /
`SetLoginSettings` (`LoginTheme` for mode, colors, header and footer), and per-client
styles with `ClientLoginStyles`, `ClientLoginSettings`, `SetClientLoginSettings` and
`DeleteClientLoginSettings` (see [hosted login](../../guides/hosted-login.md)).
Sign-in methods per client: `ClientSignIn`, `ClientSignIns`, `SetClientSignIn(ctx,
client, SignIn{...})` and `DeleteClientSignIn`. Social login: `CreateFederation`
with `Provider` (`ProviderGoogle`, `ProviderMicrosoft`, `ProviderGitHub`,
`ProviderApple`), `Options *FederationOptions` and `Signup`/`LinkEmail`; the
detail's `CallbackURL` is the redirect URI to register (see
[social login](../../guides/social-login.md)).
MFA: `SetOrganizationMFA(ctx, org, OrganizationMFA{Required: &on})`,
`UserFactors` and `ResetUserFactors` (see [MFA](../../guides/mfa.md)).
Passwords: `PasswordPolicy`, `SetPasswordPolicy` (replaces the whole policy),
`DeletePasswordPolicy` and `UnlockUser` (also on `apiclient`, with
`iam:users:write`); a rejected password is `apierror.CodePasswordPolicy` with
`Rule()` naming the failed rule (see [password policy](../../guides/password-policy.md)).

For a list returning a page, a low-level pattern is:

```go
var page struct {
    Items []iamclient.User `json:"items"`
    Page struct { Total, Limit, Offset int } `json:"page"`
}
err := client.Do(ctx, "GET", "/environments/"+environmentID+"/users", nil, &page)
```

This is a fragment: construct the client/context and use a trusted UUID first.
Typed slice list methods currently need envelope compatibility work; see
[SDK overview](go.md). The low-level management path cannot contain `?`, so use
explicit HTTP URL query handling for filters until a matching helper exists.

`apiclient.New(baseURL, jwt, ...)` targets `/api/v1`, not `/management/v1`.
Exchange a service credential with `authclient.MachineToken`, pass its access JWT,
and refresh that token through another exchange when needed. `SetToken` updates
the client's token; coordinate concurrent use rather than racing token mutation.
Never pass raw `ik_svc_` credentials to `apiclient`.

Management authority is workspace-wide. Scoped IAM writes require explicit IAM
permissions and still deserve privileged-backend isolation. Neither client belongs
in browser code. See the [scoped IAM API](../api/scoped-iam.md) for the permission
each route family needs.
