# Management and scoped Go clients

Construct `iamclient.New(baseURL, managementKey, iamclient.WithHTTPClient(client))`
for operator administration. `Environment(environmentID)` supplies typed entity
methods. `CreateProject`, `CreateEnvironment`, `CreateUser`, `AddMember`,
`BindResource`, `PutGrant` and integration helpers mirror management operations.
Use `context.WithTimeout` and check every returned error before using an ID.
Invitations: `Invite`, `Invitations(ctx, org, status)` (status filtered
client-side on the first page), `Invitation`, `ResendInvitation` and
`RevokeInvitation`; the issued token is returned only by `Invite` and resend.
OAuth clients: `CreateOAuthClient` (`OAuthClient.PostLogoutRedirectURIs` for
`/oauth/end_session`), `OAuthClients`, `DisableOAuthClient` and
`UpdateOAuthClient` (`OAuthClientPatch` `HostedLogin`, `RedirectURIs`,
`PostLogoutRedirectURIs`, `GrantTypes`, `AccessTokenFormat`, `TokenEndpointAuthMethod`, `TokenEndpointAuthAlg`,
`JWKS`, `JWKSURI`; nil fields unchanged). `ClientAuthentication` (embedded in
`OAuthClient` and `ServiceAccount`) sets token endpoint authentication
(`AuthClientSecretBasic`, `AuthClientSecretPost`, `AuthPrivateKeyJWT`);
`ServiceAccount(ctx, id)` and `SetServiceAccountAuthentication` read and change
a service account's. `SetServiceAccountImpersonation(ctx, id, allowed)`
(workspace owners) lets it impersonate users through token exchange
(`ServiceAccount.CanImpersonate`). `OAuthClient.AccessTokenFormat` is `AccessTokenJWT`
(default) or `AccessTokenOpaque`. `OAuthClient.GrantTypes` (empty: authorization
code + refresh token) takes `GrantAuthorizationCode`, `GrantRefreshToken`,
`GrantDeviceCode` (needs `HostedLogin`; device-only clients need no
`RedirectURIs`) and `GrantTokenExchange` (confidential clients only). Opaque tokens are not accepted by
`authclient.Validator` or the IAMKit APIs — resolve them with `Introspect`.
Back-channel logout: `OAuthClient.BackchannelLogoutURI` /
`BackchannelLogoutSessionRequired` (and the same `OAuthClientPatch` pointers;
`""` turns it off); `LogoutDeliveries(ctx, status)` and
`RetryLogoutDelivery(ctx, id)` read and requeue deliveries. Receivers verify the
POSTed token with `authclient.ValidateLogoutToken`.
Hosted login: `OAuthClient.HostedLogin` at creation, `UpdateOAuthClient(ctx, id,
OAuthClientPatch{HostedLogin: &on})`, branding with `LoginSettings` /
`SetLoginSettings` (`LoginTheme` for mode, colors, header and footer), and per-client
styles with `ClientLoginStyles`, `ClientLoginSettings`, `SetClientLoginSettings` and
`DeleteClientLoginSettings` (see [hosted login](../../guides/applications/hosted-login.md)).
Sign-in methods per client: `ClientSignIn`, `ClientSignIns`, `SetClientSignIn(ctx,
client, SignIn{...})` and `DeleteClientSignIn`. Social login: `CreateFederation`
with `Provider` (`ProviderGoogle`, `ProviderMicrosoft`, `ProviderGitHub`,
`ProviderApple`, `ProviderGitLab`, `ProviderGitHubEnterprise`, `ProviderOAuth2`),
`Options *FederationOptions` (`BaseURL`; for OAuth 2.0 the endpoints, `Scopes`
and `Claims *FederationClaimMap`) and `Signup`/`LinkEmail`/`UpdateProfile`; the
detail's `CallbackURL` is the redirect URI to register (see
[social login](../../guides/enterprise/social-login.md)).
MFA: `SetOrganizationMFA(ctx, org, OrganizationMFA{Required: &on})`,
`SetOrganizationFactors(ctx, org, OrganizationFactors{AllowedFactors: …})`,
`SignInPolicy.AllowedFactors`, `UserFactors` and `ResetUserFactors`; the SMS
provider: `SMSConfig`, `SetSMSConfig`, `DeleteSMSConfig`, `SMSStatus`,
`TestSMS` (see [MFA](../../guides/sign-in/mfa.md)).
Signing keys: `SigningKeys`, `SigningKey(ctx, kid)`, `CreateSigningKey`,
`ActivateSigningKey(ctx, kid)` and `RetireSigningKey(ctx, kid, force)` (see
[signing keys](../../guides/applications/signing-keys.md)).
Feature flags: `Features`, `Feature(ctx, name)`, `SetFeature(ctx, name,
enabled)` and `ResetFeature(ctx, name)` (see
[feature flags](../../guides/platform/feature-flags.md)).

Usage and limits: `Limits`, `SetLimits(ctx, map[string]int64)` (the
`Limit*` constants name them) and `Usage(ctx, days)` (see
[usage and limits](../../guides/platform/usage-limits.md)).
SAML applications (IAMKit as the identity provider): `SAMLIdentityProvider`,
`SAMLApps`, `SAMLApp(ctx, id)`, `CreateSAMLApp`, `UpdateSAMLApp(ctx, id, …)`
and `DeleteSAMLApp(ctx, id)` (see [SAML applications](../../guides/applications/saml-apps.md)).
User states: `User.State` (`UserSuspended`, `UserLocked`, `UserInitial`,
`UserInactive`, `UserActive`) and `LastSignedInAt`, `UsersInState`,
`DeactivateUser` and `ReactivateUser` (also on `apiclient`, with
`iam:users:read`/`iam:users:write`; see [user states](../api/users-and-organizations.md#user-states)).
Machine users: `CreateMachineUser`, `MachineUsers`, `User.Kind`, `CreateAccessToken`
(answers `IssuedAccessToken.Token`, shown once), `AccessTokens` and
`RevokeAccessToken`, keys `AddUserKey` (answers `IssuedUserKey.PrivateKey` for a
generated pair, shown once), `UserKeys` and `RemoveUserKey` (also on `apiclient`,
with `iam:users:read`/`iam:users:write`; see [machine users](../../guides/machines/machine-users.md)).
Metadata and profiles: `UserMetadata`, `SetUserMetadata`, `DeleteUserMetadata`,
`OrganizationMetadata`, `SetOrganizationMetadata`, `DeleteOrganizationMetadata`,
`UpdateUserProfile` (merge patch), `UserSchema`, `SaveUserSchema` (answers
`NonConforming`) and `DeleteUserSchema`; `User.Profile` (also on `apiclient`;
see [metadata and profiles](../../guides/organizations/user-profiles.md)).
Passwords: `PasswordPolicy`, `SetPasswordPolicy` (replaces the whole policy),
`DeletePasswordPolicy` and `UnlockUser` (also on `apiclient`, with
`iam:users:write`); a rejected password is `apierror.CodePasswordPolicy` with
`Rule()` naming the failed rule (see [password policy](../../guides/sign-in/password-policy.md)).
Organization password requirements: `OrganizationPasswordPolicy`,
`SetOrganizationPasswordPolicy`, `DeleteOrganizationPasswordPolicy`.
Organization branding (nil fields inherit, see
[organization branding](../../guides/applications/hosted-login.md#organization-branding)):
`OrganizationBranding`, `SetOrganizationBranding`, `DeleteOrganizationBranding`;
organization administrators use `apiclient` `OrgAdmin.Branding`/`SaveBranding`/`DeleteBranding`
and `PasswordPolicy`/`SetPasswordPolicy`/`DeletePasswordPolicy`.
Sign-in texts (per language; `TextScope{}` = environment, or one of
`ClientID`/`OrganizationID`, see [sign-in texts](../../guides/applications/hosted-login.md#sign-in-texts)):
`SignInTextCatalog`, `SignInTextSets`, `SignInTexts`, `SetSignInTexts`,
`DeleteSignInTexts`. Page previews (HTML): `PreviewPage(ctx, scope,
PageOptions{Page, Scheme, Locale, SignIn})`, `PreviewDraftPage` (unsaved
branding) and `PreviewSignInTexts` (unsaved texts).
Groups (see [groups](../../guides/organizations/organizations.md#groups-and-group-roles)): `Groups(ctx, org,
GroupFilter{…})`, `Group`, `CreateGroup`, `UpdateGroup`, `DeleteGroup`,
`GroupMembers`, `ChangeGroupMembers`, `MemberGroups`, `AssignGroupRole`,
`UnassignGroupRole`, `GroupRoleAssignments` and `EffectiveRoles` (direct and
group-inherited roles, each with its `Source`).
Incident actions: `RevokeUserSessions`, `RequirePasswordChange`;
`DeleteUserPermanently` erases a user (`SuspendUser` only deactivates).
`EnableFederation` re-enables a disabled connection. `LoginOptions` (no
environment) lists the operator console's sign-in methods.
Sign-in methods: `SignInPolicy`, `SetSignInPolicy`, `DeleteSignInPolicy` and,
per organization, `SetOrganizationMethods` (see
[sign-in methods](../../guides/sign-in/sign-in-methods.md)). Passkeys:
`SignInPolicy.AllowPasskey`, `OrganizationMethods.Passkey` and
`SignIn.Passkey` for hosted clients (see [passkeys](../../guides/sign-in/mfa.md#passkeys)).
Organization admin portal: `OrgAdminPortal`, `EnableOrgAdminPortal` (returns
the link in `URL`) and `DisableOrgAdminPortal` (see
[hosted portal](../../guides/organizations/organization-administration.md#hosted-portal)).
Resource grants: `SetResourceAccess(ctx, resource, ResourceAccess{OwnerOrganizationID, RequireGrant})`,
`ResourceGrants`, `ResourceGrant`, `PutResourceGrant` (`RoleIDs` nil = every
role) and `DeleteResourceGrant`; `Resource.OwnerOrganizationID`/`RequireGrant`
(`ResourceGrants(ctx, resource, organization)` filters, "" for any; see [resource grants](../../guides/organizations/organization-administration.md#resource-grants-vendor-organizations)).
Event log (also on `apiclient`, with `iam:events:read`; see
[event log](../events.md)): `Events(ctx, EventFilter{Types, Subject,
OrganizationID, After, Before, Limit})` returns an `EventPage{Items, Next}`.
To follow the log, start with `After` pointing at `0` and pass `Next` back as
`After`; the cursor stays put while nothing new arrives.
`History(ctx, collection, id, EventFilter{Before, Limit, Types})` reads one
entity's [change history](../events.md#change-history) and
`ExportEvents(ctx, filter, func(Event) error)` streams the
[export](../events.md#export) oldest first.
Event webhooks (also on `apiclient`, with `iam:webhooks:read`/`write`; see
[event webhooks](../event-webhooks.md)): `Webhooks`, `Webhook`,
`CreateWebhook(ctx, WebhookInput{Name, URL, Types})` → `WebhookSecret` (shown
once), `UpdateWebhook` (`Active` re-enables), `DeleteWebhook`,
`RotateWebhookSecret`, `TestWebhook` (`iamclient`), `ReplayWebhook(ctx, id,
from)`, `WebhookDeliveries(ctx, id, status)` and `RetryWebhookDelivery`.
Receivers verify requests with package `sdk/webhook` (`webhook.Verify(secret,
r)` → `webhook.Event`).
[Actions](../../guides/platform/actions.md) (`iamclient` only): `ActionConditions`,
`ActionTargets`, `ActionTarget`, `CreateActionTarget(ctx,
ActionTargetInput{Name, URL, Kind, TimeoutMS, InterruptOnError})` →
`ActionSecret` (shown once), `UpdateActionTarget`, `DeleteActionTarget`,
`RotateActionTargetSecret`, `TestActionTarget(ctx, id, condition, input)`,
`ActionExecutions`, `SetActionExecution(ctx, condition, targets)`,
`DeleteActionExecution` and `ActionCalls(ctx, ActionCallFilter{…})`.
Endpoints answer with package `sdk/action` (`action.Verify(secret, r)` →
`action.Input`; `action.Write(w, action.Response{…})`, `action.Deny(msg)`).

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
Its `Environment` has the same methods and types as `iamclient`'s for every
route the two APIs share (`apiclient.User` is `iamclient.User`, and so on):
users, organizations, members, groups, domains, invitations, org structure,
applications, resources, roles, grants, service accounts, delivery, SMS,
events, webhooks and usage, each gated by its `iam:*` permission.
Exchange a service credential with `authclient.MachineToken` (or
`authclient.NewOAuth(url, accountID, secret).ClientCredentials`), pass its access JWT,
and refresh that token through another exchange when needed. `SetToken` updates
the client's token; coordinate concurrent use rather than racing token mutation.
Never pass raw `ik_svc_` credentials to `apiclient`.

`Environment.OrgAdmin(organization)` returns an `apiclient.OrgAdmin` for
[organization administration](../../guides/organizations/organization-administration.md):
pass the access token of a user signed in to that organization for the IAM
resource. It covers settings, members, home users, roles, invitations,
domains, SSO connections, audit events and resource grants (`Resources`,
`ResourceGrants`, `GrantedResources`, `PutResourceGrant`,
`DeleteResourceGrant`). `User.HomeOrganizationID`,
`CreateUser.HomeOrganizationID`, `UserPatch`/`UpdateUser.HomeOrganizationID` and
`Role.SystemRole` exist on both clients.

Management authority is workspace-wide. Scoped IAM writes require explicit IAM
permissions and still deserve privileged-backend isolation. Neither client belongs
in browser code. See the [scoped IAM API](../api/scoped-iam.md) for the permission
each route family needs.
