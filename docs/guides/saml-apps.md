# SAML applications (IAMKit as the identity provider)

Some applications — SaaS tools, internal portals, older enterprise software —
sign users in only with SAML 2.0. IAMKit can be their **identity provider**
(IdP): the application (the **service provider**, SP) sends the browser to
IAMKit, the user signs in on the [hosted pages](hosted-login.md) with any
method the environment allows (password, email code, passkey, social login,
organization SSO, second factor…), and the browser posts a signed SAML
response back to the application.

This is the opposite direction of [SAML single sign-on](saml.md), where an
organization's own IdP signs users in to IAMKit. Both can be used together:
an Okta user can sign in to IAMKit through a SAML connection and continue to a
SAML application IAMKit serves.

A SAML application signs users in to one **application/resource pair**, like
an OAuth client: the session IAMKit creates carries that application and
resource, and the user's permissions on the resource can be sent as an
attribute.

## Prerequisites

- An HTTPS `JWT_ISSUER`: the IdP endpoints live under it.
- An application with the resource linked (`POST …/application-resources`).
- IAMKit signs responses with the environment's active
  [signing key](signing-keys.md) (the deployment key without one) and a
  self-signed certificate derived from it, the same on every replica.
  **Rotating the environment signing key changes the certificate**: service
  providers that read the metadata URL pick it up; those configured with a
  pasted certificate need the new one.

## 1. Give the service provider IAMKit's settings

Console **Applications → SAML applications** shows them; or
`iam saml-apps idp`, `GET …/saml/identity-provider`:

| Setting | Value |
| --- | --- |
| Metadata URL (also the IdP entity ID / Issuer) | `{JWT_ISSUER}/saml/{environment}/metadata` |
| Single sign-on URL (HTTP-Redirect and HTTP-POST) | `{JWT_ISSUER}/saml/{environment}/sso` |
| Signing certificate | PEM, RSA-SHA256 signatures |
| NameID formats | `emailAddress`, `persistent` |

Most service providers take the metadata URL; otherwise paste the three other
values.

## 2. Register the service provider

You need its **entity ID** (the Issuer of its AuthnRequests) and its
**assertion consumer service (ACS) URL(s)**, from its metadata or settings
page.

```bash
iam saml-apps create --name Wiki --application APP_ID --resource RES_ID \
  --entity-id https://wiki.example.com/saml \
  --acs https://wiki.example.com/saml/acs \
  --attr mail=email --attr displayName=name --attr roles=permissions
```

or `POST /management/v1/environments/$ENV/saml/service-providers` with
`{name, application_id, resource_id, entity_id, acs_urls, name_id_format,
attributes}`, the SDK's `CreateSAMLApp`, or the console.

- `acs_urls`: 1–10 HTTPS URLs. The response goes to the one the AuthnRequest
  names (by URL or index) — only if registered — or to the first.
- `name_id_format`: `email` (default; the user's email address, format
  `emailAddress`) or `persistent` (IAMKit's stable user ID).
- `attributes`: SAML attribute name → source. Sources: `email`, `name`,
  `user_id`, `organization_id` (the organization chosen at sign-in; omitted
  when none), `permissions` (the user's permissions on the resource, one value
  each). At most 32; none by default.
- An entity ID is registered once per environment (409 otherwise); the
  resource must be linked to the application (409 otherwise), and stays
  linked while the SAML application exists.

## 3. Sign in

SP-initiated sign-in only: the user opens the application, which sends an
AuthnRequest to the SSO URL. IAMKit checks it (version, `IssueInstant`
within 90 seconds of its clock, `Destination`, HTTP-POST response binding, a registered
issuer and ACS URL), parks it for 10 minutes and sends the browser to
`/hosted/login`. The hosted journey is the ordinary one, branded with the
environment's [default branding](hosted-login.md#branding) and sign-in
methods. When it completes, IAMKit creates the session and renders a page
that posts the signed response (auto-submitted, with a **Continue** button
fallback) to the ACS URL, with the `RelayState` the SP sent.

The response and its assertion are both signed. The assertion carries the
NameID, the attributes, `InResponseTo` = the AuthnRequest ID, the SP entity
ID as audience and `SessionIndex` = the IAMKit session ID. Assertions are not
encrypted.

Every response sent is audited `saml.assertion_issued` (actor = the user,
target = the service provider). Registrations are audited
`saml_service_provider.create`/`.update`/`.delete`.

## Security

- The pending request is bound to the browser (the same cookie as OAuth
  hosted logins) and answered once; another browser gets 401.
- Responses only go to registered ACS URLs of the registered entity ID, so
  a forged AuthnRequest cannot send an assertion elsewhere.
- AuthnRequest signatures are not verified; the metadata does not ask for
  signed requests.
- The SSO endpoint is rate limited (30/min per IP), metadata 60/min.

## Not supported (yet)

IdP-initiated sign-in, single logout (SLO), encrypted assertions and the
HTTP-Artifact binding. Deleting a SAML application does not end sessions
already open in it.

## Manage

| Task | CLI | API |
| --- | --- | --- |
| List | `iam saml-apps list [--application APP_ID]` | `GET …/saml/service-providers` |
| Show | `iam saml-apps get SP_ID` | `GET …/saml/service-providers/:id` |
| Change | `iam saml-apps update SP_ID --acs URL --name-id-format persistent --attr mail=email` (`--clear-attrs` for none) | `PATCH …/saml/service-providers/:id` |
| Delete | `iam saml-apps delete SP_ID` | `DELETE …/saml/service-providers/:id` |
