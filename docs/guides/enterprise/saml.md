# SAML 2.0 single sign-on

An organization whose identity provider speaks SAML 2.0 (Okta, Microsoft
Entra ID, ADFS, OneLogin, PingFederate, Google Workspace, Keycloak, Shibboleth…)
signs in to IAMKit through a **SAML connection**. IAMKit is the service
provider (SP); the organization's identity provider (IdP) authenticates the
user. A SAML connection is an [organization connection](federation.md#organization-sso):
discovery, just-in-time provisioning, the default group, enforcement, linking
members by email and profile sync all work as for OIDC connections.

SAML connections always belong to one organization (`organization_id` is
required). They have no client ID or secret: IAMKit reads the IdP's metadata.

For the opposite direction — IAMKit as the identity provider of SAML
applications — see [SAML applications](../applications/saml-apps.md).

## Prerequisites

- An HTTPS `JWT_ISSUER`: the SP endpoints live under it.
- A verified domain of the organization, as for any organization SSO.
- IAMKit signs requests and decrypts assertions with the environment's active
  [signing key](../applications/signing-keys.md) (the deployment key without one). Its
  certificate is self-signed and derived from the key, so every replica serves
  the same one. **Rotating the environment signing key changes the SP
  certificate**: if the IdP encrypts assertions or checks signed requests,
  give it the new SP metadata after the rotation.

## 1. Create the connection

With the IdP's metadata URL (fetched now, over HTTPS to a public address):

```bash
curl -X POST "$IAMKIT/management/v1/environments/$ENV/federation-connections" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{
    "provider": "saml", "name": "Acme Okta", "organization_id": "'$ORG'",
    "options": {"metadata_url": "https://acme.okta.com/app/exk…/sso/saml/metadata"}
  }'
```

or with the metadata XML itself (`"metadata_xml": "<EntityDescriptor …>"`, at
most 512 KiB). The metadata needs an HTTP-Redirect single sign-on service
(HTTPS) and a signing certificate. The CLI equivalent:

```bash
iam federation create --provider saml --name "Acme Okta" --organization $ORG \
  --metadata-url https://acme.okta.com/app/exk…/sso/saml/metadata
```

The console offers **SAML 2.0** under Sign-in providers → Organization SSO.

Options:

| Option | Meaning |
| --- | --- |
| `metadata_url` / `metadata_xml` | Exactly where the IdP metadata comes from (one is required). |
| `name_id_format` | `unspecified` (default), `persistent`, `email` or `transient`: the NameID format IAMKit asks for. |
| `attributes.subject` | Attribute with a stable user ID. Without it the NameID is the subject. Required with `transient` (transient NameIDs change at every login). |
| `attributes.email` | Attribute with the email. Default: `email`, `mail`, `emailaddress`, `urn:oid:0.9.2342.19200300.100.1.3`, the WS-Federation email claim, then an `email`-format NameID. |
| `attributes.name` | Attribute with the display name. Default: `displayName`, `cn`, the WS-Federation display name, or `givenName` + `sn`. |
| `attributes.groups` | Multi-valued attribute with the user's groups, all values read, for [group mapping](federation.md#group-mapping). Default: `groups`, `memberOf`, then `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`. Okta: a group attribute statement; Entra ID: a groups claim (object IDs unless set to names). |
| `sign_requests` | Sign AuthnRequests (RSA-SHA256) for IdPs that require it. |
| `single_logout` | Turn on [single logout](#single-logout). The IdP metadata must publish a SingleLogoutService (HTTP-Redirect or HTTP-POST), else the request is refused (400 `SINGLE_LOGOUT_UNAVAILABLE`). Default off. |
| `idp_initiated_client_id` | OAuth client (with an `initiate_login_uri`) that [IdP-initiated](#idp-initiated-login) responses are handed to. Unset: they are refused. |

Attribute names match an attribute's `Name` or `FriendlyName`,
case-insensitively. The connection's `issuer` is the IdP entity ID and
`client_id` the SP entity ID; the IdP entity ID cannot change later (linked
subjects belong to it).

## 2. Configure the identity provider

`GET …/federation-connections/:id` returns `saml`:

```json
"saml": {
  "entity_id":    "https://iam.example.com/identity/v1/federation/saml/ENV/CONN/metadata",
  "acs_url":      "https://iam.example.com/identity/v1/federation/saml/acs",
  "metadata_url": "https://iam.example.com/identity/v1/federation/saml/ENV/CONN/metadata"
}
```

Give the IdP the SP metadata URL (most IdPs import it), or enter the entity ID
(audience / SP entity ID) and ACS URL (HTTP-POST binding) by hand. Set the
NameID format you chose and release the email attribute. The SP metadata is
public and lists the SP certificate for encryption (and for signing, with
`sign_requests` or `single_logout`). With `single_logout` it also lists the SP's
SingleLogoutService (HTTP-Redirect and HTTP-POST) at
`…/federation/saml/ENV/CONN/slo`: import the metadata into the IdP again after
turning the option on.

## Sign-in flow

```text
Browser → IAMKit /federation/start (or hosted login): connection_id
IAMKit → browser: authorization_url (IdP SSO URL + SAMLRequest, RelayState) + binding cookie
Browser → IdP: authenticate
IdP → browser → IAMKit POST /identity/v1/federation/saml/acs: SAMLResponse + RelayState
IAMKit → browser: 303 to /identity/v1/federation/callback?code=ik_saml_…&state=…
Browser → IAMKit callback (with the binding cookie): verified, signed in
```

The start and callback are the same as for OIDC connections, so an
application that already runs [federation](federation.md#browser-flow) or the
[hosted login](../applications/hosted-login.md) needs no change. The cross-site POST to the
ACS carries no cookie; IAMKit parks the response for its RelayState and the
303 continues in the browser that holds the binding cookie.

IAMKit accepts a response only if:

- the response or the assertion is signed by a certificate in the IdP
  metadata (XML signature wrapping is refused);
- it answers this login's AuthnRequest (`InResponseTo`) — a response with no
  RelayState state is handled as [IdP-initiated](#idp-initiated-login), which
  never signs anybody in;
- its audience is the SP entity ID, its destination/recipient the ACS URL,
  and it is within `NotBefore`/`NotOnOrAfter` (with a small clock skew);
- its assertion ID was never used on this connection (replays are refused);
- it has a subject (a non-transient NameID or the mapped attribute).

Encrypted assertions are decrypted with the environment key. Every refusal is
a 401 on the callback.

## IdP-initiated login

Users also start at the identity provider: they click the IAMKit app tile in
Okta or Entra ID, which posts an *unsolicited* response (no `InResponseTo`) to
the ACS. IAMKit handles this the way WorkOS does — **an unsolicited response
never creates a session**. IAMKit verifies it completely, spends its assertion
ID, and redirects the browser to your application's sign-in endpoint, which
starts an ordinary SP-initiated login.

Set it up:

1. Give an OAuth client of your application a **sign-in endpoint**
   (`initiate_login_uri`: HTTPS, or http on localhost; the console client
   page → **IdP-initiated sign-in**, or
   `iam oauth-clients update CLIENT --initiate-login-uri https://app.example/login`).
2. Name that client on the connection (`options.idp_initiated_client_id`;
   console connection form, org-admin portal, or
   `iam federation update $CONN --idp-initiated-client CLIENT`). It must be an
   active client of the environment with an `initiate_login_uri`, of an
   application the connection's organization can use (its resource is not
   grant-restricted, or the organization owns it or was granted it).
   Without it, a correctly signed IdP-initiated response is refused with `400`
   `IDP_INITIATED_DISABLED`.
3. In the IdP, leave the SP-initiated settings as they are: the same ACS URL
   and audience serve both. The connection is found from the response's
   audience (the SP entity ID embeds environment and connection).

The browser is then sent with `303` to

```
https://app.example/login?iss=<IAMKit issuer>&connection_id=<id>&organization_id=<id>[&target_link_uri=<uri>]
```

(parameters already on `initiate_login_uri` are kept). The endpoint starts a
normal authorization for that connection by adding the hint to
`/oauth/authorize`:

```ts
// GET https://app.example/login?iss=…&connection_id=…&organization_id=…
app.get("/login", (req, res) => {
  const { iss, connection_id, organization_id } = req.query;
  if (iss !== process.env.IAMKIT_ISSUER) return res.status(400).send("unknown issuer");
  const pkce = createPKCE();                       // keep the verifier + state in the session
  res.redirect(client.authorizationUrl({
    redirectUri: "https://app.example/callback",
    state: randomToken(), nonce: randomToken(), codeChallenge: pkce.challenge,
    organizationId: organization_id, connectionId: connection_id,
  }));
});
```

With `connection_id`, the hosted login skips the identifier step and sends the
user straight to that connection's IdP (SP-initiated). The hint is used only
when the connection is active, usable by the client (organization SSO
offered; an environment connection must be one the client shows) and in the
organization of the `organization_id` hint; otherwise the ordinary sign-in
shows, so a stale link reveals nothing. A malformed `connection_id` is a `400`.
The hint is followed once per sign-in: when the user comes back to the same
sign-in page (the IdP's back button, a failed sign-in), the ordinary identifier
page shows instead of another redirect to the IdP.

Rules of the redirect:

- The IdP's `RelayState` is optional and read as URL query parameters. Only
  `client_id` (another active client of the connection's environment with an
  `initiate_login_uri`, usable by the organization) and `redirect_uri`
  (registered on the chosen client; sent as `target_link_uri`) are honoured;
  everything else is ignored, and an unusable `client_id` falls back to the
  connection's client.
- Verification is the same as for SP-initiated responses except for
  `InResponseTo`: signature of the connection's IdP, issuer, destination and
  validity window. The assertion must name this service provider's entity ID in
  an `AudienceRestriction`, the response must carry exactly one assertion, and
  no `SubjectConfirmationData` may carry an `InResponseTo` (a response to one
  of our requests is not unsolicited). A replayed or tampered response is `401`;
  nothing is looked up, no user is created.
- Nothing is revealed before the signature checks out: a response that is
  forged, malformed, for an unknown or inactive connection, or for a
  non-SAML one is the same `401`. Only a correctly signed response from the
  connection's IdP gets `400` `IDP_INITIATED_DISABLED` when the option is off.
- Each accepted response writes a `connection.idp_initiated` event and shares
  the ACS rate limit.

## Single logout

With `options.single_logout` (off by default) IAMKit is the service provider of
SAML single logout, in both directions. Every message is signed: IAMKit signs
what it sends with the environment signing key, and refuses an unsigned, wrongly
signed, mis-addressed (`Destination`), stale or foreign-`Issuer` message with
`401`.

```bash
iam federation update $CONN --metadata-url … --single-logout
```

- **IdP-initiated.** The IdP sends a signed `LogoutRequest` to the SLO endpoint
  (HTTP-Redirect or HTTP-POST). IAMKit ends the sessions that signed in through
  this connection with that NameID (narrowed to the request's `SessionIndex`es
  when it names them), writes a `connection.single_logout` event, and answers
  the IdP with a signed `LogoutResponse` (`Success`; `PartialLogout` when the
  sessions could not be ended). A request is honored once: replays are
  refused and not answered.
- **SP-initiated.** When `/oauth/end_session` ends a session that signed in
  through such a connection, IAMKit then sends the browser to the IdP with a
  signed `LogoutRequest` (a `303`, or an auto-submitted POST form for IdPs that
  only publish the POST binding). The IdP's `LogoutResponse` is accepted once,
  for ten minutes at most, and brings the browser on to the client's
  `post_logout_redirect_uri` (with `state`) or to the hosted signed-out page.
  The IAMKit session has already ended by then; an IdP that fails or never
  answers does not undo it.
- Only sessions created after the option was on are linked to the IdP session
  (NameID, format and `SessionIndex` are stored with the session). Headless
  `POST /identity/v1/logout` and `DELETE /me/sessions` stay local: they never
  call the IdP.

## Updating

`PATCH` with `options` replaces the options whole. Sending `metadata_url`
refetches the metadata (for instance after the IdP rotates its signing
certificate); new `metadata_xml` replaces it. Metadata naming another entity
ID is refused (400): create another connection instead. SAML connections
refuse `client_secret`.

```bash
iam federation update $CONN --metadata-url https://acme.okta.com/app/exk…/sso/saml/metadata
```

## Limits

- SP-initiated sign-in HTTP-Redirect → HTTP-POST only; no artifact binding.
  Single logout is opt-in per connection and needs the IdP to publish a
  SingleLogoutService; there is no SOAP back-channel logout. Without it, end
  sessions with [session revocation](../../concepts/sessions-and-tokens.md).
- IdP-initiated login only hands off to your application's sign-in endpoint
  (see above); it never signs the user in by itself. IdP-initiated
  responses with encrypted assertions are not supported and are refused (the
  audience is not readable before decryption); configure the IdP to sign
  plain assertions for IdP-initiated sign-in. Encrypted assertions work for
  SP-initiated login.
- One IdP per connection; create one connection per IdP.
- Responses up to 64 KiB.

## Verify

A first login JIT-provisions a member (or links one by email with
`link_email`); the next logins find the linked subject. Check the identities
list (`origin` `jit`/`email`/`linked`), a refused login from an email outside
the verified domains (401), and `SSO_REQUIRED` for passwords after enforcing.
