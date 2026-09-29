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
applications — see [SAML applications](saml-apps.md).

## Prerequisites

- An HTTPS `JWT_ISSUER`: the SP endpoints live under it.
- A verified domain of the organization, as for any organization SSO.
- IAMKit signs requests and decrypts assertions with the environment's active
  [signing key](signing-keys.md) (the deployment key without one). Its
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
| `sign_requests` | Sign AuthnRequests (RSA-SHA256) for IdPs that require it. |

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
`sign_requests`).

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
[hosted login](hosted-login.md) needs no change. The cross-site POST to the
ACS carries no cookie; IAMKit parks the response for its RelayState and the
303 continues in the browser that holds the binding cookie.

IAMKit accepts a response only if:

- the response or the assertion is signed by a certificate in the IdP
  metadata (XML signature wrapping is refused);
- it answers this login's AuthnRequest (`InResponseTo`) — IdP-initiated
  logins are not accepted;
- its audience is the SP entity ID, its destination/recipient the ACS URL,
  and it is within `NotBefore`/`NotOnOrAfter` (with a small clock skew);
- its assertion ID was never used on this connection (replays are refused);
- it has a subject (a non-transient NameID or the mapped attribute).

Encrypted assertions are decrypted with the environment key. Every refusal is
a 401 on the callback.

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

- SP-initiated HTTP-Redirect → HTTP-POST only; no artifact binding, no
  IdP-initiated login, no SAML single logout (end sessions with
  [session revocation](../concepts/sessions-and-tokens.md)).
- One IdP per connection; create one connection per IdP.
- Responses up to 64 KiB.

## Verify

A first login JIT-provisions a member (or links one by email with
`link_email`); the next logins find the linked subject. Check the identities
list (`origin` `jit`/`email`/`linked`), a refused login from an email outside
the verified domains (401), and `SSO_REQUIRED` for passwords after enforcing.
