# Identity provider setup guides

Step-by-step setup for the identity providers organizations connect most
often. Every guide is also built into the console and the organization admin
portal as a **guided setup** wizard (**Guided setup** in the console,
**Guided SSO setup** in the portal); the old create form stays reachable there
as **Advanced**. The wizard and this page say the same thing.

Menu names are those of each vendor's admin console at the time of writing and
vendors rename them: when a path differs, look for the setting by its name.

## The flow

1. **Pick the provider.** For SAML the wizard creates a [draft
   connection](#draft-connections): the connection exists before the identity
   provider's metadata does, so IAMKit can show the values the IdP asks for.
2. **Give the IdP IAMKit's values**: for SAML the ACS URL, the entity ID and
   the metadata URL (`GET …/federation-connections/:id` returns them as
   `saml`); for OIDC the redirect URI (`callback_url`). Each has a copy button.
3. **Paste the IdP's values back**: the metadata URL or XML for SAML (saved
   with `PATCH`), the issuer, client ID and client secret for OIDC.
4. **Test.** [Test connection](#test-connection) opens a new tab that signs in
   at the IdP and shows what IAMKit received. Nothing is created.
5. **Enable**, choosing whether the connection is optional or
   [enforced](federation.md#organization-sso) (members of the organization can
   then only sign in with it; test it first).

Nothing signs in through a draft or a connection you have not enabled.

## SAML 2.0

For each provider IAMKit gives the IdP the **ACS URL** (HTTP-POST binding) and
the **entity ID** (the audience); if the IdP can import service provider
metadata, give it the metadata URL instead. Send the user's email as the NameID
(format `emailAddress`) or as an `email` attribute, plus optionally
`displayName` and `groups` (see [group mapping](federation.md#group-mapping)).

| Provider | Where | IdP metadata to bring back |
|----------|-------|----------------------------|
| Okta | Applications → Applications → Create App Integration → SAML 2.0. Single sign-on URL = ACS URL, Audience URI = entity ID, Name ID format EmailAddress, Application username Email. Attribute Statements: `email`, `displayName`; a Group Attribute Statement named `groups` for group mapping | Sign On tab → Metadata URL |
| Microsoft Entra ID | Enterprise applications → New application → Create your own application (non-gallery) → Single sign-on → SAML. Identifier = entity ID, Reply URL = ACS URL. Attributes & Claims: email = `user.mail`, unique identifier = email or UPN; add a groups claim if you map groups (object IDs) | SAML Certificates → App Federation Metadata Url |
| Google Workspace | Admin console → Apps → Web and mobile apps → Add app → Add custom SAML app. ACS URL and Entity ID as given; Name ID format EMAIL, Name ID = Primary email | Download Metadata: a **file**, paste its XML (Google gives no URL) |
| OneLogin | Applications → Add App → SAML Custom Connector (Advanced). Audience (EntityID) = entity ID; Recipient and ACS (Consumer) URL = ACS URL, ACS URL Validator = a regex matching it. Parameters: `email`, optional `name`, `groups` | More Actions → SAML Metadata (XML), or the Issuer URL from the SSO tab |
| JumpCloud | SSO Applications → Custom SAML App. SP Entity ID = entity ID, ACS URL = ACS URL, SAMLSubject NameID = `email`; attribute statements for `email`, `displayName`, `groups`; User Groups tab to assign | Export Metadata (XML) |
| ADFS | AD FS Management → Relying Party Trusts → Add Relying Party Trust (claims aware), import the metadata URL. Claim Issuance Policy: send E-Mail-Addresses as E-Mail Address and Display-Name as Name, then transform E-Mail Address → Name ID (format Email) | `https://<adfs-host>/FederationMetadata/2007-06/FederationMetadata.xml` |
| PingFederate | Applications → Integration → SP Connections → Create Connection (Browser SSO); import IAMKit's metadata URL or enter ACS URL (POST) and entity ID as Partner Entity ID; extend the attribute contract with `email`, `displayName`, `groups` | Export the connection's metadata (XML) |
| Generic | Any SAML 2.0 IdP: custom SAML app, ACS URL, entity ID, NameID email | Metadata URL or XML |

## OpenID Connect

IAMKit's redirect URI is `<issuer>/identity/v1/federation/callback` (shown in
the wizard and as `callback_url`). Register it exactly, with `https://` and the
path.

- **Okta (OIDC)**: Create App Integration → OIDC → Web Application; Sign-in
  redirect URI = the value above. Copy the Client ID and secret; the issuer is
  your Okta domain (or a custom authorization server). Add a `groups` claim to
  the ID token for group mapping.
- **Microsoft Entra ID**: App registrations → New registration, platform Web,
  Redirect URI as above; Certificates & secrets → New client secret (copy its
  **Value**, not the ID). The wizard uses the Microsoft preset, whose issuer
  is derived from the tenant; enter the Directory (tenant) ID to accept only
  your tenant.
- **Google Workspace**: Google Cloud console → APIs & Services → OAuth consent
  screen (user type **Internal**) → Credentials → OAuth client ID → Web
  application, Authorized redirect URI as above. The wizard uses the Google
  preset; list your Workspace domains so only they can sign in.
- **Generic OIDC**: a confidential web client with the authorization code
  flow; the issuer is the HTTPS URL that serves
  `/.well-known/openid-configuration`.

## LDAP and Active Directory

The wizard collects the directory URL (`ldaps://`, or `ldap://` with
StartTLS), an optional read-only bind account, the users' base DN and a filter
that matches exactly one entry, e.g. `(sAMAccountName={username})` or
`(mail={email})`. IAMKit must reach the server; see [LDAP and Active
Directory](ldap.md) for private hosts and attributes. There is no draft for
LDAP and no test link: users test it by signing in.

## SCIM provisioning (Okta, Microsoft Entra ID)

The organization admin portal's **Directory** page shows the same guides next
to the token list. **Okta**: add an application with SCIM provisioning,
Provisioning → Integration → Configure API Integration, SCIM connector base
URL = the SCIM URL, unique identifier `userName`, HTTP Header authentication
with the token, then enable Create/Update/Deactivate Users. **Microsoft Entra
ID**: Enterprise application → Provisioning → Automatic, Tenant URL = the SCIM
URL, Secret Token = the token, Test Connection, then Provisioning Status On.
The token is shown once, when it is added. See [SCIM
provisioning](scim-provisioning.md).

## Draft connections

A SAML connection can be created before the IdP's metadata exists:

```http
POST /api/v1/environments/:environment/federation-connections
{"provider": "saml", "name": "Acme Okta", "organization_id": "…", "draft": true}
```

`201 {"id"}`. A draft takes no metadata, is **inactive**, never appears in
discovery and cannot sign anyone in. `GET …/federation-connections/:id` returns
`draft: true` and the `saml` values to give the IdP. While it is a draft you
can update it (`PATCH` with `options.metadata_url` or `options.metadata_xml`)
and test it. `POST …/:id/enable` needs the metadata: it fetches and checks it,
then makes the connection active and no longer a draft. Drafts exist only for
SAML (OIDC needs the IdP's client ID first; LDAP has nothing to hand to the
IdP). A draft that nobody enables is deleted after `SAMLDraftTTL` (7 days) by
the hourly `federation_draft_prune` job.

The CLI does the same:

```sh
iam federation create --provider saml --name "Acme Okta" --organization ORG_ID --draft
iam federation update CONNECTION_ID --metadata-url https://acme.okta.example/app/x/sso/saml/metadata
iam federation test CONNECTION_ID
iam federation enable CONNECTION_ID
```

## Test connection

`POST …/federation-connections/:id/test` (organization admins:
`POST …/organizations/:organization/admin/connections/:connection/test`,
`iam:org:sso:write`) returns `{"url", "expires_at"}` and records
`connection.test_requested` (actor = the administrator). The URL carries a
one-time `ik_fedtest_` ticket valid for 10 minutes (`FederationTestTTL`). Open
it in a browser: it shows a short page with a **Start test sign-in** button.
Opening the link spends nothing, so email and chat link scanners cannot use up
the ticket; the button posts it and redirects to the IdP, and when you come back
IAMKit shows what it received (subject, email, whether the email is verified,
name, groups) or why it failed. A test works for OIDC and SAML connections,
active or draft; LDAP has none.

A test creates no session, no user and no link, and nothing about the claims is
stored. It records only `connection.tested` with the connection and whether it
succeeded. A used, expired or foreign ticket answers 401 `invalid or expired
test connection link` when the button is pressed (the page itself only checks
the ticket's shape); a draft without metadata is 422.

## Troubleshooting

| Problem | Check |
|---------|-------|
| The IdP says the audience or ACS URL does not match | Copy the entity ID and ACS URL again; they are case-sensitive and must not have trailing spaces |
| The test page says the signature is invalid | The metadata IAMKit holds is out of date or belongs to another application: paste this application's metadata again |
| The test page shows no email | Send the email as the NameID (format `emailAddress`) or as an `email` attribute; for OIDC grant the `email` scope. Only a verified email links or creates accounts |
| The provider says the redirect URI does not match | Register the redirect URI exactly as shown |
| The issuer is rejected | It must be the HTTPS URL that serves `/.well-known/openid-configuration`, without an added path |
| Invalid client or secret | Check the client ID; create a new secret and copy its value |
| The user is not allowed to sign in | Assign the user or one of their groups to the application at the IdP |
| LDAP: the connection is refused / users are not found | URL and port, CA certificate, that IAMKit can reach the host; base DN and a filter that matches exactly one entry |
| SCIM: Test Connection fails | Paste the Tenant URL and token again; replace a revoked or expired token |

## Next steps

- [SAML 2.0 single sign-on](saml.md), [OIDC federation](federation.md),
  [LDAP and Active Directory](ldap.md), [SCIM provisioning](scim-provisioning.md)
