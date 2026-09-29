# LDAP and Active Directory

An organization that keeps its users in an LDAP directory (Microsoft Active
Directory, OpenLDAP, FreeIPA, 389 Directory Server…) signs in to IAMKit
through an **LDAP connection**. Users type their directory password on the
sign-in page; IAMKit checks it against the directory and never stores it.
An LDAP connection is an [organization connection](federation.md#organization-sso):
discovery by verified domain, just-in-time provisioning, the default group,
enforcement, linking members by email, profile sync and
[MFA](mfa.md) work as for OIDC and SAML connections. Sessions carry the `fed`
authentication method.

## Prerequisites

- A verified domain of the organization, as for any organization SSO.
- `IAMKIT_ENCRYPTION_KEY` when IAMKit binds with a service account (its
  password is stored encrypted).
- A directory reachable over TLS: `ldaps://` (port 636 by default), or
  `ldap://` (port 389) with StartTLS. Plaintext LDAP is refused, so no
  password ever crosses the network in clear.
- IAMKit dials only public addresses. For a directory on a private network,
  list its host (or `host:port`) in `IAMKIT_LDAP_ALLOWED_HOSTS` on the IAMKit
  server, e.g. `IAMKIT_LDAP_ALLOWED_HOSTS=dc1.corp.acme.com,10.0.0.5:636`.

## 1. Create the connection

```bash
curl -X POST "$IAMKIT/management/v1/environments/$ENV/federation-connections" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' -d '{
    "provider": "ldap", "name": "Acme AD", "organization_id": "'$ORG'",
    "client_secret": "service-account-password",
    "options": {
      "url": "ldaps://dc1.acme.com",
      "bind_dn": "CN=iamkit,OU=Service Accounts,DC=acme,DC=com",
      "user_base_dn": "OU=People,DC=acme,DC=com",
      "user_filter": "(&(objectClass=user)(userPrincipalName={email}))"
    }
  }'
```

The CLI equivalent (the password is read from a file):

```bash
iam federation create --provider ldap --name "Acme AD" --organization $ORG \
  --ldap-url ldaps://dc1.acme.com --user-base-dn "OU=People,DC=acme,DC=com" \
  --bind-dn "CN=iamkit,OU=Service Accounts,DC=acme,DC=com" --client-secret-file ./bind-password
```

The console offers **LDAP / AD** under Sign-in providers → Organization SSO.

Options:

| Option | Meaning |
| --- | --- |
| `url` | `ldaps://host[:port]`, or `ldap://host[:port]` with `start_tls`. The host and port cannot change later. |
| `start_tls` | Required with `ldap://`: upgrade the connection with StartTLS before binding. |
| `ca_pem` | PEM of the CA certificates that sign the directory's certificate (a private CA). Default: the system roots. The certificate must name the URL's host. |
| `bind_dn` | Service account IAMKit binds as to search for users; its password is `client_secret` (required with `bind_dn`, refused without it). Omit both for a directory that allows anonymous search. |
| `user_base_dn` | Subtree searched for users. Cannot change later (linked subjects belong to it). |
| `user_filter` | Search filter; `{email}` is the typed email and `{username}` its part before `@` (both escaped). Default `(|(mail={email})(userPrincipalName={email}))`. Active Directory with short logon names: `(sAMAccountName={username})`. |
| `attributes.subject` | Attribute with a stable user ID. Default: `objectGUID`, then `entryUUID`, else the entry DN. Binary values are hex-encoded. |
| `attributes.email` | Attribute with the email. Default: `mail`, then `userPrincipalName`, else the typed email. |
| `attributes.name` | Attribute with the display name. Default: `displayName`, then `cn`. |

The connection's `issuer` is the normalized server (`ldaps://dc1.acme.com:636`)
and its `client_id` the lowercased base DN.

## Sign-in flow

1. `POST /identity/v1/discover` with the email answers
   `{"method":"sso","provider":"ldap","connection_id":…,"organization_id":…}`
   for the organization's verified domains. The [hosted login](hosted-login.md)
   does this itself and shows a password field for the directory.
2. The client posts the password:

```bash
curl -X POST "$IAMKIT/identity/v1/federation/ldap/login" -H 'Content-Type: application/json' -d '{
  "environment_id": "'$ENV'", "audience": "https://api.acme.com", "organization_id": "'$ORG'",
  "connection_id": "'$CONN'", "email": "ada@acme.com", "password": "…"
}'
```

The answer is the same as `POST /identity/v1/login`: a token pair, or an MFA
step when the organization requires a second factor. The SDK exposes it as
`authclient.Client.DirectoryLogin`.

IAMKit, for each attempt:

1. dials the directory (guarded as above) and sets up TLS, checking the
   certificate against `ca_pem` or the system roots;
2. binds as `bind_dn` (or stays anonymous);
3. searches `user_base_dn` (whole subtree) with the filter — it must match
   **exactly one** entry; none or several answer 401;
4. binds as that entry with the typed password (an empty password is refused
   before, so an unauthenticated bind can never pass);
5. maps the entry to the subject, email and name, then signs in like any
   federated login: the email's domain must be verified by the organization,
   the subject is linked or provisioned, and enforcement and MFA apply.

A wrong password, an unknown user and an ambiguous filter all answer the same
401. An unreachable directory, a refused certificate or a failed service
account bind answer 502. The route is limited to 10 attempts per minute per IP;
the directory's own lockout policy also applies.

## Updating

`PATCH` with `options` replaces the options whole (send `url` and
`user_base_dn` again). A new `client_secret` replaces the service account
password; clearing `bind_dn` drops it. Changing the host or the base DN is
refused (400): create another connection instead.

```bash
iam federation update $CONN --ldap-url ldaps://dc1.acme.com --user-base-dn "OU=People,DC=acme,DC=com" \
  --user-filter "(sAMAccountName={username})"
```

## Limits

- Simple bind over TLS only: no SASL/Kerberos, no plaintext LDAP.
- One server URL per connection (no failover list).
- No directory sync: users appear on first sign-in (JIT) or through
  [SCIM](scim-provisioning.md); disabling an account in the directory stops
  its next sign-in, but live sessions end only when revoked.
- Group membership is not read from the directory; use the connection's
  default group or SCIM groups.

## Verify

A first sign-in JIT-provisions a member (or links one by email with
`link_email`); the next ones find the linked subject. Check a wrong password
(401), an email outside the verified domains (401), and `SSO_REQUIRED` for
IAMKit passwords after enforcing.
