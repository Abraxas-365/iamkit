# Machine users, personal access tokens and keys

A machine user is a user without email, password or second factor, made for
scripts, CI jobs and integrations that act *inside a customer organization*.
It joins organizations, belongs to groups and receives roles and grants exactly
like a person, and it authenticates only with personal access tokens
(`ik_pat_…`) or with [keys](#keys-jwt-bearer-login) (a signed JWT traded at
`/oauth/token`).

## Service account or machine user?

| | Service account | Machine user |
| --- | --- | --- |
| Is a user | No | Yes (`kind` `machine`) |
| Organization | None — tokens carry no organization | Member of organizations; each token acts in one |
| Permissions | Fixed list chosen when created | Live: the roles, groups and grants it holds in that organization |
| Managed by | Operators (and `/api/v1` with `iam:service_accounts:*`) | Operators, `/api/v1` with `iam:users:*`, like any user |
| Credential | `ik_svc_` secret or `private_key_jwt` | Personal access tokens and keys, several per user |
| Token | Exchanged for an access JWT (`/identity/v1/machine-token`, `client_credentials`) | A token used directly as a bearer or exchanged at `/identity/v1/token-exchange`; or a key-signed assertion traded at `/oauth/token` (`jwt-bearer`) |
| Secret held by IAMKit | Hash of the secret, or your public keys | Hash of each token; only the public half of each key |
| Good for | Your own backend calling your own API | A customer's automation acting in their organization |

## Create one

Console: **Users → Create machine user**. API (management key or `/api/v1`
with `iam:users:write`):

```sh
curl -X POST "$IAMKIT_URL/management/v1/environments/$ENV/users" \
  -H "X-API-Key: $IAMKIT_MANAGEMENT_KEY" \
  -d '{"kind":"machine","name":"billing-sync","home_organization_id":"ORG_UUID"}'
```

`kind` `machine` refuses `email`, `password`, `username` and `otp_enabled`;
the user can never receive a password, second factor, sign-in code, linked
identity or SCIM record (enforced in the database too). SCIM never lists or
removes machine users. Filter lists with `?kind=machine` (`human` for people).
Add memberships, roles and grants as for any user.

CLI: `iam machine-users create --name billing-sync --home-organization ORG_UUID`,
`iam machine-users list`.

## Personal access tokens

A token acts as its machine user in **one organization** (which the user must
belong to) for **one resource of one application**:

```sh
curl -X POST "$IAMKIT_URL/management/v1/environments/$ENV/users/$USER/access-tokens" \
  -H "X-API-Key: $IAMKIT_MANAGEMENT_KEY" \
  -d '{"name":"nightly export","organization_id":"ORG_UUID","application_id":"APP_UUID","resource_id":"RESOURCE_UUID","expires_in":"720h"}'
```

201 returns the token metadata plus `token` (`ik_pat_…`), shown only this once.
`expires_in` is `1h`–`8760h` or `never`; the default is `24h`. GET lists tokens
(never secrets, with `last_used_at`); DELETE `…/access-tokens/:token` revokes one.
Creating and revoking are audited `user.access_token_created` and
`user.access_token_revoked`. CLI: `iam machine-users tokens create|list|revoke`.

Creating a token does not need the machine user to hold a role on the resource,
but every use is refused (401) until it does. The console's **Create token**
dialog warns when the user holds no role (direct or through a group) on the
chosen resource in the chosen organization.

### Use it directly

Send the token as `Authorization: Bearer ik_pat_…`:

- on [`/api/v1`](../reference/api/scoped-iam.md) when the token's resource is
  the IAM resource, with the IAM permissions the machine user holds;
- to your own API, which checks it with
  [`POST /identity/v1/introspect`](../reference/api/identity.md) (the OAuth
  `/oauth/introspect` endpoint does not accept personal access tokens).

Permissions are resolved at every request from what the machine user holds in
the organization — change a role and the next request sees it. No session is
created. SDK local JWT validation (`authclient.Validator`, `fiberauth`,
`httpauth`) does **not** accept personal access tokens; exchange them instead.

### Exchange it for an access token

```sh
curl -X POST "$IAMKIT_URL/identity/v1/token-exchange" -H "Authorization: Bearer $PAT"
```

The answer is an ordinary 15-minute access JWT (no refresh token) that any
JWT-validating API accepts. It is backed by a session shared by every exchange
of the same token, which ends when the token expires or is revoked. Go SDK:
`authclient.New(url).ExchangeAccessToken(ctx, pat)`.

## What ends a token

Revoking it; its expiry; deactivating the machine user; the user leaving the
organization, or its membership, the organization or the application being
deactivated; losing the permissions (a token with no grant in the
organization is refused). Each is checked at every use, and the sessions
exchanged from the token end when it is revoked. Reactivating the user or the
membership restores unexpired, unrevoked tokens. Deleting the user or the
organization deletes its tokens; an application-resource link used by a
token cannot be removed (409) until the token is gone.

## Keys (JWT-bearer login)

A key lets the machine user sign in without any secret stored by IAMKit: the
machine user signs a short JWT with its private key and trades it at
`/oauth/token` with the [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)
grant `urn:ietf:params:oauth:grant-type:jwt-bearer`. Unlike a personal access
token, the organization, application and resource are chosen at each sign-in.

### Add a key

```sh
# IAMKit generates an RSA pair and returns the private key once
curl -X POST "$IAMKIT_URL/management/v1/environments/$ENV/users/$USER/keys" \
  -H "X-API-Key: $IAMKIT_MANAGEMENT_KEY" -d '{"expires_in":"8760h"}'

# or upload the public half of a key you hold (RSA ≥ 2048 bits or EC P-256/384/521)
curl -X POST "$IAMKIT_URL/management/v1/environments/$ENV/users/$USER/keys" \
  -H "X-API-Key: $IAMKIT_MANAGEMENT_KEY" \
  -d '{"public_key":{"kty":"EC","crv":"P-256","x":"…","y":"…"}}'
```

201 returns `{id, user_id, public_key, expires_at, last_used_at, created_at}`
and, for a generated pair only, `private_key` (PKCS #8 PEM) — IAMKit does not
keep it. Uploaded keys must be public (private members such as `d` are
refused) and meant for signing. `expires_in` is `1h`–`8760h` or `never`
(default `8760h`). A machine user holds at most 10 keys; people cannot have
any (422). GET lists the keys (public halves), DELETE `…/keys/:key` removes one
and ends the sessions opened with it. Audited `user.key_added` and
`user.key_removed`. Console: the machine user's **Keys** section. CLI:
`iam machine-users keys add USER_ID --private-key-out bot.pem`
(or `--public-key-file key.jwk`), `keys list`, `keys remove`.

### Sign in with it

Sign a JWT with the private key:

| Where | Value |
| --- | --- |
| header `kid` | the key ID |
| header `alg` | `RS256`–`RS512`/`PS256`–`PS512` for RSA; `ES256`, `ES384`, `ES512` for P-256, P-384, P-521 |
| `iss`, `sub` | the machine user ID |
| `aud` | `$IAMKIT_URL/oauth/token` (or the issuer, `$IAMKIT_URL`) |
| `exp` | at most one hour ahead |
| `jti` | unique; each assertion is accepted once |

then post it (no client authentication):

```sh
curl -X POST "$IAMKIT_URL/oauth/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion="$ASSERTION" \
  -d organization_id=ORG_UUID -d application_id=APP_UUID -d resource_id=RESOURCE_UUID
```

`environment_id` is optional (the key's). The machine user must have access
to the resource in the organization, as for any sign-in. The answer is
`{access_token, token_type: Bearer, expires_in}` — an ordinary 15-minute
application JWT with `amr` `["swk"]` and a `sid`, no refresh token: sign a new
assertion when it expires. Consecutive sign-ins with the same key and boundary
reuse one session, which ends when the key is removed or expires, the user is
deactivated, or access is lost. Any refusal is `400 invalid_grant`; a missing
`assertion` or malformed boundary is `invalid_request`.

Go SDK:

```go
key, _ := authclient.ParsePrivateKey(pemBytes)
login, _ := authclient.NewKeyLogin(iamkitURL, machineUserID, keyID, key)
tokens, err := login.Token(ctx, authclient.KeyBoundary{OrganizationID: org, ApplicationID: app, ResourceID: res})
```
