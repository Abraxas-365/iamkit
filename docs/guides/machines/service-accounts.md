# Service accounts

A service account authenticates a trusted worker/backend, not a browser user.
Create an application-resource binding first. Using management `X-API-Key`, POST
`/management/v1/environments/ENV_UUID/service-accounts`:

```json
{"name":"Invoice worker","application_id":"APP_UUID","resource_id":"RESOURCE_UUID","permissions":["invoices:read"],"expires_in":"24h"}
```

201 returns `{id,secret,expires_at}`. Store `secret` once in a secret manager.
Exchange it without placing it in URLs:

```sh
curl --fail --silent --show-error -X POST "$IAMKIT_URL/identity/v1/machine-token" \
  -H "Authorization: Bearer $SERVICE_SECRET"
```

Or use the standard OAuth 2.0 client credentials grant — any OAuth library
works, with the account ID as `client_id` and the secret as `client_secret`:

```sh
curl --fail --silent --show-error -X POST "$IAMKIT_URL/oauth/token" \
  -u "$SERVICE_ACCOUNT_ID:$SERVICE_SECRET" -d grant_type=client_credentials
```

Both answer the same token. The response contains an access JWT; there is no user refresh token. Use that JWT
on the intended API and enforce its audience/resource/permissions. Machine tokens
have no user organization/session. Renew access by exchanging the still-valid
service credential; rotate the credential before its expiry.

## Authenticate with a private key (private_key_jwt)

Instead of a shared secret, an account can prove itself with a JWT signed by a
key only it holds ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)). Register
its public keys — a JWKS inline (up to 10 RSA or EC keys) or an HTTPS
`jwks_uri` IAMKit fetches and caches for up to an hour — with PUT
`/service-accounts/:id/authentication` (also accepted on create):

```json
{"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":"ES256","jwks_uri":"https://worker.example.com/jwks.json"}
```

Console: **Service accounts → Actions → Authentication**. CLI:
`iam service-accounts set-auth ID --auth-method private_key_jwt --jwks-uri URL`
(or `--jwks-file keys.json`). Then request tokens with an assertion whose
`iss` and `sub` are the account ID, `aud` is `$IAMKIT_URL/oauth/token` (the
issuer alone is also accepted), with a unique `jti`, `exp` at most an hour
away, and the `kid` of a registered key in its header:

```sh
curl -X POST "$IAMKIT_URL/oauth/token" -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$SIGNED_JWT"
```

Each assertion is accepted once. Once an account uses `private_key_jwt`, its
`ik_svc_` secret no longer works — neither at `/oauth/token` nor at
`/identity/v1/machine-token`. The Go SDK signs assertions for you:
`authclient.NewOAuth(url, accountID, "", authclient.WithPrivateKeyJWT(key, kid, "ES256")).ClientCredentials(ctx)`.
Switching back to a secret method drops the keys; changes are audited
`service_account.authentication`. `client_secret_post` (secret in the form
body) is accepted too.

## Backend user provisioning

The built-in IAM resource is for selected administration through
[`/api/v1`](../../reference/api/scoped-iam.md), using a dedicated app binding and
explicit IAM permissions. The token only works in its own environment and only on
the route families its permissions name; grant the smallest set you need. The
onboarding example instead uses a deliberately workspace-wide operator key on a
trusted backend.

This differs from a machine token for Invoices API. A resource-bound business
token is not a management key and cannot call `/management/v1`. See
[scoped IAM routes](../../reference/api/scoped-iam.md).

## Rotate and revoke

Issue a replacement, deploy it securely, prove successful exchange and intended
API access, then DELETE `/service-accounts/:id` for the predecessor. Read lists
with GET `/service-accounts`. Test denied exchange after revocation and current
state through introspection. Offline JWT consumers retain the expiry trade-off.
Do not give a signup frontend the ability to choose service-account permissions.
