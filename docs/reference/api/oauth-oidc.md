# OAuth/OIDC protocol reference

Discovery: `GET /.well-known/openid-configuration`. Keys:
`GET /.well-known/jwks.json`. The configured issuer must match the client's trusted
issuer, including the public HTTPS origin.

| Endpoint | Contract |
| --- | --- |
| `GET /oauth/authorize` | Authorization code request; returns JSON ticket/context and Secure binding cookie |
| `POST /oauth/authorize/complete` | JSON `authorization_ticket`, `approve`; requires browser cookie and matching user Bearer token |
| `POST /oauth/token` | Form-encoded code or refresh grant; OAuth token response |
| `POST /oauth/revoke` | Form-encoded `token`, client authentication; protocol revocation response |

Authorize requires `client_id`, `response_type=code`, registered `redirect_uri`,
`state`, `nonce`, `scope` including `openid`, `code_challenge_method=S256` and
`code_challenge`. Supported scopes: `openid profile email offline_access`.
No implicit or password grant is advertised. `prompt`/`max_age` are unsupported.

Code exchange fields: `grant_type=authorization_code`, `code`, `redirect_uri`,
`code_verifier`, plus client identity/authentication. Refresh exchange uses
`grant_type=refresh_token` and `refresh_token`. Public clients have no secret;
confidential clients use `client_secret_basic` as advertised by discovery. Use a
standards-aware library for form/Basic credential encoding.

Authorization codes last five minutes; access and ID tokens fifteen minutes;
refresh lifespan is constrained by session validity. Replay protection is not a
license to retry old rotating credentials indiscriminately. Token endpoint errors
use OAuth fields (`error`, etc.), not the management JSON envelope.

Client administration: POST/GET `/management/v1/environments/:environment/oauth-clients`,
DELETE `.../oauth-clients/:id`. Create returns 201
`{id,client_id,client_secret}`; list uses a page; disable returns 204.

Source: `internal/iam/oauth/adapters/oauthhttp/handler.go`,
`oauthsvc/service.go`, `internal/config/constants.go`. Follow the
[integration guide](../../guides/oauth-oidc.md) for the interaction sequence.
