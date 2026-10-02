# Actions

Actions let your own endpoint take part in IAMKit flows **while they run**:
refuse a sign-in, add claims to OAuth tokens, rename an account coming from
an identity provider, or veto a management request. They are synchronous
hooks — unlike [event webhooks](../reference/event-webhooks.md), which tell
you afterwards what happened and cannot change it.

An action is two things, per environment:

- **Targets** — HTTPS endpoints (at most 20) with a kind, a timeout and an
  error policy. Every request is signed with the target's secret.
- **Executions** — which targets a **condition** calls, in order (at most 5
  per condition).

Nothing is called until a condition has targets. The `actions`
[feature flag](feature-flags.md) (environment-scoped, on by default) turns
every call off at once without deleting the configuration.

## Conditions

| Condition | Runs | Targets may |
| --- | --- | --- |
| `function:pre_sign_in` | Before a user session is created — every sign-in method (password, codes, passkeys, federation, hosted and headless) | deny |
| `function:pre_registration` | Before a self-service sign-up, or a federated first sign-in that would create a user, creates the account (linking an existing account by email does not count) | deny |
| `function:post_federation` | After an identity provider verified the user, before the account is linked or updated | deny, patch `name` |
| `function:pre_access_token` | Before an OAuth access token is issued; again on every refresh | deny, add claims |
| `function:pre_id_token` | Before an OIDC ID token is issued | deny, add claims |
| `function:pre_userinfo` | Before `/oauth/userinfo` answers | add claims |
| `request:user.create` | Before the management API creates a user | deny, patch `name`, `username`, `avatar_url` |
| `request:user.update` | Before the management API updates a user | deny, patch `name`, `avatar_url` |
| `request:membership.create` | Before the management API adds a user to an organization | deny |

`GET …/action-conditions` lists them with what they accept. Identity-API
tokens (`/identity/v1`) are never changed by actions, so the claims APIs
authorize on stay under IAMKit's control.

## Target kinds and failures

| Kind | Waits | Uses the answer |
| --- | --- | --- |
| `call` | Yes, up to the timeout | Yes: deny, claims, patch |
| `webhook` | Yes, up to the timeout | No; only a `2xx` counts |
| `async` | No (sent in the background) | No; never changes or stops the flow |

The timeout is 100–10,000 ms (default 5,000). A call **fails** when the
endpoint times out, answers outside `2xx`, follows a redirect, sends more
than 64 KiB, or answers something the condition does not accept (a claim it
cannot set, a field it cannot patch, a message over 200 characters, a body
that is not a JSON object). Then:

- `interrupt_on_error: true` — the flow stops with `ACTION_FAILED` (502);
  hosted pages show a generic error.
- `interrupt_on_error: false` (default) — the flow goes on **without that
  target's changes**.

Either way the call is logged and an `action.failed` event is written
(`data.condition`, `outcome`, `error`, `interrupted`), so an
[event webhook](../reference/event-webhooks.md) on `action.failed` can page
you. After 5 failures in a row a target is skipped for 30 seconds (outcome
`skipped`, treated as a failure) so a broken endpoint does not slow every
sign-in.

Targets run in order. A denial stops at once; claims and patches merge,
a later target's value winning over an earlier one's for the same name.

## The request

```http
POST /iam/pre-sign-in HTTP/1.1
Content-Type: application/json
User-Agent: IAMKit-Actions/1
webhook-id: act_5f0c2d…
webhook-timestamp: 1759300000
webhook-signature: v1,K5p4…

{"condition":"function:pre_sign_in","environment_id":"7ae0…",
 "organization_id":"1b2c…","application_id":"9d8e…",
 "user":{"id":"33b4…","email":"ada@example.com","name":"Ada"},
 "amr":["pwd"]}
```

| Field | Sent for |
| --- | --- |
| `condition`, `environment_id` | Always |
| `organization_id`, `application_id` | When the flow has them |
| `client_id`, `scopes` | Token and UserInfo conditions |
| `user` (`id`, `email`, `name`, `username`) | When a user is known; no `id` before registration |
| `amr` | Sign-in and token conditions: how the user signed in |
| `identity` (`connection_id`, `provider`, `subject`, `email`, `name`) | `post_federation` and federated `pre_registration` |
| `request` | `request:*`: the request body (never a password) |

No secrets, password hashes or tokens are ever sent. Requests are signed
per [Standard Webhooks](https://www.standardwebhooks.com) like
[event webhooks](../reference/event-webhooks.md#verifying-the-signature): verify
`webhook-signature` with the target's `whsec_` secret before trusting the
body. Rotating the secret keeps the previous one signing (both signatures
sent) for 24 hours. Endpoints must use `https` (`http` only for `localhost`)
and resolve to public addresses.

## The answer

Answer `204` (or `200` with an empty body or `{}`) to change nothing. A
`call` target may answer `200` with:

```json
{"deny": true, "message": "Your account is under review."}
```

```json
{"claims": {"tier": "gold", "https://example.com/roles": ["editor"]}}
```

```json
{"patch": {"name": "Ada Lovelace"}}
```

- **`deny`** refuses the flow: management requests answer 403
  `ACTION_DENIED` with `message`; sign-in shows `message` on the hosted page
  (or returns it as `ACTION_DENIED` from `/identity/v1`); the token endpoint
  answers `access_denied` with it as the description. Without a message a
  generic one is used.
- **`claims`** are added to the access token, ID token or UserInfo answer:
  names of 1–128 characters (letters, digits, `_ . : / -`, starting with a
  letter — namespaced URLs welcome), any JSON values, 4 KiB in total. Names
  IAMKit sets itself are refused and fail the call: `iss`, `sub`, `aud`,
  `exp`, `iat`, `nbf`, `jti`, `auth_time`, `nonce`, `acr`, `amr`, `azp`,
  `at_hash`, `c_hash`, `sid`, `act`, `scope`, `scp`, `client_id`,
  `environment_id`, `organization_id`, `application_id`, `resource_id`,
  `permissions`, `purpose`, `oauth_client_id`, `token_use`, `token_type`,
  `cnf`, `may_act` — as is any claim the token already carries (profile
  claims, `email`, …). Claims from `pre_access_token` are recomputed on every
  refresh.
- **`patch`** replaces the listed string fields, then the request is
  validated again as if the caller had sent the new values.

## Set it up

Console: **Actions** in the environment menu — add a target (the secret is
shown once), then **Edit** a condition to choose its targets and their
order. A target's page tests it, rotates its secret and lists its calls.

CLI:

```sh
iam actions targets create --name Risk --url https://risk.example/iam --interrupt-on-error
iam actions set function:pre_sign_in --targets <target id>
iam actions targets test <target id> --condition function:pre_sign_in \
  --input '{"user":{"email":"ada@example.com"}}'
iam actions calls --outcome failed
```

A test sends the condition, the environment and the `--input` you give,
shows the answer and never applies it. Recent calls (tests included) are
kept for 7 days.

## Receivers

Go, with `sdk/action`:

```go
func preSignIn(w http.ResponseWriter, r *http.Request) {
	in, err := action.Verify(secret, r)
	if err != nil {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	switch in.Condition {
	case action.PreSignIn:
		if blocked(in.User.Email) {
			action.Write(w, action.Deny("Your account is under review."))
			return
		}
	case action.PreAccessToken:
		action.Write(w, action.Response{Claims: map[string]any{"tier": tier(in.User.ID)}})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

Node, with the `standardwebhooks` package:

```js
import express from "express";
import { Webhook } from "standardwebhooks";

const hook = new Webhook(process.env.IAMKIT_ACTION_SECRET.replace("whsec_", ""));
const app = express();

app.post("/iam/actions", express.raw({ type: "application/json" }), (req, res) => {
  let input;
  try {
    input = hook.verify(req.body, req.headers);
  } catch {
    return res.status(401).end();
  }
  if (input.condition === "function:pre_access_token") {
    return res.json({ claims: { tier: lookupTier(input.user.id) } });
  }
  res.status(204).end();
});
```

Keep receivers fast: sign-in waits for them. Answer from a cache or local
data where you can, and choose `interrupt_on_error` only for checks that
must hold (a denylist), not for enrichment (extra claims).

## API

Management API under `/management/v1/environments/:environment`:

| Route | Purpose |
| --- | --- |
| `GET /action-conditions` | The conditions above |
| `GET`, `POST /action-targets` | List; create (`name`, `url`, `kind`, `timeout_ms`, `interrupt_on_error`) → `{id, secret}` (201, secret shown once) |
| `GET`, `PATCH`, `DELETE /action-targets/:id` | Read, change (fields given), delete (also removed from every execution) |
| `POST /action-targets/:id/rotate-secret` | New secret → `{id, secret}` |
| `POST /action-targets/:id/test` | `{condition, input}` → `{outcome, status, duration_ms, error, response}` |
| `GET /action-executions` | Conditions with targets |
| `PUT`, `DELETE /action-executions/:condition` | `{targets: [id…]}` in call order; remove (URL-encode the `:`) |
| `GET /action-calls` | Recent calls, newest first; `target_id`, `condition`, `outcome`, `limit` (50) |

Writes need owner/admin and are audited (`action_target.*`,
`action_execution.*`). Secrets need `IAMKIT_ENCRYPTION_KEY` (422
`ENCRYPTION_KEY_REQUIRED` otherwise). Actions are not on the scoped
`/api/v1`. The Go management client has the same operations
(`ActionTargets`, `CreateActionTarget`, `SetActionExecution`,
`TestActionTarget`, `ActionCalls`, …).
