# API keys

An **API key** is a long-lived secret (`ik_key_…`) that lets a script, an
integration or a customer's system call **your API**. IAMKit stores only its
hash, shows the value once, and recomputes what the key may do on every use.
There is one credential and three kinds of owner.

## Three owners

| Owner | Acts as | Created by | Good for |
| --- | --- | --- | --- |
| `user` | A person, in one organization | The person, in your application (self-service); operators and organization administrators can list and revoke them | Ana's scripts and CLI: "my key, with at most what I can do" |
| `organization` | The organization itself, no person behind it | Organization administrators (portal or `…/admin/api-keys`) or an operator | A customer's ERP, warehouse or Zapier connection; survives whoever created it |
| `machine` | A [machine user](machine-users.md) | Operators only | Automation that needs IAMKit's own API or a token exchange |

### Compared with the other machine credentials

| | Service account | Machine user + key | User API key | Organization API key |
| --- | --- | --- | --- | --- |
| Identity | None, environment-level | A user (`kind` `machine`) | The person | None, the organization |
| Organization in the token | No | Yes | Yes | Yes |
| Permissions | Fixed list | Live roles and grants of the user | Key list ∩ allowlist ∩ the person's live access | Key list ∩ allowlist ∩ what the organization can reach |
| Managed by | Operators | Operators | The person | The organization's administrators |
| Calls IAMKit's API | With `iam:*` | With `iam:*` | Never | Never |
| Used by | Exchanged for a JWT | Directly, or exchanged for a JWT | Validated by your backend | Validated by your backend |

Choose a service account for your own backend, a machine user when automation
must hold roles inside a customer organization, and a user or organization key
when your **customers** need to call **your** API with something they create and
revoke themselves.

> **User and organization keys never carry `iam:*` permissions.** They cannot
> call IAMKit's own API (`/api/v1`, `…/admin`) and cannot be exchanged for a
> token. If a customer's key must lead to IAMKit data (for example listing
> users), your backend validates the key and then calls IAMKit as a proxy with
> **its own** service account or machine user. The IAM resource's allowlists are
> empty by construction.

## Operator setup

Nothing is enabled by default.

### 1. Enable the kinds in the policy

One policy per environment (`GET`/`PUT …/api-key-policy`, console **Settings →
API keys**, `iam api-keys policy get|set`):

| Field | Default | Meaning |
| --- | --- | --- |
| `user_keys` | `false` | Users may hold keys. Off: creation is 403 `API_KEYS_DISABLED` and existing keys stop validating |
| `organization_keys` | `false` | Same for organization keys |
| `max_ttl_days` | none | Longest lifetime a new key may ask for (1–365). When set, `never` and longer lifetimes are 400. Unset allows `never` |
| `max_per_user` | 10 | Keys per user per organization (1–100); beyond it 422 `API_KEY_LIMIT_REACHED` |
| `max_per_organization` | 50 | Organization keys per organization (1–500) |

Machine keys are an operator credential and ignore the two toggles. Changes are
audited as `api_key_policy.updated`.

```sh
curl -X PUT "$IAMKIT_URL/management/v1/environments/$ENV/api-key-policy" \
  -H "X-API-Key: $IAMKIT_MANAGEMENT_KEY" \
  -d '{"user_keys":true,"organization_keys":true,"max_ttl_days":365,"max_per_user":10,"max_per_organization":50}'
```

### 2. Choose what each resource lets keys do

Each resource carries two allowlists, subsets of its `permissions`: the ones
**user** keys may hold and the ones **organization** keys may hold. Both are empty
at first, so no key can be made for the resource.

```sh
curl -X PUT "$IAMKIT_URL/management/v1/environments/$ENV/resources/$RESOURCE/api-key-permissions" \
  -H "X-API-Key: $IAMKIT_MANAGEMENT_KEY" \
  -d '{"user":["invoices:read"],"organization":["invoices:read","invoices:write"]}'
```

CLI: `iam resources api-key-permissions get|set RESOURCE_ID --user invoices:read --organization invoices:write`.
Console: the resource's **API keys** section. The resource JSON shows
`api_key_permissions: {user, organization}`. Removing a permission from the
resource drops it from both lists. The IAM resource refuses any entry (422).

## Who can create what

| Surface | Kinds | Rules |
| --- | --- | --- |
| Operator: `POST …/api-keys` (management, or `/api/v1` with `iam:api-keys:write`) | `organization` | No granter check; the policy and allowlist still apply |
| Operator: `POST …/users/:id/api-keys` (`iam:users:write`) | `machine` | Machine users only; needs `application_id`; `permissions` optional |
| Organization administrator: `POST …/organizations/:organization/admin/api-keys` (`iam:org:api-keys:write`) | `organization` | A person must call; [setup links](../organizations/organization-administration.md#setup-links) get 403. An administrator may only grant permissions **they hold themselves**, the rule roles follow |
| The person: `POST /identity/v1/me/api-keys` | `user` | Application token of the user, signed in recently (403 `REAUTHENTICATION_REQUIRED` otherwise), not impersonated; resource linked to the token's application; organization = the token's |

Organization administrators cannot create machine users: that stays with
operators, and they use organization keys instead.

Create body, for all but machine keys:

```json
{"organization_id":"ORG_UUID","resource_id":"RESOURCE_UUID","name":"warehouse sync",
 "permissions":["invoices:read"],"expires_in":"2160h"}
```

`permissions` must be non-empty and inside the resource's allowlist for that
kind **and** inside what the owner can reach right now; otherwise 422.
`expires_in` is `1h`–`8760h` or `never`; **omitted means `never`**, subject to
`max_ttl_days`. The answer is `201` with the key and `value` (`ik_key_…`),
shown only this once. Every key records its creator (`created_by: {kind, id}`:
operator, user, setup link or service account).

Reading: the operator lists the environment's keys with `GET …/api-keys` (filters
`owner_type`, `organization_id`, `user_id`, `resource_id`, `state`, and `search`
on the name); an administrator lists the organization's keys and its members'
user keys at `…/admin/api-keys` (never machine keys) and may revoke either; the
person lists their own with `GET /identity/v1/me/api-keys`. `GET …/options`
(admin and self-service) returns what the caller may offer in a create form:
resources and, for each, the permissions the caller may give. Another scope's
key is always 404.

## What a key may do: recomputed on every use

The effective permissions of a key are never stored:

| Kind | Effective permissions |
| --- | --- |
| `user` | key list ∩ resource's user allowlist ∩ the person's live permissions in the organization |
| `organization` | key list ∩ resource's organization allowlist ∩ what the organization can reach on the resource (owner and [grant](../organizations/organization-administration.md#resource-grants-vendor-organizations) rules; everything when the resource needs no grant) |
| `machine` | key list (omitted = everything) ∩ the machine user's live permissions |

So removing a role takes effect on the next request, narrowing the allowlist
narrows existing keys, and a key whose effective set is empty is inactive.
A key is also inactive when it is revoked or expired, the policy no longer
allows its kind, the organization (or application, for machine keys) is
deactivated, or the owner is not an active user with an active membership.

Lifecycle:

- **User keys** end when the membership ends: removing the user from the
  organization revokes their keys there at once (`reason: membership_ended`).
  A suspended user's keys stop validating; reactivation restores unexpired ones.
- **Organization keys** belong to the organization and **outlive their
  creator**; any administrator with the permission can list and revoke them.
- Removing a machine user or an organization deletes its keys. Revoking a key
  ends the sessions exchanged from it.

## Validate keys in your backend

Your API receives `Authorization: Bearer ik_key_…` and asks IAMKit:

```sh
curl -X POST "$IAMKIT_URL/identity/v1/introspect" \
  -H "Authorization: Bearer $KEY" \
  -d '{"environment_id":"ENV_UUID","audience":"https://api.example.com"}'
```

An unknown, revoked, expired or disabled key, or an owner that is no longer
valid, answers `{"active":false}`. Otherwise:

```json
{
  "active": true,
  "claims": {
    "purpose": "api_key",
    "sub": "USER_UUID",
    "environment_id": "ENV_UUID",
    "organization_id": "ORG_UUID",
    "resource_id": "RESOURCE_UUID",
    "permissions": ["invoices:read"],
    "aud": ["https://api.example.com"],
    "exp": 0,
    "api_key": {
      "id": "KEY_UUID",
      "name": "warehouse sync",
      "owner": {"type": "user", "id": "USER_UUID", "organization_id": "ORG_UUID"},
      "resource_id": "RESOURCE_UUID",
      "permissions": ["invoices:read"],
      "expires_at": 0
    }
  }
}
```

`permissions` are the **effective** ones. `sub` is the user for user keys and
empty for organization keys; `exp` 0 means the key never expires. The
`audience` you send must equal the key's resource audience, otherwise the key
is inactive: a key made for another resource of yours does not pass. Take the
environment and audience from your configuration, never from the request.

Go, with [`authclient`](../../reference/sdk/authentication.md#validating-api-keys)
(the client carries the environment and audience):

```go
client := authclient.New(iamkitURL, authclient.WithAudience(environmentID, "https://api.example.com"))
key, err := client.ValidateAPIKey(ctx, rawKey)
if err != nil { /* 401 */ }
if !key.HasPermission("invoices:read") { /* 403 */ } // effective permissions
```

Node, with [`@iamkit/node`](../../reference/sdk/node.md#api-keys):

```ts
const keys = createAPIKeyValidator({ baseUrl, environmentId, audience })
const key = await keys.validate(rawKey) // rejects with 401 when inactive
```

Middleware refuses API keys unless asked: the Go `fiberauth`/`httpauth` option
`AllowAPIKeys` and the Node `allowApiKeys` option accept `ik_key_` bearers
(through introspection) next to JWTs and hand the key's claims to handlers.
Always scope data to `organization_id` and, for user keys, to `sub`. User and
organization keys are **validated only**: they are never traded for a JWT.

## Machine keys

A [machine user's](machine-users.md) keys are the only ones IAMKit's own
endpoints accept: as a bearer on `/api/v1` (when the key's resource is the IAM
resource) and at `POST /identity/v1/token-exchange` for a 15-minute access JWT.
They validate through introspection like the others. A user or organization key
sent to `/api/v1` is 401 ("API keys of users and organizations cannot call the
IAMKit API"). See [machine users](machine-users.md#api-keys).

## Events and audit

| Event | When | `data` |
| --- | --- | --- |
| `api_key.created` | A key was created | `owner_type`, `user_id` (user and machine keys), `organization_id`, `resource_id`, `name`, `permissions` |
| `api_key.revoked` | A key was revoked | the same; `reason: membership_ended` when the membership ended |
| `api_key_policy.updated` | The environment policy changed | the policy |

The actor is the operator, user or setup link that created or revoked the key
(the creator is also on the key as `created_by`). A machine user acting through
its key or JWK appears with the actor kind `machine`, and the automatic
revocation on membership end has actor `system`. Key values are never in an
event. There is no `api_key.expired`: expiry is checked at use. Events reach
[webhooks](../../reference/event-webhooks.md) and
[log streams](../platform/log-streams.md), and organization administrators read
their organization's at `…/admin/events`. See the
[event catalog](../../reference/events.md).

## Security notes

- The value is returned once at creation; IAMKit keeps a hash and the last four
  characters. Lists show `obfuscated_value` (`ik_key_…abcd`) to tell keys apart.
- Rotate by creating the new key, deploying it, then revoking the old one;
  `last_used_at` (updated at most once a minute) shows whether anything still
  uses it. Revocation is immediate and idempotent (204).
- Prefer a lifetime. `never` exists for integrations nobody can re-key, and the
  policy's `max_ttl_days` can forbid it.
- Keep keys in server-side secret storage, never in browser code, and log by
  `api_key.id`, not by value.
- Give keys the fewest permissions that work: the allowlist is a ceiling, not a
  default.

## Related

- [Machine users](machine-users.md) and [service accounts](service-accounts.md)
- [Organization administration](../organizations/organization-administration.md#api-keys)
- [Credentials and boundaries](../../concepts/credentials-and-boundaries.md)
- [Token claims](../../reference/token-claims.md#api-key-validation)
- [CLI](../../reference/cli.md#api-keys)
