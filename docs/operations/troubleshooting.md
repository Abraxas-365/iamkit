# Troubleshooting

| Symptom | Diagnose | Repair and verify |
| --- | --- | --- |
| Container cannot read key | Path, mount, PEM format, runtime UID | Grant runtime-only read permission; restart and verify health |
| Startup migration failure | Empty-schema requirement, checksum, DB access | Preserve state; correct deployment/migration sequence, never erase history |
| Health 503 | PostgreSQL connectivity/credentials/capacity | Restore DB reachability; verify health and a functional request |
| Management 401 | Header family, expiry, active operator | Use `X-API-Key`; rotate/recover credential and verify `/me` |
| Console loses login | HTTPS, cookie scope, CSRF header, proxy | Same-origin HTTPS, preserve cookies; login/read/logout test |
| Password login denied | Boundary IDs, active user/app, membership, binding, grant | Inspect each prerequisite; verify known-good and cross-tenant denial |
| OTP never arrives | Delivery config in container, eligibility, webhook failures | Verify trusted test mailbox and delivery logs without codes |
| Old OTP rejected | Resend invalidated predecessor or expiry/attempt limit | Start a new challenge; retain only latest ID |
| Provider binding not approved | Exact env/issuer/client/secret reference | Correct deployment approval and recheck connection |
| Federation callback denied | HTTPS cookie, state/nonce, verified subject link | Repeat browser flow; do not bypass validation |
| OAuth exchange rejected | Redirect, verifier, client authentication, reused code | Start a new authorization; never replay consumed code |
| SCIM 401 | `X-API-Key`, expiry, connection credential | Rotate on same connection; validate discovery and a test user |
| SDK cannot decode list | Array vs page envelope/version mismatch | Verify endpoint contract and SDK version; do not discard errors |
| JWT valid but wrong tenant access | API only checks permission string | Compare organization and scope DB query; add a denied tenant test |
| Excess 429 | Process/edge limit and retry storms | Back off, serialize refresh/resend, assess legitimate capacity |

Do not paste credentials, token payloads containing personal data, or webhook
codes into bug reports. Record endpoint family, redacted request shape, status,
image digest and correlation information. Reproduce against disposable data.

See [configuration](../reference/configuration.md), [identity](../reference/api/identity.md)
and [observability](observability.md).
