# Executable examples

Run from the repository root unless stated otherwise. Use disposable data and a
trusted shell; secrets appear in process environments, so restrict local access.
Do not enable shell tracing on credential-bearing scripts.

| Example | Prerequisites and execution |
| --- | --- |
| [Onboarding](onboarding/run.sh) | Healthy IAMKit, Bash/curl/jq, authorized management key. Set `IAMKIT_URL`, `MGMT`, `DEMO_PASSWORD`, `OUTPUT`; run `bash docs/examples/onboarding/run.sh`. See [first application](../start/first-application.md). |
| [Protected Go API](go-api/main.go) | Go and local SDK checkout; configure the boundary/issuer variables listed in [protect an API](../guides/protect-an-api.md). Run `go run .` from `docs/examples/go-api`. |
| [Browser helpers](browser/auth.js) | Import into your same-origin app with `/identity/` proxied to IAMKit; supply UI, trusted boundary selection and session storage policy. Not a standalone UI. |
| [Docker smoke](deployment/smoke.sh) | Docker, Bash, curl, jq, OpenSSL; build `iamkit-docs-validation:local`, then run `bash docs/examples/deployment/smoke.sh`. Creates/removes only its own temporary containers, network, key volume and files. |

Onboarding is a multi-request sequence, not a transaction; on failure inspect the
newly created project before retrying. The private output contains credentials:
keep it outside version control and remove it after your test. Do not run cleanup
against a shared installation. The smoke script uses a disposable database and
cleans its own resources automatically.

See [testing](../maintainers/testing.md) for checks and
[validation status](../maintainers/validation.md) for what was actually exercised.
