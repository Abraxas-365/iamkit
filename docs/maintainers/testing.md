# Testing

Run from the repository root unless a command names another directory:

```sh
make test
make vet
make test-e2e
make test-browser
python3 scripts/check_docs.py
bash -n docs/examples/onboarding/run.sh docs/examples/deployment/smoke.sh
(cd docs/examples/go-api && go test ./... && go vet ./...)
docker build -t iamkit-docs-validation:local .
bash docs/examples/deployment/smoke.sh
```

The smoke test creates only disposable named Docker resources. It checks non-root
key access, explicit bootstrap, provisioning, password login, introspection,
cross-tenant login rejection and restart. It is not a TLS/provider/restore test.
The Go example's compilation does not prove a live API integration by itself.

`check_docs.py` checks local Markdown links/heading anchors, SVG XML, trailing
whitespace and accidental PEM private keys in documentation. This narrow secret
check is not a substitute for a repository/history secret scanner. External URLs
are not fetched, so provider documentation and registry availability need separate
verification. See [validation record](validation.md).

`make test-e2e` starts one disposable PostgreSQL container (testcontainers),
applies every migration to a template database and gives each test its own
copy. The HTTP journeys run against the real app on that database;
`tests/e2e/schema_test.go` additionally checks each migration's constraints
directly with SQL (unique, check and foreign-key violations by SQLSTATE,
defaults, cascades on user deletion). Add a case there when a migration adds
a constraint.

When changing auth, test both success and denial: wrong tenant/environment,
permission absence, replay, expiry and revoked state. Test SDK decoding against
real response envelopes, not only mocks. Run browser flows through actual HTTPS
for cookie-bound OAuth/federation/console behavior.

## Browser suite

```sh
make test-browser                   # npm ci, Chromium, then the journeys (Docker required)
```

`tests/browser` runs Playwright in headless Chromium against IAMKit built from
the checkout (the console is rebuilt and embedded first; set
`IAMKIT_BROWSER_BINARY` to reuse a binary). `global-setup.ts` starts PostgreSQL
and Mailpit with testcontainers, terminates TLS in-process (cookies are
`Secure`/`__Host-`), runs a loopback receiver for action targets and webhooks,
and seeds the environment through the management API. The journeys cover the
console (bootstrap password change, CRUD, change history, features, limits,
sign-in texts, actions, webhooks, console languages, the org-admin portal) and
the hosted pages (password, emailed code over real SMTP, reset, TOTP
enrollment, sign-up, browser language). CI runs it as the `browser` job;
failures upload the trace, screenshots and `.stack/iamkit.log`.

## TypeScript clients and the custom sign-in parity suite

```sh
make api-client                     # @iamkit/api, @iamkit/js, @iamkit/react: typecheck, tests, build
cd examples/nextjs-login && npm ci && npx playwright install chromium && bash e2e/run.sh
```

`e2e/run.sh` builds IAMKit from the checkout and starts Postgres (Docker),
a TLS proxy, a mail webhook sink and the Next.js example on loopback ports.
It seeds them through the management API and replays the hosted journeys
(password, wrong password, emailed code, reset, MFA enrollment, sign-up,
invitation) through `<SignInForm>` in Chromium. The stack is removed on exit.
Build the three clients first: the example installs them as `file:` copies.
CI runs it as the `custom-ui-parity` job. When a hosted journey changes,
change `tests/e2e/hosted_test.go`, `custom_ui_test.go` and
`examples/nextjs-login/e2e/journeys.spec.ts` together.
