# Testing

Run from the repository root unless a command names another directory:

```sh
make test
make vet
make test-e2e
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
