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

When changing auth, test both success and denial: wrong tenant/environment,
permission absence, replay, expiry and revoked state. Test SDK decoding against
real response envelopes, not only mocks. Run browser flows through actual HTTPS
for cookie-bound OAuth/federation/console behavior.
