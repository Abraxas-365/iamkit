# Launch checklist

Use this as a deployment acceptance record. Check an item only after observing the
result in the target topology; do not infer it from the presence of documentation.

- [ ] Image digest, source revision and dependency review recorded; public package
  accessibility and distribution permission verified where applicable.
- [ ] Database initialized/migrated safely; backup and restore rehearsal successful.
- [ ] Signing/OAuth/provider/mail secrets stored, mounted and rotated appropriately.
- [ ] Explicit bootstrap or controlled bootstrap-log handling; recovery access tested.
- [ ] HTTPS issuer and callbacks match; console cookies and CSRF work.
- [ ] CORS/proxy trust allowlists verified; management exposure deliberately restricted.
- [ ] Before enabling `/api/v1`, fix the [known scoped-routing blockers](../reference/api/scoped-iam.md#deployment-blockers)
  and pass cross-environment and least-permission regression tests. Until then,
  restrict that API; passing ordinary login tests does not validate its isolation.
- [ ] Provisioning/login/introspection succeed; missing permission, wrong tenant,
  wrong environment and expired/revoked credential tests deny access.
- [ ] Refresh replay and concurrent refresh behavior understood by app clients.
- [ ] Mail/provider/SCIM flows tested for every integration actually enabled.
- [ ] API tenant filtering and impersonation policy reviewed in business code.
- [ ] Shared ingress abuse controls, capacity tests and alerts in place.
- [ ] Upgrade/rollback compatibility and recovery objectives recorded.
- [ ] Named operators, incident procedure, secret expiry and retention owners assigned.

Record test date, image/database versions, actual results and unresolved items.
The [documentation validation record](../maintainers/validation.md) describes
repository checks only, not acceptance of your deployment.
