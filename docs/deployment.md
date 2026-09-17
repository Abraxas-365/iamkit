# Deployment

A practical checklist for running IAMKit somewhere other than a laptop. This organizes the
constraints already stated in [Security status](../SECURITY.md) into an actionable order; that
document remains the authoritative source — read it in full before any non-local deployment.

> [!IMPORTANT]
> IAMKit is early development: not independently audited or certified. See
> [Security status](../SECURITY.md) for exactly what is and isn't implemented before deciding
> this is production-ready for your use case.

## 1. Before you start

- [ ] An empty, managed PostgreSQL database. `migrate` refuses to run against a non-empty schema
      it doesn't own — see [Getting started](getting-started.md) and
      [Configuration](configuration.md#database-not-environment-variables).
- [ ] A stable HTTPS domain for `JWT_ISSUER`. Plain HTTP only works for local password/machine
      login; OAuth and federation browser-binding cookies require HTTPS
      (`Secure`/`__Host-` cookies).
- [ ] Secret management for: the RSA signing key, `OIDC_HMAC_SECRET`, `EMAIL_WEBHOOK_TOKEN`,
      every `IAMKIT_PROVIDER_*` value, and `DATABASE_URL`'s credentials. None of these belong in
      source control, browser code, or logs.

## 2. Core configuration

Set every variable listed in [Configuration](configuration.md). In particular:

- [ ] Generate a real RSA key (2048+ bits), not a dev key reused from `.dev-secrets/`:
      `openssl genrsa -out /path/jwt.pem 2048 && chmod 600 /path/jwt.pem`. This key signs every
      token; protect it like the rest of your trust root.
- [ ] `OIDC_HMAC_SECRET`: at least 32 random bytes, stable across restarts (rotating it
      invalidates in-flight OAuth/federation state). Only required if you use `/oauth/*` or
      federation.
- [ ] Restrict database access and egress at the network layer — IAMKit does not enforce this
      itself.

## 3. Run migrations, then bootstrap

```sh
go run ./cmd/iamkit migrate
go run ./cmd/iamkit bootstrap --email owner@example.com --workspace "Your Workspace" --output /secure/path/owner.json
```

- [ ] `bootstrap`/`recover-owner` write exclusively newly-created `0600` files — never rerun
      them pointed at a path that could already exist with different permissions.
- [ ] The written management credential expires in 24 hours. Move it into real secret storage
      immediately and rotate (`POST /management/v1/keys`) before expiry — see
      `api.md#operator-administration`.
- [ ] Plan for **offline owner recovery**: know how you'll run `recover-owner` (which needs
      trusted local database access) if the credential is lost. This isn't self-service from the
      API.

## 4. Optional subsystems — only enable what you need

Each of these is off by default and adds its own operational surface:

- [ ] **Email delivery** (`EMAIL_WEBHOOK_URL`): must be your own trusted HTTPS service. IAMKit
      gives it a 10-second timeout, follows no redirects, and never logs the OTP code — your
      webhook implementation must uphold the same discipline for the payload it receives.
- [ ] **External federation** (`FEDERATION_CREDENTIAL_BINDINGS`): only approve issuers you trust,
      including every endpoint their OIDC discovery metadata advertises — an approved issuer is
      effectively a trusted code path into your system. See
      [Recipes → Google login](recipes.md#recipe-let-a-products-users-sign-in-with-google).
- [ ] **OAuth/OIDC server** (`OIDC_HMAC_SECRET` set, `/oauth-clients` created): confidential
      client secrets are returned once — capture and store them immediately, same discipline as
      the management credential.
- [ ] **SCIM provisioning**: `ik_scim_...` credentials are organization-bound and expire in 24
      hours by default; plan rotation the same way as management keys (see
      [Recipes → SCIM rotation](recipes.md#recipe-provision-users-automatically-from-your-identity-provider-scim)).

## 5. Ingress / edge concerns IAMKit does not handle for you

- [ ] **Rate limiting is process-local only** — a multi-replica deployment does not get
      cross-replica rate limiting for free. Protect `/identity/v1/login`,
      `/identity/v1/introspect` and other expensive endpoints at your ingress/load balancer if
      you run more than one replica or expect abuse.
- [ ] **Trusted proxy configuration** (`X-Forwarded-For` etc.) is not handled — configure your
      edge/proxy layer according to Fiber's own trusted-proxy settings if you rely on client IPs
      anywhere downstream.
- [ ] Per-account abuse controls, comprehensive audit retention, and expired-record cleanup are
      not implemented — build them at your operational layer if required.

## 6. Before going live

- [ ] Confirm upstream ownership/licensing (`README.md#provenance--license`) and complete a
      secrets audit — no license is asserted for distribution as-is.
- [ ] Review the dependency graph for retracted/vulnerable packages (Fosite's transitive
      dependencies currently include a retracted `github.com/dgraph-io/ristretto v1.0.0` — verify
      current status before shipping).
- [ ] Decide your signing-key rotation plan; it is not automated.
- [ ] Re-read [Security status](../SECURITY.md) end to end — this checklist reorganizes it but
      does not replace it.

## Multiple replicas

Concurrent refresh/OAuth-code rotation is serialized by endpoint family locks so replay across
replicas is still caught (see [Security status](../SECURITY.md)), but process-local rate
limiting means each replica enforces its own limit independently — factor that into capacity
planning, not just correctness.
