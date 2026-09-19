# Scaling and abuse controls

Multiple API replicas share PostgreSQL and must agree on issuer, signing key,
OAuth HMAC and provider bindings. Run migrations through a coordinated rollout.
Replay/transaction locking does not by itself provide global request limiting.

Rate limits are process-local. `RATE_LIMIT_PER_MINUTE` controls authenticated
management/scoped API requests (default 120 per IP per minute); login/challenge
endpoints have separate limits. Increasing replicas increases aggregate allowed
traffic unless ingress provides a shared limit. Implement per-account and
endpoint-specific abuse policy where your exposure requires it.

At the edge, constrain request sizes/timeouts, trust only known proxy hops and
verify observed client IP. Never rely on forwarded headers supplied directly by
untrusted clients. Protect bcrypt-heavy login and introspection paths from abuse.

## Capacity validation

Use a disposable representative dataset, not customer credentials. Measure login,
refresh, introspection, entity inventories and write latency under expected
concurrency. Record hardware, replicas, DB version, connection limits, request
mix, dataset size and percentile/error results. No throughput target is claimed
without such a measurement.

Test replay across replicas, dependency failure and slow webhook behavior. Keep
expired-state cleanup/retention under operational review; no general scheduled
cleanup service should be assumed. Some inventories load bounded collections
before pagination, so evaluate large tenants explicitly.
