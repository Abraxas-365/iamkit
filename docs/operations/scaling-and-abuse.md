# Scaling and abuse controls

Multiple API replicas share PostgreSQL and must agree on issuer, signing key,
OAuth HMAC and provider bindings. Run migrations through a coordinated rollout.
Replay/transaction locking does not by itself provide global request limiting.

Every replica runs the back-channel logout dispatcher (every 5 seconds, 20
notifications per round). Replicas lease rows with `FOR UPDATE SKIP LOCKED`, so
adding replicas adds delivery capacity without duplicate sends; a replica that
stops mid-send loses its lease after two minutes and another one retries. Egress
to relying parties' logout URLs must be allowed (public addresses only).

Rate limits are process-local unless `REDIS_URL` is set (below), and key on
the client address, which behind a proxy needs `IAMKIT_TRUSTED_PROXIES`
([forwarded headers](reverse-proxy.md#forwarded-headers)) — otherwise all
clients share the proxy's limit.
`RATE_LIMIT_PER_MINUTE` controls authenticated management/scoped API requests
(default 120 per IP per minute); login/challenge endpoints have separate limits.
Without Redis, increasing replicas increases aggregate allowed traffic unless
ingress provides a shared limit. Implement per-account and endpoint-specific
abuse policy where your exposure requires it.

Device authorization user codes have 20⁸ (≈2.6×10¹⁰) values and live ten
minutes; per-IP limits (`/oauth/device_authorization` at the general limit,
`POST /hosted/device*` at 10/min) keep guessing impractical from one address.
Behind a shared ingress limit, keep code entry at least as tight.

At the edge, constrain request sizes/timeouts, trust only known proxy hops and
verify observed client IP. Never rely on forwarded headers supplied directly by
untrusted clients. Protect bcrypt-heavy login and introspection paths from abuse.

## Redis (optional)

With `REDIS_URL`, every replica uses one Redis for:

- **Per-IP rate limits** of every route: the counters are shared, so the limits
  hold for the deployment instead of per replica. Two replicas reading and
  writing one counter at the same moment may each admit a request, so a limit
  can be exceeded by a few requests under heavy concurrency.
- **Per-minute [usage limits](../guides/usage-limits.md)** (`requests_per_minute`,
  `action_calls_per_minute`): one atomic counter per environment and minute.
- **Caches** of reads that happen on every sign-in or token: feature flag
  overrides and action bindings (30 seconds) and identity providers' OIDC
  discovery documents (15 minutes). A management change deletes the entry, so
  every replica sees it on the next request; Redis only holds copies.

Only these reads are cached because they were measured: a PostgreSQL point read
costs about 0.5 ms from the application and a Redis read about 0.2 ms, so
caching ordinary reads saves little, while discovery is an HTTPS round trip to
the provider on every federated sign-in. Daily counters (emails, SMS), quotas
and the event log stay in PostgreSQL.

Redis is not required to be up. Each call has a 250 ms deadline; when Redis does
not answer, caches read PostgreSQL and counters fall back to the replica's own
memory, and `GET /health` stays 200 with `cache: "down"` (one warning is logged
per minute). Keys are prefixed `iamkit:` and all expire, so Redis needs no
persistence and can be shared with other applications (use a database number of
its own, `redis://host:6379/2`). Use `rediss://` and a password
(`rediss://:password@host:6380/0`) when Redis is not on a private network.

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
