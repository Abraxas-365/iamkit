# GeoIP

[Risk signals](../sign-in/risk-signals.md) can use the client's **country** (for
country restrictions) and **coordinates** (for impossible travel). IAMKit does not
ship a GeoIP database and does not call an online service: GeoIP is
**optional and deployment-wide**, supplied by one of two sources. Without
either, everything else keeps working; only the two features that need
location are unavailable.

| Source | Setting | Gives | Needs |
| --- | --- | --- | --- |
| Database file | `IAMKIT_GEOIP_DB=/path/GeoLite2-City.mmdb` | Country, and coordinates with a City database | A MaxMind-format `.mmdb` file readable by IAMKit |
| Country header | `IAMKIT_GEOIP_HEADER=CF-IPCountry` | Country only | A trusted proxy that sets the header, and `IAMKIT_TRUSTED_PROXIES` |

| Feature | Country header | Country database | City database |
| --- | --- | --- | --- |
| Country on attempts and events | yes | yes | yes |
| `country` restrictions | yes | yes | yes |
| `impossible_travel` | no | no | yes |

When no source is configured, setting `impossible_travel` or creating a
`country` restriction answers 422 `GEOIP_REQUIRED`, and the console shows them
disabled. With a country-only source, `impossible_travel` is refused the same way.
`GET …/environments/:environment/risk/status` (`iam risk status`) tells you what
the running deployment has:

```json
{"geoip":{"source":"mmdb","database":"GeoLite2-City","build_date":"2026-10-06T00:00:00Z","countries":true,"travel":true},
 "captcha":true,"risk_signals":true}
```

`source` is `mmdb`, `header` or `none`; `error` appears when a database file
cannot be read. If both sources are configured the database is used when it can locate the
address; otherwise the trusted header is the fallback. `risk/status` reports
`source: "mmdb"` while a readable database is loaded (and includes `header`
when configured), or `source: "header"` when the header is the active source.

## MaxMind GeoLite2

1. Create a free [GeoLite2 account](https://www.maxmind.com/en/geolite2/signup),
   accept the license and note your **account ID**.
2. Generate a **license key** under *Manage license keys*.
3. Download the database. Use **GeoLite2-City** for impossible travel; **GeoLite2-Country** is
   smaller and enough for country restrictions. For a one-off download use the
   account's *Download files* page. To keep it fresh run MaxMind's
   [`geoipupdate`](https://github.com/maxmind/geoipupdate), which needs the
   account ID, the license key and the edition ids (`GeoLite2-City`).
   MaxMind refreshes GeoLite2 twice a week (Tuesdays and Fridays), and its license asks you to
   keep the data current.
4. Point IAMKit at the file: `IAMKIT_GEOIP_DB=/geoip/GeoLite2-City.mmdb`.

IAMKit opens the file read-only and checks its modification time **every minute**;
when `geoipupdate` replaces it the new version is loaded without a restart
(replace it atomically, as `geoipupdate` does, so a half-written file is never
read). A file that cannot be read is reported as `error` in `risk/status`.

A free GeoLite2 download is **City-level and approximate**: addresses of mobile
carriers, VPNs and corporate networks are often located far from the user. This
is why impossible travel needs a minimum distance (500 km) and a speed
threshold, why `challenge` is a better action than `block`, and why you should
start in [log mode](../sign-in/risk-signals.md#start-in-log-mode).

### Compose

The Compose variants have a `geoip` profile that runs `geoipupdate` in its own
container and shares a volume (`/geoip`, read-only for IAMKit) with IAMKit:

```sh
# deploy/compose/<variant>/.env
COMPOSE_PROFILES=geoip
GEOIPUPDATE_ACCOUNT_ID=<your account id>
GEOIPUPDATE_LICENSE_KEY=<your license key>
IAMKIT_GEOIP_DB=/geoip/GeoLite2-City.mmdb
```

`setup.sh` writes exactly these lines for you when `GEOIPUPDATE_ACCOUNT_ID` and
`GEOIPUPDATE_LICENSE_KEY` are set in its environment; otherwise it leaves them
commented out in `.env`. Optional: `GEOIPUPDATE_EDITION_IDS` (default
`GeoLite2-City`; use `GeoLite2-Country` for country only, and adjust
`IAMKIT_GEOIP_DB`) and `GEOIPUPDATE_FREQUENCY` (hours between updates, 72 by
default). `docker compose up -d --wait` waits for the first download to finish.
See [Compose with TLS](../../operations/deployment.md#compose-with-tls).

### Kubernetes

Set `geoip.enabled=true` and give the chart a Secret holding the account id and
license key. Every pod then runs a `geoip-update` sidecar that downloads the
database into a pod-local volume shared read-only with IAMKit and refreshes it
every `geoip.frequencyHours` (72). A failed download is retried every 15
minutes and never makes the pod unready; no shared storage is needed.

```sh
kubectl create secret generic iamkit-geoip \
  --from-literal=GEOIPUPDATE_ACCOUNT_ID=<your account id> \
  --from-literal=GEOIPUPDATE_LICENSE_KEY=<your license key>
helm upgrade --install iamkit … --set geoip.enabled=true --set geoip.existingSecret=iamkit-geoip
```

The chart sets `IAMKIT_GEOIP_DB` to `/geoip/<geoip.editionId>.mmdb`
(`GeoLite2-City` by default). For header mode set `geoip.header=CF-IPCountry`
together with `trustedProxies`; the chart refuses to render the header without
them. Confirm the effective source in `GET …/risk/status` before enabling a
country restriction or `impossible_travel`; `countries` and `travel` must both
be `true` for the latter. See [Kubernetes (Helm)](../../operations/deployment.md#kubernetes-helm).
Anything else (a baked image, a volume you manage, an init container) works as
long as `IAMKIT_GEOIP_DB` names a readable file.

## DB-IP Lite

[DB-IP](https://db-ip.com/db/lite.php) publishes free "Lite" City and Country
databases in the same MMDB format under a Creative Commons Attribution license
(keep the attribution it requires). Download the monthly `.mmdb`, decompress it
and point `IAMKIT_GEOIP_DB` at it. Nothing else changes; there is no account or
license key. Replace the file when a new month is published (IAMKit reloads on
change). Its accuracy is comparable to GeoLite2's; compare both on your own traffic
before choosing.

## Country header

If your edge already knows the country, let it say so:

- Cloudflare: `CF-IPCountry` (enable *IP Geolocation* in the dashboard
  under **Network**).
- Other CDNs and load balancers have equivalents (for example `CloudFront-Viewer-Country`,
  `X-AppEngine-Country`); use any header whose value is a two-letter
  country code.

```sh
IAMKIT_GEOIP_HEADER=CF-IPCountry
IAMKIT_TRUSTED_PROXIES=203.0.113.0/24      # your proxy's addresses
```

The header is a claim made by whoever sent the request, so IAMKit believes it
**only on requests from a proxy in `IAMKIT_TRUSTED_PROXIES`** (the same
list that lets IAMKit read `X-Forwarded-For`), and **refuses to start**
when `IAMKIT_GEOIP_HEADER` is set without it. Your proxy must also
*overwrite* the header on every request so a client cannot forge it
(Cloudflare does; check the others). Values that are not two letters, or
`XX`/`T1` style "unknown" markers, are ignored. Header mode gives a country, never
coordinates, so it supports country restrictions but not impossible travel.

## Privacy

- IP addresses and countries are personal data in many jurisdictions. IAMKit
  stores them on sign-in attempts and sessions for
  `IAMKIT_SIGN_IN_ATTEMPT_RETENTION` (30 days by default) and in the event log
  for `IAMKIT_EVENT_RETENTION`; shorten both if your policy says so.
- Lookups are local: the address never leaves your deployment for geolocation.
  (`geoipupdate` talks to MaxMind with your account credentials, not with addresses.)
- Only a country code and, with a City database, the coordinates of
  the address are stored, not a street address, and no device fingerprint is collected.
- The device cookie and `device_id` are random identifiers stored only as keyed hashes.
- Disable all of it with `IAMKIT_FEATURES=risk_signals=false`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `risk/status` says `source: none` | `IAMKIT_GEOIP_DB` is unset or the file does not exist inside IAMKit's container; check the volume mount |
| Status shows `error` | The file is truncated or not an MMDB; re-download it |
| Country is empty on every attempt | The client address is the proxy's; set `IAMKIT_TRUSTED_PROXIES`. Private addresses (10.x, 192.168.x, loopback) have no location |
| Header mode never fills the country | The request does not come from a trusted proxy, or the header name differs (names are case-insensitive) |
| Server refuses to start: `IAMKIT_GEOIP_HEADER needs IAMKIT_TRUSTED_PROXIES` | Set both |
| 422 `GEOIP_REQUIRED` when saving a policy or restriction | The deployment has no source, or only a country source for `impossible_travel` |

Configuration is listed in the [reference](../../reference/configuration.md).
