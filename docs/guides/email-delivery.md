# Email delivery

IAMKit sends one-time codes (`login`, `password_reset`, `email_verification`)
and [invitations](../reference/api/users-and-organizations.md#invitations). Who
sends them is the **provider**:

| Provider | Who writes the email | Who sends it |
| --- | --- | --- |
| `webhook` (default) | Your service, from the [webhook payload](../reference/webhooks.md) | Your service |
| `smtp` | IAMKit, in the environment's branding and language | Your SMTP server (SES, SendGrid, Postmark, Mailgun, Gmail, …) |
| `resend` | IAMKit, in the environment's branding and language | The [Resend](https://resend.com) API |

Every environment may have its own configuration; without one, the **global
fallback** set by the deployment applies. With neither, codes cannot be sent.

## Global fallback

Set these in the **container environment**, not just the Compose interpolation
file, and restart. `EMAIL_PROVIDER` defaults to `webhook`:

```yaml
services:
  iamkit:
    environment:
      EMAIL_WEBHOOK_URL: ${EMAIL_WEBHOOK_URL:?Set trusted HTTPS endpoint}
      EMAIL_WEBHOOK_TOKEN: ${EMAIL_WEBHOOK_TOKEN:?Set delivery credential}
```

```yaml
services:
  iamkit:
    environment:
      EMAIL_PROVIDER: smtp            # or resend
      EMAIL_FROM: no-reply@acme.example
      EMAIL_FROM_NAME: Acme
      SMTP_HOST: smtp.sendgrid.net
      SMTP_USERNAME: apikey
      SMTP_PASSWORD: ${SMTP_PASSWORD:?Set SMTP password}
      # RESEND_API_KEY: ${RESEND_API_KEY:?Set Resend API key}   # for resend
```

These are Compose override fragments; every variable is listed in the
[configuration reference](../reference/configuration.md#email). Values are checked
like an environment's configuration, so a typo stops startup with the variable
named. The deployment's own SMTP server or webhook may be on a private network;
environment SMTP/Resend/webhook configurations may not (see [containment](#containment)).

### Local development (Mailpit)

To see IAMKit's emails without sending real mail, run a mail catcher such as
[Mailpit](https://mailpit.axllent.org) and point the **global** provider at it
(environment configurations refuse private addresses unless
[`IAMKIT_ALLOW_PRIVATE_DELIVERY`](#local-development-environment-delivery-settings)
is set). IAMKit always verifies
the server certificate and uses plaintext only for `localhost`/loopback hosts,
so the catcher must be reachable on loopback:

- IAMKit on the host: `docker run -p 1025:1025 -p 8025:8025 axllent/mailpit`,
  then `EMAIL_PROVIDER=smtp EMAIL_FROM=no-reply@localhost.test SMTP_HOST=127.0.0.1 SMTP_PORT=1025`.
- Both in Compose: share IAMKit's network namespace, so Mailpit listens on
  IAMKit's loopback:

  ```yaml
  services:
    mailpit:
      image: axllent/mailpit
      network_mode: service:iamkit    # UI on the iamkit service's published 8025
    iamkit:
      ports: ["8025:8025"]
      environment:
        EMAIL_PROVIDER: smtp
        EMAIL_FROM: no-reply@localhost.test
        SMTP_HOST: 127.0.0.1
        SMTP_PORT: "1025"
  ```

A catcher on another host name (`SMTP_HOST=mailpit`) without a trusted
certificate fails with `SMTP server rejected the message` (no STARTTLS) or
`email provider could not be reached` (untrusted certificate).

### Local development: environment delivery settings

The global provider covers most local testing. To also exercise an
**environment's** own delivery settings (console → Notifications) against a
local receiver or Mailpit, start IAMKit with the development-only flag:

```dotenv
IAMKIT_ALLOW_PRIVATE_DELIVERY=true
```

Then save, for example, an environment webhook of `http://localhost:9099/mail`
or SMTP host `127.0.0.1` port `1025`, and use **Send test**. The server logs a
warning while the flag is on. **Never set it in production**: it lets anyone who
can edit delivery settings make the server call your internal network (see
[containment](#containment) and the
[configuration reference](../reference/configuration.md#private-delivery-addresses-development-only)).

With a webhook, your handler must authenticate the request — the bearer token,
or better the [signature](../reference/webhooks.md#signature), which also rejects
replays — validate the
payload, choose a safe template by purpose and deliver to the specified email.
Treat codes as secrets: suppress bodies in application, proxy, tracing and error
logs. Do not send management keys to the delivery service.

## Per-environment configuration

The console's **Notifications** page edits it (with presets for common SMTP
services), shows the status and sends test emails. With management authority,
the API is `/management/v1/environments/ENV_UUID/delivery`:

- `GET`: the configuration, never a secret: `environment_id`, `provider`,
  `invitation_url`, `created_at`, `updated_at`, the provider's fields below, and
  `has_token` (webhook token stored) / `has_secret` (SMTP password or Resend API
  key stored). Absent configuration returns 404.
- `PUT`: replace it; success is 204. `provider` defaults to `webhook`. Fields of
  another provider are rejected (400 naming them).

  | Provider | Fields |
  | --- | --- |
  | `webhook` | `webhook_url`, `webhook_token` (both required) |
  | `smtp` | `from_email` (required), `from_name`, `reply_to`, `smtp_host` (required; host name or IP, no scheme or port), `smtp_port` (default 587), `smtp_tls` (`starttls`, or `tls` for implicit TLS; default `tls` on 465, else `starttls`), `smtp_username`, `smtp_password` (required with a username) |
  | `resend` | `from_email` (required; on a domain verified in Resend), `from_name`, `reply_to`, `api_key` (required) |

  ```json
  {"provider":"smtp","from_email":"no-reply@acme.example","from_name":"Acme",
   "smtp_host":"smtp.sendgrid.net","smtp_port":587,"smtp_username":"apikey","smtp_password":"PRIVATE"}
  ```

  `smtp_password` and `api_key` are write-only. Left out on a `PUT` that keeps the
  provider, the stored one is kept, so you can change the sender without
  re-entering it. For SMTP the stored password is only kept while `smtp_host`,
  `smtp_port`, `smtp_tls` and `smtp_username` stay the same; changing any of
  them requires the password again (400), so a stored password is never sent
  to a different server. They are stored encrypted, which requires
  [`IAMKIT_ENCRYPTION_KEY`](../reference/configuration.md#encryption-key); without
  it, storing one returns 422. The webhook token is stored as before.
  Plaintext SMTP is not configurable (only a `localhost`/loopback mail catcher
  that offers no STARTTLS is used without TLS, for local development).

  Optional `invitation_url` (HTTPS) is the page an invitation email links to,
  where the invited person accepts: a new person creates an account, an existing
  one joins the organization. For your own page, IAMKit appends `token=…`; the
  page posts it to [`/identity/v1/invitations/accept`](../reference/api/identity.md#invitations).
  Webhooks receive the result as `link`; without it they get no
  link. SMTP/Resend emails always have a button: without `invitation_url` it
  opens IAMKit's own page (`https://IAMKIT_HOST/hosted/invite`,
  [hosted login](hosted-login.md#invitations)). Use private request files, not
  tracked configuration or shell history: the configuration controls where codes go.
- `DELETE`: 204; removes the override and **restores global fallback**, not
  necessarily disables delivery. Deleting an absent override returns 404.
- `GET /delivery/status`: which configuration serves the environment and what
  happened last, without any address or secret:

  ```json
  {"source":"global","provider":"smtp","global_configured":true,"hosted_invitation_url":"https://IAMKIT_HOST/hosted/invite",
   "last_attempt":{"source":"global","purpose":"login","delivered":true,"latency_ms":84,"at":"2026-09-27T10:00:00Z"},
   "last_failure":{"source":"environment","purpose":"invitation","delivered":false,"status":503,"reason":"webhook rejected the request","latency_ms":0,"at":"2026-09-26T09:12:00Z"}}
  ```

  `source` is `environment` (this environment's configuration), `global` (the
  deployment's) or `none` (nothing delivers); `provider` is the serving one (`""`
  with `none`). `last_attempt` is the latest delivery of any purpose;
  `last_failure` is the latest failed one and survives later successes. Both are
  `null` until the first delivery. `reason` is fixed text that never contains the
  provider's answer:

  | Provider | Reasons |
  | --- | --- |
  | webhook | `webhook rejected the request` (with `status`), `webhook did not respond in time`, `webhook could not be reached`, `webhook address is not allowed`, `no webhook configured`, `webhook URL is not allowed` |
  | smtp, resend | `email provider rejected the credentials`, `email provider rejected the request` (Resend, with `status`), `SMTP server rejected the message`, `email provider did not respond in time`, `email provider could not be reached`, `email provider address is not allowed`, `stored credential could not be decrypted` |
  | any | `delivery failed` |

  Recording is best effort and never blocks delivery.
- `POST /delivery/test` with `{"email":"ops@example.com"}`: sends a test through
  the effective configuration and returns the attempt (200 whether or not it was
  accepted; `delivered` says which). A webhook receives
  `{"email":"ops@example.com","purpose":"test"}`; handle or ignore purpose `test`.
  SMTP/Resend send a rendered test email. Owners/admins only, audited as
  `delivery.test`, and limited to five per minute per environment and client (429
  beyond). The console offers this as **Send test email**.

Changes are audited as `delivery.update` and `delivery.delete` (actor and
environment; never an address or secret) — review them in **Audit events**.
Scoped [`/api/v1` delivery routes](../reference/api/scoped-iam.md) also exist
(`iam:delivery:read` for `GET`, `iam:delivery:write` otherwise).

Rotating or unsetting the global configuration does not change environment
overrides. To stop delivery, remove affected overrides **and** disable global
fallback. A configuration lookup failure currently falls back to global delivery,
so do not depend on overrides alone for strict delivery isolation during DB errors.
A stored secret that cannot be decrypted (for example after losing the
encryption key) fails delivery instead of falling back; re-save the secret.

### From the `iam` CLI

`iam delivery set` replaces the configuration; secrets come from stdin or
environment variables, never from flags:

```sh
printf %s "$SMTP_PASSWORD" | iam delivery set --provider smtp \
  --from-email no-reply@acme.io --smtp-host smtp.sendgrid.net \
  --smtp-username apikey --smtp-password-stdin
IAMKIT_RESEND_API_KEY=re_... iam delivery set --provider resend --from-email no-reply@acme.io
IAMKIT_WEBHOOK_TOKEN=... iam delivery set --webhook-url https://mail.acme.io/hook
iam delivery preview --purpose login --locale es
iam delivery templates set login es --subject "Tu código: {{code}}"
```

## Emails IAMKit writes (SMTP, Resend)

Emails have an HTML and a plain-text part, in the environment's **branding**
(the hosted login default style's name, logo and primary color; client styles
do not apply) and **language**:

1. the language the request asked for: `locale` on
   `POST /identity/v1/challenges`, or the hosted login's `ui_locales`;
2. the environment's language — `locale` in
   `PUT …/login-settings` (the **Language** setting of the hosted login
   default style, which also sets the language of the hosted pages; `""` =
   server default; `GET …/login-settings/locales` lists the choices);
3. `EMAIL_LOCALE`, then English.

Available languages: the 23 of the [hosted pages](hosted-login.md#language)
(`GET …/login-settings/locales`). Invitations use steps 2–3.

`GET /delivery/preview?purpose=invitation&locale=es` returns
`{"subject","html","text"}`: a sample email with the saved branding and wording
and made-up values; nothing is sent. Purposes: `login`, `password_reset`,
`email_verification`, `invitation`, `test`. The preview is the same for a
webhook environment, which writes its own emails.

## Customizing email wording

Each email's text can be changed per purpose and language; the layout, logo and
colors come from branding. Customized wording applies to SMTP and Resend only
(a webhook writes its own emails). Under `/delivery/templates`:

- `GET /delivery/templates`: `{"items":[{"purpose","locale","customized","updated_at"}]}`,
  every purpose × language.
- `GET /delivery/templates/:purpose/:locale`: `template` (the saved wording;
  empty fields use the default), `defaults` (IAMKit's wording) and the
  `placeholders` this email may use.
- `PUT /delivery/templates/:purpose/:locale` with
  `{"subject","heading","body","action","footer"}`: saves it and returns the
  same shape as `GET`. Empty fields keep IAMKit's wording. Audited as
  `email_template.updated`.
- `DELETE /delivery/templates/:purpose/:locale`: 204; back to IAMKit's wording.
  Audited as `email_template.reset`.
- `POST /delivery/preview` with `{"purpose","locale","template":{…},"app_name"}`:
  previews unsaved wording and, optionally, an unsaved `app_name` (at most 100
  characters; `""` previews the default "IAMKit"); validated like a save,
  stored nowhere; write access.

| Field | Limit |
| --- | --- |
| `subject`, `heading` | 200 characters, one line |
| `body` | 2000 characters; blank lines separate paragraphs |
| `action` | 60 characters, one line; the button label, only for `invitation` |
| `footer` | 500 characters |

Wording is plain text: HTML is escaped, never interpreted. It may use these
placeholders, written `{{name}}`; others are rejected (400 listing the valid ones):

| Purpose | Placeholders |
| --- | --- |
| `login`, `password_reset`, `email_verification` | `app_name`, `email`, `code`, `expires_in` (minutes) |
| `invitation` | `app_name`, `email`, `organization`, `inviter`, `expires_at` |
| `test` | `app_name`, `email` |

The code itself and the invitation button are always part of the email, so
wording cannot drop them. `{{app_name}}` and the name at the top of every email
are the hosted login default style's `display_name` ("IAMKit" when empty), shared
by all emails and languages and by the hosted pages. The console's
**Notifications** page has an editor with a live preview, where the **App name**
can be changed too (it saves `display_name`); the CLI has
`iam delivery templates list|get|set|reset` and `iam delivery preview`.

## Containment

Webhook URLs require HTTPS (HTTP only on localhost/127.0.0.1), without userinfo
or fragment. Environment webhooks, SMTP hosts and the Resend API are reached only
on public addresses: private, loopback and link-local addresses are refused when
connecting (after DNS resolution), reported as `webhook address is not allowed`
or `email provider address is not allowed`. So an environment webhook on
`localhost` passes validation but is refused at send time; use the global
`EMAIL_WEBHOOK_URL` for a local receiver, or on a development machine set
`IAMKIT_ALLOW_PRIVATE_DELIVERY=true` ([local development](#local-development-environment-delivery-settings);
never in production — it removes this protection). (Before 2026-09-28 environment
webhooks were not restricted this way.) Restrict outbound network access and who may edit delivery
configuration. Stored secrets are sensitive database contents: back up the
encryption key with the database and protect both.

The webhook payload has no environment/application/resource IDs. Separate
environment endpoints can choose their own template, but cannot infer additional
tenant or application context from fields IAMKit does not send.
Delivery is synchronous with a 10-second timeout and no automatic retry queue.
Invitation mail is sent after the invitation is saved: a failed delivery is
reported as `delivery: "failed"` and does not undo the invitation.
A non-2xx response or network failure rejects delivery; do not return success
before your service has accepted responsibility for sending.

**Verify:** request OTP for an enabled test user, receive mail, complete once and
confirm replay fails. Simulate an unavailable provider and verify no secret
appears in logs. Monitor delivery rejection/latency and mailbox provider failures
(bounces, spam placement) separately.

### Deliverability checklist (SMTP, Resend)

IAMKit hands the email to your provider; whether it reaches the inbox depends on
the sender domain:

- **Verify the sender domain** with the provider (Resend requires it; SES,
  Postmark, SendGrid and others do too). `from_email` must use that domain.
- **SPF**: the domain's TXT record includes the provider (e.g.
  `include:amazonses.com`).
- **DKIM**: publish the provider's DKIM records so messages are signed for your
  domain.
- **DMARC**: publish a `_dmarc` policy (start with `p=none` and reports) and make
  sure SPF or DKIM *aligns* with the `from_email` domain.
- Use a dedicated sending subdomain (`auth.acme.com`) to keep login mail
  separate from marketing reputation, and a monitored `reply_to`.
- Send a test (`POST /delivery/test`) to Gmail and Outlook and check the
  authentication results in the headers.
