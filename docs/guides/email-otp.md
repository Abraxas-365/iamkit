# Email OTP login

Prerequisites: configure [email delivery](email-delivery.md), enable `otp_enabled`
on the local user and provision the normal membership/binding/grant. OTP is a
passwordless login option, not MFA attached to a password or provider login.

1. Browser POSTs `/identity/v1/challenges`:
   `{"environment_id":"ENV_UUID","email":"alice@example.com","purpose":"login"}`.
2. Save `challenge_id` from 202. Show the same message whether the user is eligible
   or not. IAMKit sends a code to the trusted webhook; the webhook sends the email.
3. Ask for the **8-character** code and POST `/identity/v1/challenges/verify` with
   `challenge_id`, `code`, `purpose:"login"` and the full login boundary.
4. On 200, handle access/refresh tokens as in [password login](password-login.md).

```text
Browser → IAMKit: initiate (environment + email)
IAMKit → trusted mail webhook → mailbox: one-time code
Browser → IAMKit: verify (challenge + code + full boundary)
IAMKit → browser/BFF: scoped session tokens
```

Initiation currently has no application/resource context. The code is tied to
user/environment/purpose, not an application selected at step 1. Verification
checks the requested app/resource access. Do not promise per-app email routing
or application-bound challenges that the request contract does not provide.

Codes expire in five minutes; at most five wrong attempts. Resend creates a new
challenge and invalidates the previous code for that purpose. Rate-limit resend
UX and handle server throttling. Never display the webhook payload in a console.

**Verify:** correct code succeeds once; second use, expired code, disabled OTP and
wrong environment fail. Exercise mail outage separately: generic acceptance is
not evidence an email reached the inbox.
