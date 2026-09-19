# Email verification

Use `purpose:"email_verification"` with the same two-step challenge API:

1. POST `/identity/v1/challenges` with `environment_id`, `email`, purpose.
2. POST `/identity/v1/challenges/verify` with the environment, returned
   `challenge_id`, delivered 8-character `code` and the same purpose.
3. Expect 204; read the user/profile to confirm `email_verified:true`.

The local user must exist and be active; verification is not public registration.
The challenge requires configured [mail delivery](email-delivery.md). Use generic
messages and test expiry/replay just like OTP. App/resource context and a password
are not needed to verify an email challenge.

**Policy matters:** recording `email_verified` does not automatically block all
password logins before verification. If your product requires verification before
access, keep onboarding grants withheld until your policy checks pass. Do not
assume the client UI hiding a button enforces this requirement.

OTP and password reset also mark the email verified on successful challenge
completion. Provider email claims are not a substitute for explicit local subject
linking. See [signup](signup-and-onboarding.md).
