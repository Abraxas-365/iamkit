# Forgot password

Your app provides the form. IAMKit uses the challenge API with
`purpose:"password_reset"`; [email delivery](email-delivery.md) must be configured.
The user must already have a password. This flow does not add a password to a
federation-only/passwordless account.

```http
POST /identity/v1/challenges
Content-Type: application/json

{"environment_id":"ENV_UUID","email":"alice@example.com","purpose":"password_reset"}
```

Show the generic 202 message, store the returned challenge ID and collect the
8-character code and a new 12–72 byte password. Then:

```http
POST /identity/v1/challenges/verify
Content-Type: application/json

{"environment_id":"ENV_UUID","challenge_id":"CHALLENGE_UUID","code":"12345678","purpose":"password_reset","password":"new-unique-password"}
```

Use real IDs and the delivered code. Success is **204 with no token response**;
return the user to login. Full org/app/resource context is not required for reset.
Reset marks email verified and password changes invalidate sessions/challenges;
offline JWT consumers cannot observe revocation instantly.

Codes expire in five minutes, are single-use and allow five failures. Resending
supersedes the old same-purpose challenge. Never log codes or new passwords.

**Verify:** new password logs in; old password fails; replayed reset fails; old
session is rejected by online introspection. Use a disposable user for the test.
