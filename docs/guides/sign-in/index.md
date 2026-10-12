# Authentication

Let people sign in to your application using passwords, email codes, passkeys,
social providers or enterprise SSO. Choose the methods you need and add security
controls without changing your application's authorization model.

## Connect your application first

You need a running IAMKit environment and an application linked to an API
resource. If you have not created them, follow
[your first application](../../start/first-application.md).

- **Use IAMKit's pages:** [hosted sign-in](../applications/hosted-login.md) handles the sign-in journey through OAuth authorization code and PKCE.
- **Build your own pages:** [custom sign-in UI](../applications/custom-sign-in-ui.md) covers the browser client and React flow.
- **Integrate on your server:** [choose an SDK](../../reference/sdk/index.md) for token verification, sessions and backend API calls.

## Choose sign-in methods

Set the environment's [sign-in policy](sign-in-methods.md), then narrow it for
individual organizations or hosted applications as needed.

| Method | Guide |
| --- | --- |
| Email and password, including password reset | [Passwords](passwords.md) |
| One-time email codes | [Email codes](email-otp.md) |
| Passkeys and a second factor | [Passkeys and MFA](mfa.md) |
| Google, Microsoft, GitHub and other social providers | [Social login](../enterprise/social-login.md) |
| Your customers' identity providers | [Enterprise connections](../enterprise/index.md) |

## Onboard and protect users

Start with [sign-up and onboarding](signup-and-onboarding.md) to choose between
self-service registration, invitations and backend-controlled provisioning.
Use a [waitlist](waitlist.md) when registration needs approval.

Security controls are separate from the sign-in UI:

- [Password policies](password-policy.md) define password requirements.
- [Bot protection](bot-protection.md) adds CAPTCHA to supported public forms.
- [Risk signals](risk-signals.md) detect suspicious activity and apply configured responses.
- [Session management](sessions.md) lets users inspect and end their sessions.

## Verify your integration

Check a successful sign-in and a refused credential. Then follow
[protect your API](../../start/protect-an-api.md) to verify permission and
organization checks: signing in alone does not grant access to business data.

## Reference

[Identity API](../../reference/api/identity.md) ·
[Token claims](../../reference/token-claims.md) ·
[Errors](../../reference/errors-and-pagination.md)
