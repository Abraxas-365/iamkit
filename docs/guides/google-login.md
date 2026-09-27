# Google login

Two ways to use Google:

- **Social login** for everyone with a Google account: an environment
  connection with `"provider":"google"`. See [social login](social-login.md#google),
  which covers registration, sign-up and email linking.
- **One organization's Google Workspace** as its enterprise SSO: an
  [organization connection](federation.md#organization-sso) with
  `"provider":"google"` and the organization's `organization_id`. JIT
  provisioning then admits only emails of the organization's verified
  domains, so other Google accounts are refused.

Either way, register a *Web application* OAuth client in Google Cloud with the
exact redirect URI `${JWT_ISSUER}/identity/v1/federation/callback`. IAMKit
requests `openid profile email`, uses PKCE and a nonce, and verifies the ID
token against `https://accounts.google.com`; it never accepts an access token
as proof of identity.

For redirect mismatches compare scheme, host and path with the registration
exactly; for consent errors check the consent screen's publishing status and
test users. A Google sign-in still needs local membership and grants.

Provider documentation: [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect).
