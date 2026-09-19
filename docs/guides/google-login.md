# Google login

Prerequisites: [federation setup](federation.md), HTTPS IAMKit issuer and a Google
Cloud project you administer. This guide describes the registration contract;
live provider login must be verified in your own test project.

1. Configure the Google OAuth consent screen and test users/publishing settings
   appropriate to your application.
2. Create a web application OAuth client. Add the exact redirect URI
   `https://YOUR_IAMKIT_HOST/identity/v1/federation/callback`.
3. Use issuer `https://accounts.google.com`, the assigned client ID and a private
   `IAMKIT_PROVIDER_GOOGLE` secret variable in the deployment binding.
4. Create the federation connection with the same issuer/client/secret reference.
5. Enroll a local user and link the provider's verified `sub` for this client.
   Do not copy an unverified token payload or infer the subject from email.
6. Start federation with the user's intended organization/app/resource boundary.

The adapter requests `openid profile email`; it verifies the ID token rather
than accepting an access token as identity proof. A successful Google sign-in
still needs local membership and grants.

Test linked login and an unlinked Google account. For redirect mismatch, compare
scheme/host/path against the provider registration exactly. For consent errors,
check project audience/test-user settings before changing IAMKit authorization.

Provider documentation: [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect).
Keep provider client secrets server-side and rotate through deployment storage.
