# Integrate your application

![Trust boundaries](../assets/application-integration.svg)

Your browser owns forms; your backend owns signup/tenant policy; IAMKit owns
identity state and scoped sessions; your API enforces access to business data.
The diagram's management-key path is one integration option. The current backend
also exposes [permission-scoped IAM endpoints](../reference/api/scoped-iam.md) for
service-account/user JWTs, but [routing blockers](../reference/api/scoped-iam.md#deployment-blockers)
currently prevent relying on their environment isolation. Keep that API restricted.

## Recommended sequence

1. Operator creates an environment, app, API resource/catalog and binding.
2. Operator provisions the trusted backend's management credential. It carries
   workspace authority: expose only policy-checked onboarding actions, not a
   generic management proxy. The scoped alternative is blocked as noted above.
3. Browser submits signup to your backend. Backend validates invitation/tenant
   policy and provisions user, membership and default grant.
4. Browser/BFF signs in with a complete environment/org/app/resource boundary.
5. API validates the access token, requested organization and required permissions.
6. Client rotates refresh tokens serially and clears local state on logout.

There is no public IAMKit signup endpoint. Do not expose a generic management
proxy or trust organization/role choices supplied by a public signup form.

## Browser versus BFF

Direct integration returns tokens to your browser code. Keep them in memory,
minimize script exposure and define reload/refresh behavior. A BFF can keep refresh
tokens server-side and issue its own Secure HttpOnly cookie, with CSRF protection.
Neither approach makes CORS an authorization control. Same-origin proxying is
simpler for cookie-bound federation/OAuth; credentialed cross-origin access must
use a tightly controlled allowlist.

Provider callbacks currently issue JSON tokens, not an automatic redirect to an
arbitrary app URL. Design your HTTPS callback/BFF handoff explicitly and preserve
the browser-binding cookie. Never put tokens in query strings.

Follow [onboarding](signup-and-onboarding.md), [password login](password-login.md),
[OTP](email-otp.md), [federation](federation.md) and [protect an API](protect-an-api.md).
