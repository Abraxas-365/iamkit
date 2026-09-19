# Signup and onboarding

**Outcome:** a new local user with deliberately selected tenant access. There is
no unauthenticated signup endpoint. Your backend decides eligibility and calls
IAMKit; do not let the frontend choose privileged organization IDs or grants.

## Authority

Use `X-API-Key` on `/management/v1/environments/ENV_UUID` from a trusted operator
backend. This credential is workspace-wide; your backend must restrict requested
environments, organizations and grants. The alternative JWT `/api/v1` surface has
[environment and permission-routing blockers](../reference/api/scoped-iam.md#deployment-blockers)
and must not be treated as an isolated provisioning boundary until corrected.
Do not grant extra permissions to work around its routing errors.

## Orchestrate

1. Validate signup policy, invitation and email-ownership requirements in your app.
2. `POST /users` with name/email and optional password/OTP preference; save the ID.
3. `POST /memberships` with server-selected organization and user ID.
4. `PUT /grants` or `POST /role-assignments` with a server-selected default policy.
5. Return an application-level success result; never return automation credentials.
6. Start normal identity login using the app/resource boundary.

See the [executable tutorial](../examples/onboarding/run.sh) for exact management
requests and ID handling. Creation, membership and grant are separate operations,
not an atomic signup transaction. Persist progress, handle conflicts and resume
only the missing operations. Do not blindly recreate users after a timeout or
assume email equality authorizes linking to an existing identity.

If onboarding fails midway, leave an explicit pending state in your application
and avoid granting access until policy checks complete. Compensation must not
suspend an existing user shared by another organization.

Federation signup requires a pre-created local user and a trusted provider-subject
link. Do not auto-link by matching email. Password reset cannot add a password to
a passwordless account through the reset flow.

**Verify:** a user without membership/grant cannot log into the resource; an
onboarded user can. A second tenant cannot claim the same permissions by changing
request IDs. Test duplicate submission and failure after every write.
