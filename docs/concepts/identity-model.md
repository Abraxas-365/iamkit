# Identity model

A workspace is the operator authority boundary. Projects group isolated
environments. Use separate environments for development, staging and production;
a user ID from one environment is not a user in another.

Within an environment:

- **User:** local identity, optional password, OTP preference and metadata.
- **Organization:** tenant/business membership boundary. One user may belong to
  several organizations; login selects one organization for the session.
- **Application:** client experience requesting tokens.
- **Resource:** protected API, immutable audience/prefix and exact permission catalog.
- **Binding:** allows an application to request a resource; does not grant user access.
- **Grant:** permissions for a user + organization + resource. Roles group resource
  permissions and role assignments associate them with an organization member.
- **Federation connection:** approved external OIDC issuer/client credentials.
  External subject links resolve to local users; matching email is not a link.
- **Service account:** machine identity bound to an app/resource and permissions.

There is also a built-in **IAM resource**, prefix `iam`, audience
`urn:iamkit:environment:ENV_UUID`. Its permissions authorize selected operations
through `/api/v1`, not workspace operator administration. Do not confuse it with
your Invoices API resource or an application named IAM.

A user can sign in through several methods and still resolve to the same user ID.
Each login creates a session; it does not merge all devices into one session.
Organization units, managers and positions describe structure, not implicit access.

Next: [authorization](authorization.md), [credentials](credentials-and-boundaries.md).
