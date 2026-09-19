# Management and scoped Go clients

Construct `iamclient.New(baseURL, managementKey, iamclient.WithHTTPClient(client))`
for operator administration. `Environment(environmentID)` supplies typed entity
methods. `CreateProject`, `CreateEnvironment`, `CreateUser`, `AddMember`,
`BindResource`, `PutGrant` and integration helpers mirror management operations.
Use `context.WithTimeout` and check every returned error before using an ID.

For a list returning a page, a low-level pattern is:

```go
var page struct {
    Items []iamclient.User `json:"items"`
    Page struct { Total, Limit, Offset int } `json:"page"`
}
err := client.Do(ctx, "GET", "/environments/"+environmentID+"/users", nil, &page)
```

This is a fragment: construct the client/context and use a trusted UUID first.
Typed slice list methods currently need envelope compatibility work; see
[SDK overview](go.md). The low-level management path cannot contain `?`, so use
explicit HTTP URL query handling for filters until a matching helper exists.

`apiclient.New(baseURL, jwt, ...)` targets `/api/v1`, not `/management/v1`.
Exchange a service credential with `authclient.MachineToken`, pass its access JWT,
and refresh that token through another exchange when needed. `SetToken` updates
the client's token; coordinate concurrent use rather than racing token mutation.
Never pass raw `ik_svc_` credentials to `apiclient`.

Management authority is workspace-wide. Scoped IAM writes require explicit IAM
permissions and still deserve privileged-backend isolation. Neither client belongs
in browser code. **The backend currently has environment and permission-routing
blockers on `/api/v1`; the SDK does not compensate for them.** See
[scoped-route blockers](../api/scoped-iam.md#deployment-blockers) before enabling it.
