# SCIM SDK

`scimclient.New(baseURL, provisioningSecret, scimclient.WithHTTPClient(client))`
uses an `ik_scim_` credential through X-API-Key. Keep it on a trusted provisioning
service, not in a browser. Base URL is the IAMKit server root.

Methods: `Create`, `Get`, `List`, `Replace`, `Patch`, `Delete`. Use `User` and
`Operation` DTOs for the supported server fields; do not assume arbitrary SCIM
extensions are accepted.

```go
page, err := client.List(ctx, `userName eq "alice@example.com"`, 1, 100)
```

This fragment assumes a constructed client/context. Start index is **1-based**;
passing zero is rejected by the server. Count is at most 100. Inspect
`totalResults`, `startIndex`, `itemsPerPage` and `Resources` rather than ordinary
IAMKit page fields. SCIM errors use its protocol schema.

The enterprise manager schema is
`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`; manager values must
reference users in the same provisioning connection. Rotate credentials on the
same connection to preserve external-ID ownership.

See [SCIM reference](../api/scim.md) and
[provisioning guide](../../guides/scim-provisioning.md).
