# SCIM provisioning

Use SCIM to synchronize an organization's users from a trusted directory. It is
not public signup or an OAuth provider login. An operator first POSTs
`/management/v1/environments/ENV_UUID/provisioning-credentials`:

```json
{"name":"Acme directory","organization_id":"ORG_UUID","expires_in":"24h"}
```

Save the 201 `secret`, `connection_id`, `id` and expiry. Configure the directory's
SCIM base URL as `https://YOUR_IAMKIT_HOST/scim/v2` and supply the secret through
**`X-API-Key`**. Some directory products only support a Bearer header; verify
compatibility before promising a native connector. Do not send a management key.

Create a test user through SCIM with a stable `externalId`. Read it back, change
its profile, deactivate it and verify access is removed for this provisioning
boundary. Directory changes should not rewrite unrelated organizations' profiles.
Manager references must resolve through the same connection and cannot form cycles.

For existing users, an operator explicitly links
`{connection_id,user_id,external_id}` via `/provisioned-identities`. Do not assume
email collision automatically transfers identity ownership.

## Rotation

Issue a new provisioning credential with the **same connection_id** and
organization to preserve mappings. Deploy/test it, then DELETE the old credential
ID. Creating a fresh connection is not equivalent to rotating a credential.

See [SCIM reference](../reference/api/scim.md) for supported operations/filtering.
Test list pagination from `startIndex=1`, duplicate external IDs, out-of-connection
manager references and revoked credentials. Use a test directory; a configuration
snippet alone is not a verified vendor integration.
