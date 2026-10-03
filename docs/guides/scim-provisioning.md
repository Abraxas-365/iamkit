# SCIM provisioning

Use SCIM to synchronize an organization's users from a trusted directory. It is
not public signup or an OAuth provider login. An operator first POSTs
`/management/v1/environments/ENV_UUID/provisioning-credentials`:

```json
{"name":"Acme directory","organization_id":"ORG_UUID","expires_in":"24h"}
```

Save the 201 `secret`, `connection_id`, `id` and expiry. Configure the directory's
SCIM base URL as `https://YOUR_IAMKIT_HOST/scim/v2` and the secret as its
**bearer / secret token** (sent as `Authorization: Bearer`; `X-API-Key` also
works for custom clients). Do not send a management key.

Directory notes:

- **Microsoft Entra ID**: Enterprise application → Provisioning → Tenant URL and
  Secret Token as above. Map `externalId` to `objectId`. Default attribute
  mappings work; unstored attributes (title, department, …) are ignored.
- **Okta**: SCIM 2.0 app with "HTTP Header" authentication (Bearer). Unique
  identifier field `userName`; push `externalId` if available.
- UPN/email renames update the user's login email and keep the same identity,
  unless the user is shared with another organization or directory.
- Unassigning a user (Entra "soft delete" `active=false`) deactivates the
  membership: the user's sessions in the organization end at once, and a
  `membership.updated` event with `data.changes.active: [true, false]` (actor
  `directory`) reaches webhooks and the user's history. A hard DELETE deprovisions it, removes its access in the
  organization and returns 404 until reassigned.

Create a test user through SCIM with a stable `externalId`. Read it back, change
its profile, deactivate it and verify access is removed for this provisioning
boundary. Directory changes should not rewrite unrelated organizations' profiles.
Manager references must resolve through the same connection and cannot form cycles.

For existing users, an operator explicitly links
`{connection_id,user_id,external_id}` via `/provisioned-identities`, or issues
the connection with `"adopt_existing_members": true` so that directory users are
matched to existing members of the organization by email. Adoption never reaches
users outside the organization, and the directory cannot rename the login email
of users it adopted or that were linked (only of users it created). Add
`"adopt_scope": "verified_domains"` to adopt only members whose email is on one
of the organization's verified domains (Organization → Members → Domains).
Disable adoption by issuing a credential on the same connection with
`"adopt_existing_members": false`; every change is audited.

## Phone numbers

Directories send phone numbers, but IAMKit keeps them only when asked:
issue the connection's credential with `"map_phone": true` (console: *Sync
mobile phone numbers*). The user's `mobile` number then becomes their phone
(unverified — users confirm it themselves, or operators mark it verified);
other types are ignored and invalid numbers leave the phone as it was.
Without it, a directory never reads, sets or clears phones, so turning on SCIM
for an existing organization cannot wipe numbers users verified.

## Groups

Enable group push in the directory (Entra: *Provision Microsoft Entra ID
Groups*; Okta: *Push Groups*). Pushed groups appear as organization groups with a
Directory badge in the console. The directory owns their name and members;
operators decide what they grant by assigning roles to them (console → Groups →
group → *Assign role*, or `POST /group-role-assignments`). Members receive those
roles at their next token; removing a user from the group in the directory
removes them. Group members must be users provisioned by the same connection,
so assign users to the application before, or together with, their groups.
Deleting a group in the directory removes its role bindings as well. See
[SCIM Groups](../reference/api/scim.md#group-resource).

## Rotation

Issue a new provisioning credential with the **same connection_id** and
organization to preserve mappings (omit `adopt_existing_members` to keep the
connection's setting). Deploy/test it, then DELETE the old credential
ID. Creating a fresh connection is not equivalent to rotating a credential.

See [SCIM reference](../reference/api/scim.md) for supported operations/filtering.
Test list pagination from `startIndex=1`, duplicate external IDs, out-of-connection
manager references and revoked credentials. Use a test directory; a configuration
snippet alone is not a verified vendor integration.
