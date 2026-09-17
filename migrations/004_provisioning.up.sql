CREATE TABLE provisioning_credentials (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, organization_id uuid NOT NULL,
 name text NOT NULL, secret_hash bytea NOT NULL UNIQUE, expires_at timestamptz NOT NULL, revoked_at timestamptz,
 FOREIGN KEY(organization_id,environment_id) REFERENCES organizations(id,environment_id), UNIQUE(id,environment_id)
);
CREATE TABLE provisioned_identities (
 credential_id uuid NOT NULL, environment_id uuid NOT NULL, user_id uuid NOT NULL, external_id text NOT NULL,
 PRIMARY KEY(credential_id,external_id), UNIQUE(credential_id,user_id),
 FOREIGN KEY(credential_id,environment_id) REFERENCES provisioning_credentials(id,environment_id),
 FOREIGN KEY(user_id,environment_id) REFERENCES users(id,environment_id)
);
