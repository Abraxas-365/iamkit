CREATE TABLE federation_connections (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL REFERENCES environments(id),
 name text NOT NULL, issuer text NOT NULL, client_id text NOT NULL,
 secret_env text NOT NULL, active boolean NOT NULL DEFAULT true,
 UNIQUE(id,environment_id), UNIQUE(environment_id,issuer,client_id)
);
CREATE TABLE external_identities (
 connection_id uuid NOT NULL, environment_id uuid NOT NULL, subject text NOT NULL, user_id uuid NOT NULL,
 PRIMARY KEY(connection_id,subject), UNIQUE(connection_id,user_id),
 FOREIGN KEY(connection_id,environment_id) REFERENCES federation_connections(id,environment_id),
 FOREIGN KEY(user_id,environment_id) REFERENCES users(id,environment_id)
);
CREATE TABLE federation_states (
 secret_hash bytea PRIMARY KEY, connection_id uuid NOT NULL, environment_id uuid NOT NULL,
 organization_id uuid NOT NULL, application_id uuid NOT NULL, resource_id uuid NOT NULL,
 binding_hash bytea NOT NULL, nonce text NOT NULL, verifier text NOT NULL,
 expires_at timestamptz NOT NULL, consumed_at timestamptz,
 FOREIGN KEY(connection_id,environment_id) REFERENCES federation_connections(id,environment_id),
 FOREIGN KEY(organization_id,environment_id) REFERENCES organizations(id,environment_id),
 FOREIGN KEY(environment_id,application_id,resource_id) REFERENCES application_resources(environment_id,application_id,resource_id)
);
