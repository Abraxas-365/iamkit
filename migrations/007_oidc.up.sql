CREATE TABLE oauth_clients (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, application_id uuid NOT NULL, resource_id uuid NOT NULL,
 redirect_uris text[] NOT NULL, public boolean NOT NULL, secret_hash bytea NOT NULL DEFAULT '', active boolean NOT NULL DEFAULT true,
 UNIQUE(id,environment_id),
 FOREIGN KEY(environment_id,application_id,resource_id) REFERENCES application_resources(environment_id,application_id,resource_id)
);
CREATE TABLE oauth_requests (
 environment_id uuid NOT NULL, kind text NOT NULL, signature_hash text NOT NULL,
 client_id uuid NOT NULL, request_id text NOT NULL, data jsonb NOT NULL,
 expires_at timestamptz NOT NULL, active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(environment_id,kind,signature_hash),
 FOREIGN KEY(client_id,environment_id) REFERENCES oauth_clients(id,environment_id)
);
CREATE INDEX oauth_request_family ON oauth_requests(environment_id,request_id);
CREATE TABLE oauth_authorizations (
 secret_hash bytea PRIMARY KEY, environment_id uuid NOT NULL, client_id uuid NOT NULL,
 binding_hash bytea NOT NULL, request_form text NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz,
 FOREIGN KEY(client_id,environment_id) REFERENCES oauth_clients(id,environment_id)
);
