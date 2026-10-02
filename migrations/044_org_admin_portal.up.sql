-- Built-in OAuth clients IAMKit registers itself. 'org_admin' is the hosted
-- organization administration portal (/org-admin): one per environment, a
-- public hosted-login client of its own application linked to the IAM
-- resource. Operators turn it on and off (…/org-admin-portal) but never
-- edit it through /oauth-clients.
ALTER TABLE oauth_clients
    ADD COLUMN system text CHECK (system IN ('org_admin'));
CREATE UNIQUE INDEX oauth_clients_system ON oauth_clients(environment_id, system) WHERE system IS NOT NULL;
