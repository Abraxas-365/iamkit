-- IdP group mapping: values of the group claim or attribute an organization's
-- identity provider sends, and the operator-managed groups of the
-- organization they put users in. Applied at every sign-in through the
-- connection, to the mapped groups only. The service and the repository
-- accept only groups with connection_id IS NULL (not SCIM groups).
CREATE TABLE federation_group_mappings (
    connection_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    value text NOT NULL,
    group_id uuid NOT NULL,
    created_at timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT federation_group_mappings_pkey PRIMARY KEY (connection_id, value, group_id),
    CONSTRAINT federation_group_mappings_value_check CHECK (length(value) BETWEEN 1 AND 512),
    CONSTRAINT federation_group_mappings_connection_fkey FOREIGN KEY (connection_id, environment_id) REFERENCES federation_connections(id, environment_id) ON DELETE CASCADE,
    CONSTRAINT federation_group_mappings_group_fkey FOREIGN KEY (group_id, environment_id, organization_id) REFERENCES groups(id, environment_id, organization_id) ON DELETE CASCADE
);
CREATE INDEX federation_group_mappings_group ON federation_group_mappings USING btree (group_id);
