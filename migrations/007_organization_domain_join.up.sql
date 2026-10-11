-- Auto-join by verified domain (domain capture without SSO). With domain_join
-- on, a human user whose verified email is on one of the organization's
-- verified domains becomes a member when they sign in or sign up, and joins
-- domain_join_group_id (an operator-managed group of the organization, whose
-- roles the new member gets) when one is set. Removed members stay as
-- inactive membership rows, which sign-in never reactivates, so an explicit
-- removal is respected without a separate exclusion table.
ALTER TABLE organizations
    ADD COLUMN domain_join boolean DEFAULT false NOT NULL,
    ADD COLUMN domain_join_group_id uuid,
    ADD CONSTRAINT organizations_domain_join_group FOREIGN KEY (domain_join_group_id, environment_id, id)
        REFERENCES groups(id, environment_id, organization_id) ON DELETE SET NULL (domain_join_group_id);
