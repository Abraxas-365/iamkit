ALTER TABLE sessions ADD COLUMN actor_id uuid REFERENCES operators(id);
ALTER TABLE sessions ADD COLUMN impersonation_reason text;
ALTER TABLE sessions ADD CONSTRAINT impersonation_attribution CHECK((actor_id IS NULL AND impersonation_reason IS NULL) OR (actor_id IS NOT NULL AND length(trim(impersonation_reason))>=10));
