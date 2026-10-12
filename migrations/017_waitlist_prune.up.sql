-- Waitlist retention (waitlist_prune job): completed and rejected entries
-- are deleted once decided longer ago than IAMKIT_WAITLIST_RETENTION. The
-- partial index keeps the hourly scan off the rest of the table.
CREATE INDEX waitlist_entries_prune ON waitlist_entries USING btree ((COALESCE(decided_at, created_at))) WHERE (status = ANY (ARRAY['completed'::text, 'rejected'::text]));
