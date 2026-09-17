ALTER TABLE users ADD COLUMN otp_enabled boolean NOT NULL DEFAULT false;
CREATE FUNCTION invalidate_otp_challenges() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE identity_challenges SET consumed_at=now() WHERE user_id=NEW.id AND environment_id=NEW.environment_id AND purpose='login' AND consumed_at IS NULL;
 RETURN NEW;
END $$;
CREATE TRIGGER otp_policy_changed AFTER UPDATE OF otp_enabled ON users FOR EACH ROW WHEN (OLD.otp_enabled IS DISTINCT FROM NEW.otp_enabled) EXECUTE FUNCTION invalidate_otp_challenges();
