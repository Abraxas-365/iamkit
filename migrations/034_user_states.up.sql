-- User states. `active` stays the sign-in gate; the state shown to
-- operators (suspended, locked, inactive, initial, active) is derived from
-- it, the lockout, memberships, credentials and the last sign-in.
--
-- last_signed_in_at is set whenever a session is created for the user
-- through a sign-in (not impersonation or token exchange).
ALTER TABLE users ADD COLUMN last_signed_in_at timestamptz;

-- Existing users who already signed in are not "initial".
UPDATE users u SET last_signed_in_at = s.last
  FROM (SELECT environment_id, user_id, max(authenticated_at) AS last
          FROM sessions
         WHERE actor_id IS NULL AND actor_account_id IS NULL AND parent_session_id IS NULL
         GROUP BY environment_id, user_id) s
 WHERE s.environment_id = u.environment_id AND s.user_id = u.id;
