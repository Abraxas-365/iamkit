-- Emergency (break-glass) password access to the console. With
-- IAMKIT_OPERATOR_PASSWORD_LOGIN=break_glass (the default once operator SSO is
-- configured) only members granted it may sign in with a password; everyone
-- else uses single sign-on. Per membership: an owner decides for their own
-- workspace only. Ignored in the enabled and disabled modes.
ALTER TABLE workspace_members ADD COLUMN password_allowed boolean NOT NULL DEFAULT false;

-- Owners who already sign in with a password keep it as emergency access, so
-- turning SSO on never locks them out.
UPDATE workspace_members m SET password_allowed = true
  FROM operators o
  WHERE o.id = m.operator_id AND m.role = 'owner' AND m.active AND o.password_hash <> '';
