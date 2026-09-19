-- Backfill the system IAM resource for every environment created before it
-- became a built-in resource. New environments get one automatically at
-- creation time (see mgmtpg.CreateEnvironment); this migration ensures
-- existing environments are not left without it.
INSERT INTO resources (id, environment_id, name, prefix, audience, permissions)
SELECT
  gen_random_uuid(),
  e.id,
  'IAM',
  'iam',
  'urn:iamkit:environment:' || e.id,
  ARRAY[
    'iam:users:read', 'iam:users:write',
    'iam:orgs:read', 'iam:orgs:write',
    'iam:members:read', 'iam:members:write',
    'iam:apps:read', 'iam:apps:write',
    'iam:resources:read', 'iam:resources:write',
    'iam:roles:read', 'iam:roles:write',
    'iam:grants:read', 'iam:grants:write',
    'iam:service-accounts:read', 'iam:service-accounts:write'
  ]
FROM environments e
WHERE NOT EXISTS (
  SELECT 1 FROM resources r WHERE r.environment_id = e.id AND r.prefix = 'iam'
);
