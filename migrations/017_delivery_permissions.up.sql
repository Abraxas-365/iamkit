-- Add delivery permissions to the system IAM resource for every environment.
UPDATE resources
SET permissions = permissions || ARRAY['iam:delivery:read', 'iam:delivery:write']
WHERE prefix = 'iam'
  AND NOT permissions @> ARRAY['iam:delivery:read'];
