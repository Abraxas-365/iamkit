-- iam:users:import (authorization.PermUsersImport) joins the IAM resource's
-- catalog. New environments get it from authorization.IAMResourcePermissions;
-- this adds it to the IAM resource of every existing environment. No role or
-- service account gains it: on /api/v1 it gates POST /users/import and
-- password_hash / email_verified on POST /users, values the caller asserts.
UPDATE resources
   SET permissions = array_append(permissions, 'iam:users:import')
 WHERE prefix = 'iam'
   AND NOT ('iam:users:import' = ANY (permissions));
