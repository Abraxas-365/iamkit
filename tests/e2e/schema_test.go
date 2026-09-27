package e2e_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/Abraxas-365/iamkit/migrations"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

// SQLSTATE classes the schema is expected to raise.
const (
	okSQL      = ""
	uniqueSQL  = "23505"
	foreignSQL = "23503"
	checkSQL   = "23514"
)

// schemaFixture is the minimum set of rows the constraint checks hang off:
// two environments (A and B), each with a user, an organization and a
// membership, plus an application/resource pair in A.
type schemaFixture struct {
	envA, envB   string
	userA, userB string
	orgA, orgB   string
	orgA2        string
	app, res     string
}

func newSchemaFixture(t *testing.T, db *sqlx.DB) schemaFixture {
	t.Helper()
	f := schemaFixture{
		envA: uuid.NewString(), envB: uuid.NewString(),
		userA: uuid.NewString(), userB: uuid.NewString(),
		orgA: uuid.NewString(), orgB: uuid.NewString(), orgA2: uuid.NewString(),
		app: uuid.NewString(), res: uuid.NewString(),
	}
	workspace, project := uuid.NewString(), uuid.NewString()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO workspaces(id,name) VALUES($1,'W')`, []any{workspace}},
		{`INSERT INTO projects(id,workspace_id,name) VALUES($1,$2,'P')`, []any{project, workspace}},
		{`INSERT INTO environments(id,project_id,name) VALUES($1,$3,'A'),($2,$3,'B')`, []any{f.envA, f.envB, project}},
		{`INSERT INTO users(id,environment_id,email,name,password_hash) VALUES($1,$2,'a@example.com','A','x'),($3,$4,'b@example.com','B','x')`, []any{f.userA, f.envA, f.userB, f.envB}},
		{`INSERT INTO organizations(id,environment_id,name) VALUES($1,$2,'OA'),($3,$2,'OA2'),($4,$5,'OB')`, []any{f.orgA, f.envA, f.orgA2, f.orgB, f.envB}},
		{`INSERT INTO memberships(environment_id,organization_id,user_id) VALUES($1,$2,$3),($4,$5,$6)`, []any{f.envA, f.orgA, f.userA, f.envB, f.orgB, f.userB}},
		{`INSERT INTO applications(id,environment_id,name) VALUES($1,$2,'App')`, []any{f.app, f.envA}},
		{`INSERT INTO resources(id,environment_id,name,prefix,audience) VALUES($1,$2,'API','api','https://api')`, []any{f.res, f.envA}},
		{`INSERT INTO application_resources(environment_id,application_id,resource_id) VALUES($1,$2,$3)`, []any{f.envA, f.app, f.res}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("fixture %q: %v", q.sql, err)
		}
	}
	return f
}

// expectSQL runs one statement and checks it fails with SQLSTATE want (or
// succeeds when want is okSQL).
func expectSQL(t *testing.T, db *sqlx.DB, name, want, query string, args ...any) {
	t.Helper()
	_, err := db.Exec(query, args...)
	var got string
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		got = string(pqErr.Code)
	} else if err != nil {
		t.Fatalf("%s: unexpected error %v", name, err)
	}
	if got != want {
		t.Fatalf("%s: SQLSTATE %q, want %q (err %v)", name, got, want, err)
	}
}

func count(t *testing.T, db *sqlx.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.Get(&n, query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// TestSchemaMigrations checks every migration is recorded once and that a
// replay is a no-op.
func TestSchemaMigrations(t *testing.T) {
	db := freshDB(t)
	entries, err := filepath.Glob("../../migrations/*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, `SELECT count(*) FROM iamkit_migrations`); n != len(entries) || n < 8 {
		t.Fatalf("recorded %d migrations, embedded %d", n, len(entries))
	}
	if err := migrations.Apply(t.Context(), db); err != nil {
		t.Fatalf("replay: %v", err)
	}
}

// TestSchemaGroups covers 003: names, cross-environment isolation,
// membership-backed group members and cascades.
func TestSchemaGroups(t *testing.T) {
	db := freshDB(t)
	f := newSchemaFixture(t, db)
	group := uuid.NewString()
	expectSQL(t, db, "blank name", checkSQL, `INSERT INTO groups(id,environment_id,organization_id,name) VALUES($1,$2,$3,'  ')`, uuid.NewString(), f.envA, f.orgA)
	expectSQL(t, db, "group", okSQL, `INSERT INTO groups(id,environment_id,organization_id,name) VALUES($1,$2,$3,'Eng')`, group, f.envA, f.orgA)
	expectSQL(t, db, "name case-insensitive unique", uniqueSQL, `INSERT INTO groups(id,environment_id,organization_id,name) VALUES($1,$2,$3,'ENG')`, uuid.NewString(), f.envA, f.orgA)
	expectSQL(t, db, "same name in another org", okSQL, `INSERT INTO groups(id,environment_id,organization_id,name) VALUES($1,$2,$3,'Eng')`, uuid.NewString(), f.envA, f.orgA2)
	expectSQL(t, db, "org of another environment", foreignSQL, `INSERT INTO groups(id,environment_id,organization_id,name) VALUES($1,$2,$3,'X')`, uuid.NewString(), f.envA, f.orgB)
	expectSQL(t, db, "non-member", foreignSQL, `INSERT INTO group_members(group_id,environment_id,organization_id,user_id) VALUES($1,$2,$3,$4)`, group, f.envA, f.orgA, f.userB)
	expectSQL(t, db, "member", okSQL, `INSERT INTO group_members(group_id,environment_id,organization_id,user_id) VALUES($1,$2,$3,$4)`, group, f.envA, f.orgA, f.userA)
	expectSQL(t, db, "leave organization", okSQL, `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.orgA, f.userA)
	if n := count(t, db, `SELECT count(*) FROM group_members WHERE group_id=$1`, group); n != 0 {
		t.Fatalf("group members survived membership removal: %d", n)
	}
}

// TestSchemaDomains covers 004: normalized, environment-unique domains and a
// consistent verification state.
func TestSchemaDomains(t *testing.T) {
	db := freshDB(t)
	f := newSchemaFixture(t, db)
	insert := `INSERT INTO organization_domains(id,environment_id,organization_id,domain,verification_token,verified_at,verification_method) VALUES($1,$2,$3,$4,'t',$5,$6)`
	expectSQL(t, db, "uppercase", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "Acme.com", nil, nil)
	expectSQL(t, db, "too short", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "a.", nil, nil)
	expectSQL(t, db, "verified without method", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "acme.com", "2026-01-01", nil)
	expectSQL(t, db, "unknown method", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "acme.com", "2026-01-01", "email")
	expectSQL(t, db, "domain", okSQL, insert, uuid.NewString(), f.envA, f.orgA, "acme.com", nil, nil)
	expectSQL(t, db, "claimed by another org", uniqueSQL, insert, uuid.NewString(), f.envA, f.orgA2, "acme.com", "2026-01-01", "manual")
	expectSQL(t, db, "same domain in another environment", okSQL, insert, uuid.NewString(), f.envB, f.orgB, "acme.com", nil, nil)
	expectSQL(t, db, "adopt scope", checkSQL, `INSERT INTO provisioning_connections(id,environment_id,organization_id,name,adopt_scope) VALUES($1,$2,$3,'dir','all')`, uuid.NewString(), f.envA, f.orgA)
}

// TestSchemaOrgSSO covers 005: one secret source, organization-only
// features, one enforced connection per organization, link origin.
func TestSchemaOrgSSO(t *testing.T) {
	db := freshDB(t)
	f := newSchemaFixture(t, db)
	insert := `INSERT INTO federation_connections(id,environment_id,organization_id,name,issuer,client_id,secret_env,secret_sealed,enforcement) VALUES($1,$2,$3,'c',$4,'client',$5,$6,$7)`
	expectSQL(t, db, "no secret", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "https://a", nil, nil, "optional")
	expectSQL(t, db, "two secrets", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "https://a", "ENV", "v1:x", "optional")
	expectSQL(t, db, "environment connection enforced", checkSQL, insert, uuid.NewString(), f.envA, nil, "https://a", "ENV", nil, "enforced")
	expectSQL(t, db, "bad enforcement", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "https://a", "ENV", nil, "strict")
	enforced := uuid.NewString()
	expectSQL(t, db, "enforced", okSQL, insert, enforced, f.envA, f.orgA, "https://a", nil, "v1:x", "enforced")
	expectSQL(t, db, "second enforced", uniqueSQL, insert, uuid.NewString(), f.envA, f.orgA, "https://b", nil, "v1:x", "enforced")
	expectSQL(t, db, "same client same org", uniqueSQL, insert, uuid.NewString(), f.envA, f.orgA, "https://a", nil, "v1:x", "optional")
	expectSQL(t, db, "same client other org", okSQL, insert, uuid.NewString(), f.envA, f.orgA2, "https://a", nil, "v1:x", "enforced")
	expectSQL(t, db, "org of another environment", foreignSQL, insert, uuid.NewString(), f.envA, f.orgB, "https://c", "ENV", nil, "optional")
	expectSQL(t, db, "bad origin", checkSQL, `INSERT INTO external_identities(connection_id,environment_id,subject,user_id,origin) VALUES($1,$2,'s',$3,'scim')`, enforced, f.envA, f.userA)
	expectSQL(t, db, "sso bypass default", okSQL, `UPDATE memberships SET sso_bypass=sso_bypass WHERE sso_bypass=false AND organization_id=$1`, f.orgA)
}

// TestSchemaInvitations covers 006: one open invitation per email, a
// coherent accept/revoke state, normalized email.
func TestSchemaInvitations(t *testing.T) {
	db := freshDB(t)
	f := newSchemaFixture(t, db)
	insert := `INSERT INTO invitations(id,environment_id,organization_id,email,inviter,token_hash,expires_at) VALUES($1,$2,$3,$4,'op',$5,now()+interval '1 day')`
	first := uuid.NewString()
	expectSQL(t, db, "uppercase email", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "Bob@example.com", []byte("h0"))
	expectSQL(t, db, "invitation", okSQL, insert, first, f.envA, f.orgA, "bob@example.com", []byte("h1"))
	expectSQL(t, db, "second open invitation", uniqueSQL, insert, uuid.NewString(), f.envA, f.orgA, "bob@example.com", []byte("h2"))
	expectSQL(t, db, "token reuse", uniqueSQL, insert, uuid.NewString(), f.envA, f.orgA2, "carol@example.com", []byte("h1"))
	expectSQL(t, db, "accepted without user", checkSQL, `UPDATE invitations SET accepted_at=now() WHERE id=$1`, first)
	expectSQL(t, db, "revoke", okSQL, `UPDATE invitations SET revoked_at=now() WHERE id=$1`, first)
	expectSQL(t, db, "accepted and revoked", checkSQL, `UPDATE invitations SET accepted_at=now(),accepted_user_id=$2 WHERE id=$1`, first, f.userA)
	expectSQL(t, db, "new invitation after revoke", okSQL, insert, uuid.NewString(), f.envA, f.orgA, "bob@example.com", []byte("h3"))
	expectSQL(t, db, "org of another environment", foreignSQL, insert, uuid.NewString(), f.envA, f.orgB, "dan@example.com", []byte("h4"))
}

// TestSchemaHostedLogin covers 007: login method, branding colour, hosted
// federation states and cleanup with the user.
func TestSchemaHostedLogin(t *testing.T) {
	db := freshDB(t)
	f := newSchemaFixture(t, db)
	insert := `INSERT INTO hosted_logins(ticket_hash,environment_id,user_id,email,method,organization_id,chosen_organization_id,expires_at) VALUES($1,$2,$3,'a@example.com',$4,$5,$6,now()+interval '5 minutes')`
	expectSQL(t, db, "bad method", checkSQL, insert, []byte("t0"), f.envA, f.userA, "magic", nil, nil)
	expectSQL(t, db, "user of another environment", foreignSQL, insert, []byte("t1"), f.envA, f.userB, "password", nil, nil)
	expectSQL(t, db, "chosen org of another environment", foreignSQL, insert, []byte("t2"), f.envA, f.userA, "password", nil, f.orgB)
	expectSQL(t, db, "hosted login", okSQL, insert, []byte("t3"), f.envA, f.userA, "password", nil, f.orgA)
	if n := count(t, db, `SELECT count(*) FROM hosted_logins WHERE mfa_attempts=0 AND amr='{}'`); n != 1 {
		t.Fatalf("hosted login defaults: %d", n)
	}
	expectSQL(t, db, "bad accent", checkSQL, `INSERT INTO login_settings(environment_id,accent_color) VALUES($1,'red')`, f.envA)
	expectSQL(t, db, "uppercase accent", checkSQL, `INSERT INTO login_settings(environment_id,accent_color) VALUES($1,'#FF0000')`, f.envA)
	expectSQL(t, db, "accent", okSQL, `INSERT INTO login_settings(environment_id,accent_color) VALUES($1,'#ff0000')`, f.envA)
	expectSQL(t, db, "hosted client default", okSQL, `INSERT INTO oauth_clients(id,environment_id,application_id,resource_id,redirect_uris,public) VALUES($1,$2,$3,$4,'{}',true)`, uuid.NewString(), f.envA, f.app, f.res)
	if n := count(t, db, `SELECT count(*) FROM oauth_clients WHERE hosted_login`); n != 0 {
		t.Fatalf("clients hosted by default: %d", n)
	}
	conn := uuid.NewString()
	expectSQL(t, db, "connection", okSQL, `INSERT INTO federation_connections(id,environment_id,name,issuer,client_id,secret_env) VALUES($1,$2,'g','https://g','c','ENV')`, conn, f.envA)
	state := `INSERT INTO federation_states(secret_hash,connection_id,environment_id,organization_id,application_id,resource_id,binding_hash,nonce,verifier,expires_at,continuation) VALUES($1,$2,$3,$4,$5,$6,'b','n','v',now()+interval '5 minutes',$7)`
	expectSQL(t, db, "state without org or continuation", checkSQL, state, []byte("s1"), conn, f.envA, nil, f.app, f.res, nil)
	expectSQL(t, db, "hosted state", okSQL, state, []byte("s2"), conn, f.envA, nil, f.app, f.res, "ticket")
	expectSQL(t, db, "leave organization", okSQL, `DELETE FROM memberships WHERE user_id=$1`, f.userA)
	expectSQL(t, db, "delete user", okSQL, `DELETE FROM users WHERE id=$1`, f.userA)
	if n := count(t, db, `SELECT count(*) FROM hosted_logins`); n != 0 {
		t.Fatalf("hosted logins survived user deletion: %d", n)
	}
}

// TestSchemaMFA covers 008: one TOTP factor per user, environment
// isolation, single recovery code rows, policy/amr defaults, and that
// deleting a user erases every factor, recovery code and pending login.
func TestSchemaMFA(t *testing.T) {
	db := freshDB(t)
	f := newSchemaFixture(t, db)
	factor := `INSERT INTO user_factors(id,environment_id,user_id,kind,secret_sealed) VALUES($1,$2,$3,$4,'v1:x')`
	expectSQL(t, db, "unknown kind", checkSQL, factor, uuid.NewString(), f.envA, f.userA, "sms")
	expectSQL(t, db, "user of another environment", foreignSQL, factor, uuid.NewString(), f.envA, f.userB, "totp")
	expectSQL(t, db, "factor", okSQL, factor, uuid.NewString(), f.envA, f.userA, "totp")
	expectSQL(t, db, "second totp", uniqueSQL, factor, uuid.NewString(), f.envA, f.userA, "totp")
	expectSQL(t, db, "secret required", "23502", `INSERT INTO user_factors(id,environment_id,user_id,kind,secret_sealed) VALUES($1,$2,$3,'totp',NULL)`, uuid.NewString(), f.envB, f.userB)
	if n := count(t, db, `SELECT count(*) FROM user_factors WHERE failed_attempts=0 AND locked_until IS NULL AND last_step=0 AND confirmed_at IS NULL`); n != 1 {
		t.Fatalf("factor defaults: %d", n)
	}

	code := `INSERT INTO recovery_codes(environment_id,user_id,code_hash) VALUES($1,$2,$3)`
	expectSQL(t, db, "recovery code", okSQL, code, f.envA, f.userA, []byte("c1"))
	expectSQL(t, db, "duplicate recovery code", uniqueSQL, code, f.envA, f.userA, []byte("c1"))
	expectSQL(t, db, "recovery code of another environment", foreignSQL, code, f.envA, f.userB, []byte("c2"))

	login := `INSERT INTO mfa_logins(token_hash,environment_id,organization_id,application_id,resource_id,user_id,amr,expires_at) VALUES($1,$2,$3,$4,$5,$6,'{pwd}',now()+interval '5 minutes')`
	expectSQL(t, db, "pending login", okSQL, login, []byte("p1"), f.envA, f.orgA, f.app, f.res, f.userA)
	expectSQL(t, db, "pending login token reuse", uniqueSQL, login, []byte("p1"), f.envA, f.orgA, f.app, f.res, f.userA)
	expectSQL(t, db, "pending login org of another environment", foreignSQL, login, []byte("p2"), f.envA, f.orgB, f.app, f.res, f.userA)
	if n := count(t, db, `SELECT count(*) FROM mfa_logins WHERE attempts=0 AND NOT enroll`); n != 1 {
		t.Fatalf("pending login defaults: %d", n)
	}

	if n := count(t, db, `SELECT count(*) FROM organizations WHERE mfa_required OR mfa_for_federated`); n != 0 {
		t.Fatalf("organizations require MFA by default: %d", n)
	}
	for _, index := range []string{"mfa_logins_expires", "mfa_logins_user"} {
		if n := count(t, db, `SELECT count(*) FROM pg_indexes WHERE indexname=$1`, index); n != 1 {
			t.Fatalf("missing index %s", index)
		}
	}
	if n := count(t, db, `SELECT count(*) FROM information_schema.columns WHERE table_name='sessions' AND column_name='amr' AND is_nullable='NO' AND column_default LIKE '''{}''%'`); n != 1 {
		t.Fatal("sessions.amr must default to an empty array")
	}

	expectSQL(t, db, "leave organization", okSQL, `DELETE FROM memberships WHERE user_id=$1`, f.userA)
	expectSQL(t, db, "delete user", okSQL, `DELETE FROM users WHERE id=$1`, f.userA)
	if n := count(t, db, `SELECT (SELECT count(*) FROM user_factors)+(SELECT count(*) FROM recovery_codes)+(SELECT count(*) FROM mfa_logins)`); n != 0 {
		t.Fatalf("MFA rows survived user deletion: %d", n)
	}
}

// TestSchemaSocialLogin covers 011: known providers, sign-up bound to an
// organization of the environment, no sign-up or linking on organization
// connections, the new link origins, and per-client sign-in options.
func TestSchemaSocialLogin(t *testing.T) {
	db := freshDB(t)
	f := newSchemaFixture(t, db)
	insert := `INSERT INTO federation_connections(id,environment_id,organization_id,name,issuer,client_id,secret_sealed,provider,signup,link_email,signup_organization_id,signup_group_id) VALUES($1,$2,$3,'c',$4,'client','v1:x',$5,$6,$7,$8,$9)`
	group, other := uuid.NewString(), uuid.NewString()
	expectSQL(t, db, "group", okSQL, `INSERT INTO groups(id,environment_id,organization_id,name) VALUES($1,$2,$3,'G'),($4,$2,$5,'H')`, group, f.envA, f.orgA, other, f.orgA2)
	expectSQL(t, db, "unknown provider", checkSQL, insert, uuid.NewString(), f.envA, nil, "https://a", "facebook", false, false, nil, nil)
	expectSQL(t, db, "signup without organization", checkSQL, insert, uuid.NewString(), f.envA, nil, "https://a", "google", true, false, nil, nil)
	expectSQL(t, db, "organization without signup", checkSQL, insert, uuid.NewString(), f.envA, nil, "https://a", "google", false, false, f.orgA, nil)
	expectSQL(t, db, "signup on organization connection", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "https://a", "oidc", true, false, f.orgA, nil)
	expectSQL(t, db, "link on organization connection", checkSQL, insert, uuid.NewString(), f.envA, f.orgA, "https://a", "oidc", false, true, nil, nil)
	expectSQL(t, db, "signup organization of another environment", foreignSQL, insert, uuid.NewString(), f.envA, nil, "https://a", "google", true, false, f.orgB, nil)
	expectSQL(t, db, "group of another organization", foreignSQL, insert, uuid.NewString(), f.envA, nil, "https://a", "google", true, false, f.orgA, other)
	social := uuid.NewString()
	expectSQL(t, db, "social", okSQL, insert, social, f.envA, nil, "https://accounts.google.com", "google", true, true, f.orgA, group)
	expectSQL(t, db, "delete signup group", okSQL, `DELETE FROM groups WHERE id=$1`, group)
	if n := count(t, db, `SELECT count(*) FROM federation_connections WHERE id=$1 AND signup_group_id IS NULL AND signup`, social); n != 1 {
		t.Fatal("deleting the sign-up group must only clear it")
	}
	expectSQL(t, db, "second user", okSQL, `INSERT INTO users(id,environment_id,email,name,password_hash) VALUES($1,$2,'c@example.com','C','')`, other, f.envA)
	for user, origin := range map[string]string{f.userA: "email", other: "signup"} {
		expectSQL(t, db, "origin "+origin, okSQL, `INSERT INTO external_identities(connection_id,environment_id,subject,user_id,origin) VALUES($1,$2,$3,$4,$5)`, social, f.envA, origin, user, origin)
	}

	client := uuid.NewString()
	expectSQL(t, db, "client", okSQL, `INSERT INTO oauth_clients(id,environment_id,application_id,resource_id,redirect_uris,public) VALUES($1,$2,$3,$4,'{}',true)`, client, f.envA, f.app, f.res)
	signIn := `INSERT INTO client_sign_in(client_id,environment_id,password,email_code,organization_sso,all_connections,connections) VALUES($1,$2,true,false,false,false,$3::uuid[])`
	expectSQL(t, db, "client of another environment", foreignSQL, signIn, client, f.envB, "{}")
	expectSQL(t, db, "sign-in", okSQL, signIn, client, f.envA, "{"+social+"}")
	expectSQL(t, db, "one per client", uniqueSQL, signIn, client, f.envA, "{}")
	expectSQL(t, db, "delete client", okSQL, `DELETE FROM oauth_clients WHERE id=$1`, client)
	if n := count(t, db, `SELECT count(*) FROM client_sign_in WHERE client_id=$1`, client); n != 0 {
		t.Fatal("sign-in options survived their client")
	}

	// A consumed hosted state of an environment connection drops its
	// continuation.
	state := `INSERT INTO federation_states(secret_hash,connection_id,environment_id,organization_id,application_id,resource_id,binding_hash,nonce,verifier,continuation,expires_at,consumed_at) VALUES($1,$2,$3,NULL,$4,$5,'b','n','v',$6,now(),$7)`
	expectSQL(t, db, "state without organization or continuation", checkSQL, state, []byte("s1"), social, f.envA, f.app, f.res, nil, nil)
	expectSQL(t, db, "consumed state", okSQL, state, []byte("s2"), social, f.envA, f.app, f.res, nil, "2026-01-01")
}
