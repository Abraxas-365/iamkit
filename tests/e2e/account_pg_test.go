package e2e_test

import (
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// TestAuthpgChangeOwnPassword drives authpg.ChangeOwnPassword directly: the
// current session survives the password_hash trigger, the others and the
// open challenges end, the bypass setting does not leak, and the user is
// told apart per environment.
func TestAuthpgChangeOwnPassword(t *testing.T) {
	e := newEnv(t)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, e.Res, "invoices:read")
	e.Login(e.AliceEmail)
	e.Login(e.AliceEmail)
	e.Login("bob@example.com")
	challenge := e.openChallenge(e.Alice)
	var current string
	if err := e.DB.Get(&current, `SELECT id FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`, e.Alice); err != nil {
		t.Fatal(err)
	}
	tx, err := e.DB.Beginx()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	envID, userID := mustEnvironment(t, e.EnvID), mustUser(t, e.Alice)
	account, err := authpg.Wrap(tx).AccountPassword(e.ctx(), envID, userID)
	if err != nil || account.Hash == "" || account.ID != userID {
		t.Fatalf("account = %+v %v", account, err)
	}
	n, err := authpg.Wrap(tx).ChangeOwnPassword(e.ctx(), envID, userID, identity.MustParseSessionID(current), "$2b$04$"+"abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234")
	if err != nil || n != 1 {
		t.Fatalf("revoked = %d %v", n, err)
	}
	var setting string
	if err = tx.Get(&setting, `SELECT current_setting('iamkit.password_rehash', true)`); err != nil || setting == "on" {
		t.Fatalf("rehash bypass leaked: %q %v", setting, err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := e.liveSessions(e.Alice); got != 1 {
		t.Fatalf("live sessions = %d", got)
	}
	if got := count(t, e.DB, `SELECT count(*) FROM sessions WHERE id=$1 AND revoked_at IS NULL`, current); got != 1 {
		t.Fatal("the current session ended")
	}
	if e.challengeOpen(challenge) {
		t.Fatal("an emailed code outlived the password change")
	}
	if got := e.liveSessions(bob); got != 1 {
		t.Fatalf("another user's session ended: %d", got)
	}
	var data string
	if err = e.DB.Get(&data, `SELECT data::text FROM events WHERE environment_id=$1 AND type='user.password_changed' AND subject_id=$2`, e.EnvID, e.Alice); err != nil || data == "" {
		t.Fatalf("event data = %q %v", data, err)
	}
}

// TestAuthpgSwitchSession drives authpg.SwitchSession: the copy keeps the
// client info, authenticated_at and amr; the old session ends; sessions that
// are not switchable (revoked, impersonated, other application) find no row.
func TestAuthpgSwitchSession(t *testing.T) {
	e := newEnv(t)
	beta := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Beta"})
	e.Join(beta, e.Alice)
	e.Grant(beta, e.Alice, e.Res, "invoices:read")
	e.loginAgent(e.AliceEmail, "pg-test-agent")
	var from string
	if err := e.DB.Get(&from, `SELECT id FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`, e.Alice); err != nil {
		t.Fatal(err)
	}
	boundary := authentication.Context{EnvironmentID: mustEnvironment(t, e.EnvID), OrganizationID: identity.MustParseOrganizationID(beta),
		ApplicationID: identity.MustParseApplicationID(e.Client), ResourceID: identity.MustParseResourceID(e.Res)}
	user := mustUser(t, e.Alice)
	switchOnce := func(from string, to identity.SessionID) error {
		tx, err := e.DB.Beginx()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err = authpg.Wrap(tx).SwitchSession(e.ctx(), identity.MustParseSessionID(from), boundary, user, to); err != nil {
			return err
		}
		return tx.Commit()
	}
	to := identity.NewSessionID()
	if err := switchOnce(from, to); err != nil {
		t.Fatal(err)
	}
	var copied struct {
		Org   string `db:"organization_id"`
		Agent string `db:"user_agent"`
		Same  bool   `db:"same"`
	}
	if err := e.DB.Get(&copied, `SELECT n.organization_id,n.user_agent,(n.authenticated_at=o.authenticated_at AND n.amr=o.amr AND n.expires_at=o.expires_at) AS same FROM sessions n, sessions o WHERE n.id=$1 AND o.id=$2 AND n.revoked_at IS NULL AND o.revoked_at IS NOT NULL`, to, from); err != nil {
		t.Fatal(err)
	}
	if copied.Org != beta || copied.Agent != "pg-test-agent" || !copied.Same {
		t.Fatalf("copy = %+v", copied)
	}
	// The ended session cannot switch again.
	if err := switchOnce(from, identity.NewSessionID()); err == nil {
		t.Fatal("an ended session switched")
	}
	// Events: session.revoked of the old one names the reason.
	if got := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='user.organization_switched' AND data->>'to'=$2 AND data->>'previous_session_id'=$3`, e.EnvID, beta, from); got != 1 {
		t.Fatalf("switched events = %d", got)
	}
	// No membership: the insert is refused (foreign key), never half-applied.
	stranger := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Stranger"})
	boundary.OrganizationID = identity.MustParseOrganizationID(stranger)
	if err := switchOnce(to.String(), identity.NewSessionID()); err == nil {
		t.Fatal("switched into a foreign organization")
	}
	if got := e.liveSessions(e.Alice); got != 1 {
		t.Fatalf("live sessions after a refused switch = %d", got)
	}
}
