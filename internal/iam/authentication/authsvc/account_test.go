package authsvc

import (
	"context"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var (
	accountUser  = identity.MustParseUserID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	otherOrg     = identity.MustParseOrganizationID("bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	accountToken = func() authentication.Token {
		b := testBoundary()
		return authentication.Token{Access: identity.Access{EnvironmentID: b.EnvironmentID, OrganizationID: b.OrganizationID}, Purpose: authentication.PurposeApplication, Subject: accountUser,
			SessionID: identity.NewSessionID(), AuthTime: time.Now().Unix()}
	}
)

// accountTransaction adds the account queries to the shared fake.
type accountTransaction struct {
	*testTransaction
	hash       string
	session    authentication.Session
	email      string
	changed    []string
	switched   []identity.OrganizationID
	revoked    int
	resolveErr error
}

func (t *accountTransaction) AccountPassword(context.Context, identity.EnvironmentID, identity.UserID) (authentication.PasswordAccount, error) {
	return authentication.PasswordAccount{ID: accountUser, Email: "user@example.com", Hash: t.hash, Failures: t.failures, LockedUntil: t.lockedUntil, Changed: time.Now()}, t.lookup
}
func (t *accountTransaction) ChangeOwnPassword(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, _ identity.SessionID, hash string) (int, error) {
	t.changed = append(t.changed, hash)
	return t.revoked, nil
}
func (t *accountTransaction) Refresh(context.Context, authentication.Context, []byte) (authentication.Session, error) {
	return t.session, t.lookup
}
func (t *accountTransaction) Resolve(context.Context, authentication.Context, identity.UserID) (authentication.Access, error) {
	return authentication.Access{Audience: "api"}, t.resolveErr
}
func (t *accountTransaction) ActiveEmail(context.Context, identity.EnvironmentID, identity.UserID) (string, error) {
	return t.email, nil
}
func (t *accountTransaction) SwitchSession(_ context.Context, _ identity.SessionID, to authentication.Context, _ identity.UserID, _ identity.SessionID) error {
	t.switched = append(t.switched, to.OrganizationID)
	return nil
}

func newAccount(tx *accountTransaction, passwords authentication.Passwords) *Account {
	return New(accountRepository{tx}, passwords, testSecrets{}, nil).Accounts()
}

// accountRepository hands out the richer transaction.
type accountRepository struct{ tx *accountTransaction }

func (r accountRepository) Begin(context.Context) (authentication.Transaction, error) {
	return r.tx, nil
}

func accountErr(t *testing.T, err error, status int, code string) {
	t.Helper()
	var e *errx.Error
	if !errx.As(err, &e) || e.HTTPStatus != status || (code != "" && e.Code != code) {
		t.Fatalf("want %d %s, got %v", status, code, err)
	}
}

func TestChangePassword(t *testing.T) {
	good := authentication.PasswordChange{Current: "password", New: "a brand new password"}
	t.Run("changes the password and counts the ended sessions", func(t *testing.T) {
		tx := &accountTransaction{testTransaction: &testTransaction{}, hash: "hash", revoked: 2}
		out, err := newAccount(tx, newPasswords{}).ChangePassword(context.Background(), accountToken(), good)
		if err != nil || out.SessionsRevoked != 2 {
			t.Fatalf("out=%+v err=%v", out, err)
		}
		if len(tx.changed) != 1 || tx.changed[0] != "hash:a brand new password" || !tx.committed {
			t.Fatalf("changed=%v committed=%v", tx.changed, tx.committed)
		}
	})
	t.Run("stale sign-in", func(t *testing.T) {
		tx := &accountTransaction{testTransaction: &testTransaction{}, hash: "hash"}
		token := accountToken()
		token.AuthTime = time.Now().Add(-time.Hour).Unix()
		_, err := newAccount(tx, newPasswords{}).ChangePassword(context.Background(), token, good)
		accountErr(t, err, 403, "REAUTHENTICATION_REQUIRED")
		token.AuthTime = 0
		_, err = newAccount(tx, newPasswords{}).ChangePassword(context.Background(), token, good)
		accountErr(t, err, 403, "REAUTHENTICATION_REQUIRED")
		if len(tx.changed) != 0 {
			t.Fatal("changed with a stale token")
		}
	})
	t.Run("only people", func(t *testing.T) {
		tx := &accountTransaction{testTransaction: &testTransaction{}, hash: "hash"}
		for name, mutate := range map[string]func(*authentication.Token){
			"api key": func(k *authentication.Token) { k.APIKey = &authentication.APIKeyClaims{} },
			"machine": func(k *authentication.Token) {
				k.Purpose = authentication.PurposeMachine
				k.SessionID = identity.SessionID{}
			},
			"impersonated": func(k *authentication.Token) {
				k.ActorID = identity.MustParseOperatorID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
			},
		} {
			token := accountToken()
			mutate(&token)
			_, err := newAccount(tx, newPasswords{}).ChangePassword(context.Background(), token, good)
			t.Log(name)
			accountErr(t, err, 403, "FORBIDDEN")
		}
	})
	t.Run("no password", func(t *testing.T) {
		tx := &accountTransaction{testTransaction: &testTransaction{}}
		_, err := newAccount(tx, newPasswords{}).ChangePassword(context.Background(), accountToken(), good)
		accountErr(t, err, 422, "NO_PASSWORD")
	})
	t.Run("wrong current password counts as a failure", func(t *testing.T) {
		tx := &accountTransaction{testTransaction: &testTransaction{}, hash: "hash"}
		_, err := newAccount(tx, newPasswords{}).ChangePassword(context.Background(), accountToken(), authentication.PasswordChange{Current: "wrong", New: "a brand new password"})
		accountErr(t, err, 422, "INVALID_CURRENT_PASSWORD")
		if tx.failures != 1 || !tx.committed || len(tx.changed) != 0 {
			t.Fatalf("failures=%d committed=%v changed=%v", tx.failures, tx.committed, tx.changed)
		}
	})
	t.Run("locked account", func(t *testing.T) {
		until := time.Now().Add(time.Hour)
		tx := &accountTransaction{testTransaction: &testTransaction{lockedUntil: &until}, hash: "hash"}
		_, err := newAccount(tx, newPasswords{}).ChangePassword(context.Background(), accountToken(), good)
		accountErr(t, err, 422, "INVALID_CURRENT_PASSWORD")
	})
	t.Run("policy and breach check", func(t *testing.T) {
		policy := authentication.DefaultPasswordPolicy()
		policy.BreachCheck = true
		tx := &accountTransaction{testTransaction: &testTransaction{}, hash: "hash"}
		s := newAccount(tx, newPasswords{})
		s.Service = withPolicy(s.Service, policy, breaches{breached: true})
		_, err := s.ChangePassword(context.Background(), accountToken(), good)
		if code(err) != "PASSWORD_REJECTED" && rule(err) != authentication.RuleBreached {
			t.Fatalf("breached password accepted: %v", err)
		}
		_, err = s.ChangePassword(context.Background(), accountToken(), authentication.PasswordChange{Current: "password", New: "short"})
		if rule(err) != authentication.RuleLength {
			t.Fatalf("short password accepted: %v", err)
		}
		if len(tx.changed) != 0 {
			t.Fatal("rejected password stored")
		}
	})
}

func switchSession(amr ...string) authentication.Session {
	return authentication.Session{ID: identity.NewSessionID(), User: accountUser, Expires: time.Now().Add(time.Hour), AMR: amr, Authenticated: time.Now().Add(-time.Minute)}
}

func switchInput() authentication.Switch {
	return authentication.Switch{Boundary: testBoundary(), Token: "ik_refresh_test", Organization: otherOrg}
}

func TestSwitchOrganization(t *testing.T) {
	t.Run("opens the session in the target", func(t *testing.T) {
		tx := &accountTransaction{testTransaction: &testTransaction{}, session: switchSession("pwd"), email: "user@example.com"}
		out, err := newAccount(tx, testPasswords{}).SwitchOrganization(context.Background(), switchInput())
		if err != nil {
			t.Fatal(err)
		}
		if out.Context.OrganizationID != otherOrg || out.Session.IsZero() || out.Session == tx.session.ID || out.Refresh == "" || len(out.AMR) != 1 || !out.Authenticated.Equal(tx.session.Authenticated) {
			t.Fatalf("issued %+v", out)
		}
		if len(tx.switched) != 1 || tx.switched[0] != otherOrg || !tx.committed {
			t.Fatalf("switched=%v committed=%v", tx.switched, tx.committed)
		}
	})
	t.Run("no access is forbidden", func(t *testing.T) {
		tx := &accountTransaction{testTransaction: &testTransaction{}, session: switchSession("pwd"), resolveErr: errx.Unauthorized("no")}
		_, err := newAccount(tx, testPasswords{}).SwitchOrganization(context.Background(), switchInput())
		accountErr(t, err, 403, "FORBIDDEN")
		if len(tx.switched) != 0 || tx.committed {
			t.Fatal("switched without access")
		}
	})
	t.Run("impersonated and OAuth sessions", func(t *testing.T) {
		for _, mutate := range []func(*authentication.Session){func(s *authentication.Session) { s.Impersonated = true }, func(s *authentication.Session) { s.OAuthClient = true }} {
			session := switchSession("pwd")
			mutate(&session)
			tx := &accountTransaction{testTransaction: &testTransaction{}, session: session}
			_, err := newAccount(tx, testPasswords{}).SwitchOrganization(context.Background(), switchInput())
			accountErr(t, err, 403, "FORBIDDEN")
		}
	})
	t.Run("method not allowed", func(t *testing.T) {
		tx := &accountTransaction{testTransaction: &testTransaction{methods: &authentication.Methods{EmailCode: true}}, session: switchSession("pwd")}
		_, err := newAccount(tx, testPasswords{}).SwitchOrganization(context.Background(), switchInput())
		accountErr(t, err, 403, "REAUTHENTICATION_REQUIRED")
		var e *errx.Error
		errx.As(err, &e)
		if e.Details["reason"] != "method" || e.Details["organization_id"] != otherOrg.String() || !e.Public {
			t.Fatalf("details %v public=%v", e.Details, e.Public)
		}
	})
	t.Run("sso enforced", func(t *testing.T) {
		tx := &accountTransaction{testTransaction: &testTransaction{sso: true}, session: switchSession("pwd"), email: "user@example.com"}
		_, err := newAccount(tx, testPasswords{}).SwitchOrganization(context.Background(), switchInput())
		accountErr(t, err, 403, "REAUTHENTICATION_REQUIRED")
		var e *errx.Error
		errx.As(err, &e)
		if e.Details["reason"] != "sso" {
			t.Fatalf("details %v", e.Details)
		}
	})
	t.Run("second factor", func(t *testing.T) {
		for amr, wantErr := range map[string]bool{"pwd": true, "hwk": false} {
			tx := &accountTransaction{testTransaction: &testTransaction{}, session: switchSession(amr), email: "user@example.com"}
			if amr == "hwk" {
				tx.session.AMR = []string{"hwk", "user", "mfa"}
			}
			s := newAccount(tx, testPasswords{})
			s.SetSecondFactor(needsSecondFactor{})
			_, err := s.SwitchOrganization(context.Background(), switchInput())
			if wantErr {
				accountErr(t, err, 403, "REAUTHENTICATION_REQUIRED")
				var e *errx.Error
				errx.As(err, &e)
				if e.Details["reason"] != "mfa" {
					t.Fatalf("details %v", e.Details)
				}
			} else if err != nil {
				t.Fatalf("mfa session refused: %v", err)
			}
		}
	})
	t.Run("replay revokes the session", func(t *testing.T) {
		session := switchSession("pwd")
		session.Used = true
		tx := &accountTransaction{testTransaction: &testTransaction{}, session: session}
		_, err := newAccount(tx, testPasswords{}).SwitchOrganization(context.Background(), switchInput())
		accountErr(t, err, 401, "")
		if len(tx.switched) != 0 {
			t.Fatal("switched on a replayed token")
		}
	})
	t.Run("same organization or bad token", func(t *testing.T) {
		in := switchInput()
		in.Organization = in.Boundary.OrganizationID
		if in.Validate() == nil {
			t.Fatal("same organization validates")
		}
		in = switchInput()
		in.Token = "nope"
		tx := &accountTransaction{testTransaction: &testTransaction{}, session: switchSession("pwd")}
		_, err := newAccount(tx, testPasswords{}).SwitchOrganization(context.Background(), in)
		accountErr(t, err, 401, "")
	})
}

// needsSecondFactor asks every session for a second factor.
type needsSecondFactor struct{ authentication.SecondFactor }

func (needsSecondFactor) Requirement(context.Context, authentication.Context, identity.UserID, bool, []string) (authentication.Requirement, error) {
	return authentication.Requirement{Needed: true, Enroll: true}, nil
}

// samePasswords accepts one long current password, to test the reuse rule.
type samePasswords struct{ newPasswords }

func (samePasswords) Compare(_, password string) (bool, bool) {
	return password == "current password", false
}

func TestChangePasswordRefusesTheSamePassword(t *testing.T) {
	tx := &accountTransaction{testTransaction: &testTransaction{}, hash: "hash"}
	_, err := newAccount(tx, samePasswords{}).ChangePassword(context.Background(), accountToken(), authentication.PasswordChange{Current: "current password", New: "current password"})
	if rule(err) != authentication.RuleReused || len(tx.changed) != 0 {
		t.Fatalf("same password accepted: %v", err)
	}
}
