package invsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type fakeTx struct {
	invitation.Transaction
	target    invitation.Target
	member    bool
	refs      invitation.References
	joined    *invitation.Joining
	created   bool
	committed bool
}

func (t *fakeTx) Commit() error   { t.committed = true; return nil }
func (t *fakeTx) Rollback() error { return nil }
func (t *fakeTx) Organization(context.Context, invitation.Boundary) (invitation.Organization, error) {
	return invitation.Organization{Name: "Acme", Active: true}, nil
}
func (t *fakeTx) ActiveMember(context.Context, invitation.Boundary, string) (bool, error) {
	return t.member, nil
}
func (t *fakeTx) References(context.Context, invitation.Boundary, []identity.RoleID, []identity.GroupID) (invitation.References, error) {
	return t.refs, nil
}
func (t *fakeTx) ExpirePending(context.Context, invitation.Boundary, string) error { return nil }
func (t *fakeTx) Create(context.Context, invitation.Boundary, invitation.Mutation, invitation.Invitation, []byte) error {
	t.created = true
	return nil
}
func (t *fakeTx) LockTarget(context.Context, []byte) (invitation.Target, error) { return t.target, nil }
func (t *fakeTx) Join(_ context.Context, j invitation.Joining) error            { t.joined = &j; return nil }

type fakeRepo struct {
	invitation.Repository
	tx *fakeTx
}

func (r fakeRepo) Begin(context.Context) (invitation.Transaction, error) { return r.tx, nil }
func (r fakeRepo) Find(context.Context, invitation.Boundary, identity.InvitationID) (invitation.Invitation, error) {
	return invitation.Invitation{Email: "bob@example.com", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (r fakeRepo) InviterName(context.Context, string) (string, error) { return "owner", nil }
func (r fakeRepo) List(context.Context, invitation.Boundary, invitation.Filter, query.Pagination) (query.Paginated[invitation.Invitation], error) {
	return query.Paginated[invitation.Invitation]{}, nil
}

type fakeSecrets struct{}

func (fakeSecrets) Generate(p string) (string, []byte, error) { return p + "raw", []byte("hash"), nil }
func (fakeSecrets) Hash(string) []byte                        { return []byte("hash") }

type fakePasswords struct{}

func (fakePasswords) Hash(p string) (string, error) { return "hashed:" + p, nil }

type fakeMailer struct{ err error }

func (m fakeMailer) Send(context.Context, identity.EnvironmentID, invitation.Mail) error {
	return m.err
}
func (fakeMailer) Link(context.Context, identity.EnvironmentID, string) (string, error) {
	return "https://app.example/join?token=x", nil
}

func kind(err error) errx.Type {
	var e *errx.Error
	if errx.As(err, &e) {
		return e.Type
	}
	return ""
}

func pending() invitation.Invitation {
	return invitation.Invitation{ID: identity.NewInvitationID(), Email: "bob@example.com", ExpiresAt: time.Now().Add(time.Hour)}
}

func TestAcceptPasswordRules(t *testing.T) {
	token := invitation.TokenPrefix + "raw"
	existing := invitation.Account{ID: identity.NewUserID(), Active: true, HasPassword: true}
	cases := []struct {
		name     string
		target   invitation.Target
		password string
		want     errx.Type
	}{
		{"new needs password", invitation.Target{}, "", errx.TypeValidation},
		{"new with password", invitation.Target{}, "a long enough password", ""},
		{"sso no password", invitation.Target{SSORequired: true}, "", ""},
		{"sso rejects password", invitation.Target{SSORequired: true}, "a long enough password", errx.TypeValidation},
		{"existing keeps password", invitation.Target{Account: existing}, "a long enough password", errx.TypeValidation},
		{"existing joins", invitation.Target{Account: existing}, "", ""},
		{"inactive user", invitation.Target{Account: invitation.Account{ID: existing.ID}}, "", errx.TypeBusiness},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.target.Invitation, c.target.OrgActive = pending(), true
			tx := &fakeTx{target: c.target}
			_, err := New(fakeRepo{tx: tx}, fakeSecrets{}, fakePasswords{}, nil, nil).Accept(context.Background(), invitation.Acceptance{Token: token, Password: c.password})
			if kind(err) != c.want {
				t.Fatalf("got %v want %s", err, c.want)
			}
			if c.want == "" {
				if tx.joined == nil || !tx.committed || tx.joined.NewUser == c.target.Account.Exists() {
					t.Fatalf("join = %+v", tx.joined)
				}
				if (tx.joined.PasswordHash != "") != (c.password != "") {
					t.Fatalf("hash = %q", tx.joined.PasswordHash)
				}
			}
		})
	}
}

func TestAcceptRejectsClosedInvitations(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	for _, inv := range []invitation.Invitation{{ExpiresAt: past}, {ExpiresAt: time.Now().Add(time.Hour), RevokedAt: &past}, {ExpiresAt: time.Now().Add(time.Hour), AcceptedAt: &past}} {
		tx := &fakeTx{target: invitation.Target{Invitation: inv, OrgActive: true}}
		_, err := New(fakeRepo{tx: tx}, fakeSecrets{}, fakePasswords{}, nil, nil).Accept(context.Background(), invitation.Acceptance{Token: invitation.TokenPrefix + "x", Password: "a long enough password"})
		if !errors.Is(err, invitation.ErrInvalid) || tx.joined != nil {
			t.Fatalf("%+v: %v", inv, err)
		}
	}
}

func TestInviteChecksAndDelivery(t *testing.T) {
	ctx, b, m := context.Background(), invitation.Boundary{}, invitation.Mutation{Actor: "op"}
	role := identity.NewRoleID()
	if _, err := New(fakeRepo{tx: &fakeTx{member: true}}, fakeSecrets{}, nil, nil, nil).Invite(ctx, b, m, invitation.Input{Email: "bob@example.com"}); kind(err) != errx.TypeConflict {
		t.Fatalf("active member: %v", err)
	}
	if _, err := New(fakeRepo{tx: &fakeTx{}}, fakeSecrets{}, nil, nil, nil).Invite(ctx, b, m, invitation.Input{Email: "bob@example.com", Roles: []identity.RoleID{role}}); kind(err) != errx.TypeBusiness {
		t.Fatalf("unknown role: %v", err)
	}
	// Delivery failure is reported, the invitation stays committed.
	tx := &fakeTx{refs: invitation.References{Roles: 1}}
	out, err := New(fakeRepo{tx: tx}, fakeSecrets{}, nil, fakeMailer{err: errx.External("down")}, nil).Invite(ctx, b, m, invitation.Input{Email: "bob@example.com", Roles: []identity.RoleID{role}})
	if err != nil || !tx.created || !tx.committed || out.Delivery != "failed" || out.Token != invitation.TokenPrefix+"raw" || out.Link == "" {
		t.Fatalf("invite = %+v %v", out, err)
	}
	out, err = New(fakeRepo{tx: &fakeTx{}}, fakeSecrets{}, nil, nil, nil).Invite(ctx, b, m, invitation.Input{Email: "bob@example.com"})
	if err != nil || out.Delivery != "skipped" {
		t.Fatalf("no mailer = %+v %v", out, err)
	}
}
