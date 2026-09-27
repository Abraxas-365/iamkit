// Package invsvc implements the invitation use cases.
package invsvc

import (
	"context"
	"log/slog"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository invitation.Repository
	secrets    invitation.Secrets
	passwords  invitation.Passwords
	mailer     invitation.Mailer
	now        invitation.Clock
}

func New(r invitation.Repository, s invitation.Secrets, p invitation.Passwords, m invitation.Mailer, now invitation.Clock) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{repository: r, secrets: s, passwords: p, mailer: m, now: now}
}

var _ invitation.Commands = (*Service)(nil)
var _ invitation.Queries = (*Service)(nil)

func (s *Service) Invite(ctx context.Context, b invitation.Boundary, m invitation.Mutation, input invitation.Input) (invitation.Issued, error) {
	if err := input.Validate(); err != nil {
		return invitation.Issued{}, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return invitation.Issued{}, err
	}
	defer tx.Rollback()
	org, err := tx.Organization(ctx, b)
	if err != nil {
		return invitation.Issued{}, err
	}
	if !org.Active {
		return invitation.Issued{}, errx.Business("organization is inactive")
	}
	member, err := tx.ActiveMember(ctx, b, input.Email)
	if err != nil {
		return invitation.Issued{}, err
	}
	if member {
		return invitation.Issued{}, errx.Conflict("user is already an active member of the organization")
	}
	refs, err := tx.References(ctx, b, input.Roles, input.Groups)
	if err != nil {
		return invitation.Issued{}, err
	}
	if refs.Roles != len(input.Roles) {
		return invitation.Issued{}, errx.Business("role_ids must be roles of this environment")
	}
	if refs.Groups != len(input.Groups) {
		return invitation.Issued{}, errx.Business("group_ids must be operator-managed groups of this organization")
	}
	if err = tx.ExpirePending(ctx, b, input.Email); err != nil {
		return invitation.Issued{}, err
	}
	token, hash, err := s.secrets.Generate(invitation.TokenPrefix)
	if err != nil {
		return invitation.Issued{}, err
	}
	inv := invitation.Invitation{
		ID: identity.NewInvitationID(), Organization: b.Organization, Email: input.Email,
		Roles: input.Roles, Groups: input.Groups, Inviter: m.Actor,
		ExpiresAt: s.now().Add(config.InvitationTTL),
	}
	if err = tx.Create(ctx, b, m, inv, hash); err != nil {
		return invitation.Issued{}, err
	}
	if err = tx.Commit(); err != nil {
		return invitation.Issued{}, err
	}
	return s.issue(ctx, b, inv.ID, token, org.Name)
}

func (s *Service) Resend(ctx context.Context, b invitation.Boundary, m invitation.Mutation, id identity.InvitationID) (invitation.Issued, error) {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return invitation.Issued{}, err
	}
	defer tx.Rollback()
	inv, err := tx.Lock(ctx, b, id)
	if err != nil {
		return invitation.Issued{}, err
	}
	if !inv.Open() {
		return invitation.Issued{}, errx.Business("invitation is " + inv.State(s.now()))
	}
	org, err := tx.Organization(ctx, b)
	if err != nil {
		return invitation.Issued{}, err
	}
	if !org.Active {
		return invitation.Issued{}, errx.Business("organization is inactive")
	}
	member, err := tx.ActiveMember(ctx, b, inv.Email)
	if err != nil {
		return invitation.Issued{}, err
	}
	if member {
		return invitation.Issued{}, errx.Conflict("user is already an active member of the organization")
	}
	// A new token invalidates the previous one and restarts the expiry.
	token, hash, err := s.secrets.Generate(invitation.TokenPrefix)
	if err != nil {
		return invitation.Issued{}, err
	}
	if err = tx.Reissue(ctx, b, m, id, hash, s.now().Add(config.InvitationTTL)); err != nil {
		return invitation.Issued{}, err
	}
	if err = tx.Commit(); err != nil {
		return invitation.Issued{}, err
	}
	return s.issue(ctx, b, id, token, org.Name)
}

// issue delivers a committed invitation. A delivery failure is reported, not
// rolled back: the operator still gets the token to pass on.
func (s *Service) issue(ctx context.Context, b invitation.Boundary, id identity.InvitationID, token, orgName string) (invitation.Issued, error) {
	inv, err := s.Find(ctx, b, id)
	if err != nil {
		return invitation.Issued{}, err
	}
	out := invitation.Issued{Invitation: inv, Token: token, Delivery: "skipped"}
	if s.mailer == nil {
		return out, nil
	}
	if out.Link, err = s.mailer.Link(ctx, b.Environment, token); err != nil {
		slog.ErrorContext(ctx, "invitation link lookup failed", "invitation", id, "err", err)
	}
	inviter, err := s.repository.InviterName(ctx, inv.Inviter)
	if err != nil {
		slog.ErrorContext(ctx, "invitation inviter lookup failed", "invitation", id, "err", err)
	}
	mail := invitation.Mail{Email: inv.Email, Token: token, Link: out.Link, Organization: orgName, Inviter: inviter, ExpiresAt: inv.ExpiresAt}
	if err = s.mailer.Send(ctx, b.Environment, mail); err != nil {
		slog.ErrorContext(ctx, "invitation delivery failed", "invitation", id, "environment", b.Environment, "err", err)
		out.Delivery = "failed"
		return out, nil
	}
	out.Delivery = "sent"
	return out, nil
}

func (s *Service) Revoke(ctx context.Context, b invitation.Boundary, m invitation.Mutation, id identity.InvitationID) error {
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	inv, err := tx.Lock(ctx, b, id)
	if err != nil {
		return err
	}
	if inv.AcceptedAt != nil {
		return errx.Business("invitation is accepted")
	}
	if inv.RevokedAt != nil {
		return nil
	}
	if err = tx.Revoke(ctx, b, m, id); err != nil {
		return err
	}
	return tx.Commit()
}

// Accept joins the invitee to the organization. A new account needs a
// password unless SSO is enforced for its domain; an existing account keeps
// its credentials. The invitation's email is proven by the token, so the
// account's email becomes verified.
func (s *Service) Accept(ctx context.Context, input invitation.Acceptance) (invitation.Accepted, error) {
	if err := input.Validate(); err != nil {
		return invitation.Accepted{}, err
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return invitation.Accepted{}, err
	}
	defer tx.Rollback()
	t, err := tx.LockTarget(ctx, s.secrets.Hash(input.Token))
	if err != nil {
		return invitation.Accepted{}, err
	}
	if t.Invitation.State(s.now()) != invitation.StatusPending {
		return invitation.Accepted{}, invitation.ErrInvalid
	}
	if !t.OrgActive {
		return invitation.Accepted{}, errx.Business("organization is inactive")
	}
	j := invitation.Joining{Invitation: t.Invitation, Environment: t.Environment, User: t.Account.ID}
	if t.Account.Exists() {
		if !t.Account.Active {
			return invitation.Accepted{}, errx.Business("user is inactive")
		}
		if input.Password != "" {
			return invitation.Accepted{}, errx.Validation("an existing account keeps its password; sign in after accepting")
		}
	} else {
		j.User, j.NewUser, j.Name = identity.NewUserID(), true, input.Name
		if j.Name == "" {
			j.Name = t.Invitation.Email
		}
		switch {
		case t.SSORequired && input.Password != "":
			return invitation.Accepted{}, errx.Validation("this organization signs in with SSO; no password is set")
		case !t.SSORequired && input.Password == "":
			return invitation.Accepted{}, errx.Validation("password is required")
		case input.Password != "":
			if j.PasswordHash, err = s.passwords.Hash(input.Password); err != nil {
				return invitation.Accepted{}, err
			}
		}
	}
	if err = tx.Join(ctx, j); err != nil {
		return invitation.Accepted{}, err
	}
	if err = tx.Commit(); err != nil {
		return invitation.Accepted{}, err
	}
	return invitation.Accepted{User: j.User, Organization: t.Invitation.Organization, Email: t.Invitation.Email, Created: j.NewUser, SSORequired: t.SSORequired}, nil
}

func (s *Service) List(ctx context.Context, b invitation.Boundary, filter invitation.Filter, page query.Pagination) (query.Paginated[invitation.Invitation], error) {
	if err := filter.Validate(); err != nil {
		return query.Paginated[invitation.Invitation]{}, err
	}
	out, err := s.repository.List(ctx, b, filter, page)
	now := s.now()
	for i := range out.Items {
		out.Items[i].Status = out.Items[i].State(now)
	}
	return out, err
}

func (s *Service) Find(ctx context.Context, b invitation.Boundary, id identity.InvitationID) (invitation.Invitation, error) {
	inv, err := s.repository.Find(ctx, b, id)
	inv.Status = inv.State(s.now())
	return inv, err
}

// Preview answers only for pending invitations; everything else is the
// uniform invalid-token error.
func (s *Service) Preview(ctx context.Context, token string) (invitation.Preview, error) {
	if err := invitation.ValidToken(token); err != nil {
		return invitation.Preview{}, err
	}
	t, err := s.repository.Target(ctx, s.secrets.Hash(token))
	if err != nil {
		return invitation.Preview{}, err
	}
	status := t.Invitation.State(s.now())
	if status != invitation.StatusPending || !t.OrgActive {
		return invitation.Preview{}, invitation.ErrInvalid
	}
	return invitation.Preview{
		Organization: t.Invitation.Organization, OrganizationName: t.OrgName,
		Email: invitation.Mask(t.Invitation.Email), ExpiresAt: t.Invitation.ExpiresAt, Status: status,
		PasswordRequired: !t.Account.Exists() && !t.SSORequired, SSORequired: t.SSORequired,
	}, nil
}
