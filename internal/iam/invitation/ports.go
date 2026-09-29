package invitation

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Commands are the operator-side and invitee-side invitation use cases.
type Commands interface {
	Invite(ctx context.Context, b Boundary, m Mutation, input Input) (Issued, error)
	Resend(ctx context.Context, b Boundary, m Mutation, invitation identity.InvitationID) (Issued, error)
	Revoke(ctx context.Context, b Boundary, m Mutation, invitation identity.InvitationID) error
	Accept(ctx context.Context, input Acceptance) (Accepted, error)
}

type Queries interface {
	List(ctx context.Context, b Boundary, filter Filter, page query.Pagination) (query.Paginated[Invitation], error)
	Find(ctx context.Context, b Boundary, invitation identity.InvitationID) (Invitation, error)
	Preview(ctx context.Context, token string) (Preview, error)
}

// Repository persists invitations. Accept and invite checks run inside a
// Transaction so the membership and pending-invitation checks cannot race.
type Repository interface {
	Begin(ctx context.Context) (Transaction, error)
	List(ctx context.Context, b Boundary, filter Filter, page query.Pagination) (query.Paginated[Invitation], error)
	Find(ctx context.Context, b Boundary, invitation identity.InvitationID) (Invitation, error)
	// Target finds an invitation by token hash, whatever its status.
	Target(ctx context.Context, hash []byte) (Target, error)
	// InviterName is the display name of an actor (operator email), or "".
	InviterName(ctx context.Context, actor string) (string, error)
}

type Transaction interface {
	Commit() error
	Rollback() error
	Organization(ctx context.Context, b Boundary) (Organization, error)
	ActiveMember(ctx context.Context, b Boundary, email string) (bool, error)
	References(ctx context.Context, b Boundary, roles []identity.RoleID, groups []identity.GroupID) (References, error)
	// ExpirePending revokes the org+email invitation left pending past its
	// expiry, so a new one can be created.
	ExpirePending(ctx context.Context, b Boundary, email string) error
	Create(ctx context.Context, b Boundary, m Mutation, invitation Invitation, hash []byte) error
	// Lock loads an invitation for update.
	Lock(ctx context.Context, b Boundary, invitation identity.InvitationID) (Invitation, error)
	Reissue(ctx context.Context, b Boundary, m Mutation, invitation identity.InvitationID, hash []byte, expires time.Time) error
	Revoke(ctx context.Context, b Boundary, m Mutation, invitation identity.InvitationID) error
	// LockTarget loads an invitation by token hash for update, with the
	// invitee's account.
	LockTarget(ctx context.Context, hash []byte) (Target, error)
	// Join creates or updates the user and membership, applies roles and
	// groups, and marks the invitation accepted.
	Join(ctx context.Context, j Joining) error
}

// Secrets generates tokens and hashes them for storage.
type Secrets interface {
	Generate(prefix string) (raw string, hash []byte, err error)
	Hash(raw string) []byte
}

type Passwords interface {
	Hash(password string) (string, error)
}

// PasswordPolicy checks a new account's password against the environment's
// policy tightened by the inviting organization's requirements
// (implemented by the authentication module).
type PasswordPolicy interface {
	CheckMemberPassword(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, password string) error
}

// Mailer sends the invitation; Link returns the environment's accept link
// for a token, or "" when it has no invitation page.
type Mailer interface {
	Send(ctx context.Context, environment identity.EnvironmentID, mail Mail) error
	Link(ctx context.Context, environment identity.EnvironmentID, token string) (string, error)
}

// Clock is injected so expiry is testable.
type Clock func() time.Time
