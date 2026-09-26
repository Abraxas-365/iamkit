package provisioning

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Commands interface {
	Create(ctx context.Context, p Principal, input User) (User, error)
	Update(ctx context.Context, p Principal, user identity.UserID, input Update) (User, error)
	// Delete deprovisions the identity from the connection (SCIM DELETE).
	Delete(ctx context.Context, p Principal, user identity.UserID) error
	Authenticate(ctx context.Context, raw string) (Principal, error)
}
type Queries interface {
	Find(ctx context.Context, p Principal, user identity.UserID) (User, error)
	List(ctx context.Context, p Principal, f Filter) ([]User, int, error)
}

type Repository interface {
	Authenticate(ctx context.Context, hash []byte) (Principal, error)
	Find(ctx context.Context, p Principal, user identity.UserID) (User, error)
	List(ctx context.Context, p Principal, f Filter) ([]User, int, error)
	// Create returns the provisioned user id, which differs from input.ID when
	// a deprovisioned identity is reactivated or an existing member adopted.
	Create(ctx context.Context, p Principal, input User) (identity.UserID, error)
	Update(ctx context.Context, p Principal, user identity.UserID, input Update) (User, error)
	Deprovision(ctx context.Context, p Principal, user identity.UserID) error
}
type Secrets interface{ Hash(raw string) []byte }

// GroupCommands manage the connection's groups (SCIM /Groups).
type GroupCommands interface {
	CreateGroup(ctx context.Context, p Principal, input GroupInput) (identity.GroupID, error)
	UpdateGroup(ctx context.Context, p Principal, group identity.GroupID, input GroupUpdate) error
	DeleteGroup(ctx context.Context, p Principal, group identity.GroupID) error
}
type GroupQueries interface {
	FindGroup(ctx context.Context, p Principal, group identity.GroupID, members bool) (Group, error)
	ListGroups(ctx context.Context, p Principal, filter GroupFilter, page query.Pagination) (query.Paginated[Group], error)
}

// GroupRepository only sees groups owned by p.Connection. Members must be
// live identities provisioned by the same connection.
type GroupRepository interface {
	CreateGroup(ctx context.Context, p Principal, group identity.GroupID, input GroupInput) error
	UpdateGroup(ctx context.Context, p Principal, group identity.GroupID, input GroupUpdate) error
	DeleteGroup(ctx context.Context, p Principal, group identity.GroupID) error
	FindGroup(ctx context.Context, p Principal, group identity.GroupID, members bool) (Group, error)
	ListGroups(ctx context.Context, p Principal, filter GroupFilter, page query.Pagination) (query.Paginated[Group], error)
}

type ControlCommands interface {
	Issue(ctx context.Context, m Mutation, input CredentialInput) (Credential, error)
	Revoke(ctx context.Context, m Mutation, credential identity.CredentialID) error
	Link(ctx context.Context, m Mutation, input Link) error
}
type ControlQueries interface {
	Credentials(ctx context.Context, environment identity.EnvironmentID) ([]CredentialView, error)
}

type ControlRepository interface {
	IssueCredential(ctx context.Context, m Mutation, input CredentialInput, cred Credential, hash []byte, create bool) error
	RevokeCredential(ctx context.Context, m Mutation, credential identity.CredentialID) error
	Link(ctx context.Context, m Mutation, input Link) error
	Credentials(ctx context.Context, environment identity.EnvironmentID) ([]CredentialView, error)
}
type Generator interface {
	Generate(prefix string) (string, []byte, error)
}
