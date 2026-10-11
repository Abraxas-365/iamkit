package apikey

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Commands create and revoke keys and save the policy. Every call is
// confined to m.Scope: an organization scope reaches organization keys and
// its members' user keys, a self scope the caller's own user keys; another
// scope's key is 404.
type Commands interface {
	// Create checks the owner (active member, machine user for machine
	// keys, application link), the policy (kind allowed, limits, max TTL),
	// the allowlist and the owner's reach (api_key_permissions: the key may
	// not be wider than it would act), the creator's own permissions
	// (m.Granter) and, in a self scope, a fresh sign-in. 422 otherwise.
	Create(ctx context.Context, m Mutation, input NewAPIKey) (Issued, error)
	// Revoke ends the key (and the sessions exchanged from a machine key);
	// revoking twice is a no-op.
	Revoke(ctx context.Context, m Mutation, key identity.APIKeyID) error
	// SavePolicy replaces the environment's policy (operators).
	SavePolicy(ctx context.Context, m Mutation, policy Policy) (Policy, error)
}

// Queries read keys (never their values) and the policy.
type Queries interface {
	List(ctx context.Context, scope Scope, filter Filter, page query.Pagination) (query.Paginated[APIKey], error)
	Find(ctx context.Context, scope Scope, key identity.APIKeyID) (APIKey, error)
	Policy(ctx context.Context, environment identity.EnvironmentID) (Policy, error)
	// Options lists what the caller may create in an organization or self
	// scope: granter is the creating admin (organization keys), application
	// the caller's application (user keys: only resources linked to it).
	Options(ctx context.Context, scope Scope, granter identity.UserID, application identity.ApplicationID) (Options, error)
}

// Repository persists keys (W1 may add read helpers it needs, e.g. for
// Options). Create re-checks owner, membership,
// application link, allowlist, reach and the policy limits in its
// transaction (the service's checks are advisory under concurrency) and
// writes the api_key.created audit row and event through eventpg.
type Repository interface {
	Create(ctx context.Context, m Mutation, key APIKey, secretHash []byte, limit int) (APIKey, error)
	Revoke(ctx context.Context, m Mutation, key identity.APIKeyID) error
	List(ctx context.Context, scope Scope, filter Filter, page query.Pagination) (query.Paginated[APIKey], error)
	Find(ctx context.Context, scope Scope, key identity.APIKeyID) (APIKey, error)
	// Reach is api_key_permissions for a prospective key: the permissions
	// it would act with now.
	Reach(ctx context.Context, environment identity.EnvironmentID, input NewAPIKey) ([]string, error)
	// Held is api_key_reach of a user: what they may do on the resource in
	// the organization now (the creating admin's own permissions).
	Held(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, user identity.UserID, resource identity.ResourceID) ([]string, error)
	// OptionResources lists, for the Options of an owner kind (user in a
	// self scope, organization in an organization scope), the resources
	// with the permissions a new key may carry: the allowlist ∩ the
	// owner's reach (∩ the granter's reach for organization keys), only
	// resources linked to application in a self scope.
	OptionResources(ctx context.Context, scope Scope, kind OwnerKind, granter identity.UserID, application identity.ApplicationID) ([]OptionResource, error)
	Policy(ctx context.Context, environment identity.EnvironmentID) (Policy, error)
	SavePolicy(ctx context.Context, m Mutation, policy Policy) (Policy, error)
}

// Secrets generates key values (identity.APIKeyPrefix) and their hashes.
type Secrets interface {
	Generate(prefix string) (raw string, hash []byte, err error)
}
