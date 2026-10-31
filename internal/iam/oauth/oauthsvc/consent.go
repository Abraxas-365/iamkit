package oauthsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Consents serves what users, operators and the system do with consents
// and administrator grants (D29-D33).
type Consents struct {
	repository oauth.ConsentRepository
	// retention is how long revoked records are kept.
	retention time.Duration
}

var (
	_ oauth.ConsentCommands = (*Consents)(nil)
	_ oauth.ConsentQueries  = (*Consents)(nil)
)

// NewConsents keeps revoked consents and grants for retention, the
// deployment's security event ceiling (must be positive).
func NewConsents(r oauth.ConsentRepository, retention time.Duration) *Consents {
	return &Consents{repository: r, retention: retention}
}

func (s *Consents) Disconnect(ctx context.Context, m oauth.Mutation, input oauth.Disconnect) error {
	if input.Reason != oauth.ConsentRevokedByUser && input.Reason != oauth.ConsentRevokedByOperator {
		input.Reason = oauth.ConsentRevokedByOperator
	}
	input.Environment = m.Environment
	_, err := s.repository.Disconnect(ctx, m, input)
	return err
}

func (s *Consents) GrantClient(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID, input oauth.ClientGrantInput) (oauth.ClientGrant, error) {
	if err := input.Validate(time.Now()); err != nil {
		return oauth.ClientGrant{}, err
	}
	target, err := s.repository.ClientGrantTarget(ctx, m.Environment, protected, client)
	if err != nil {
		return oauth.ClientGrant{}, err
	}
	if target.ConsentMode != oauth.ConsentModeAdminGranted {
		return oauth.ClientGrant{}, oauth.ErrConsentModePerUser()
	}
	if err = input.CheckScopes(target.Permissions); err != nil {
		return oauth.ClientGrant{}, err
	}
	return s.repository.SaveClientGrant(ctx, m, oauth.ClientGrantSave{ID: identity.NewClientGrantID(), Protected: protected, Client: client, Input: input})
}

func (s *Consents) RevokeClientGrant(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID, grant identity.ClientGrantID) error {
	return s.repository.RevokeClientGrant(ctx, m, protected, client, grant)
}

func (s *Consents) ExpireClientGrants(ctx context.Context) (bool, error) {
	n, err := s.repository.ExpireClientGrants(ctx, config.ConsentJobBatch)
	return n >= config.ConsentJobBatch, err
}

func (s *Consents) PruneConsents(ctx context.Context) (bool, error) {
	n, err := s.repository.PruneConsents(ctx, time.Now().Add(-s.retention), config.ConsentJobBatch)
	return n >= config.ConsentJobBatch, err
}

func (s *Consents) Agreed(ctx context.Context, key oauth.ConsentKey, admin bool) (oauth.Agreed, error) {
	return s.repository.Agreed(ctx, key, admin)
}

func (s *Consents) ConnectedApps(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, filter oauth.ConnectedAppFilter) ([]oauth.ConnectedApp, error) {
	return s.repository.ConnectedApps(ctx, environment, user, filter)
}

func (s *Consents) ListClientGrants(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, filter oauth.ClientGrantFilter) ([]oauth.ClientGrant, error) {
	return s.repository.ListClientGrants(ctx, environment, protected, filter)
}
