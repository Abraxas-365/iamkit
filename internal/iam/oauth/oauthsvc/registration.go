package oauthsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
)

// Registrations is dynamic client registration (RFC 7591): it stores inert
// registrations; Service.ExternalClient materializes them per protected
// resource.
type Registrations struct {
	repository oauth.RegistrationRepository
	offers     oauth.Capabilities
	maxUnused  int
}

var _ oauth.Registrations = (*Registrations)(nil)

// NewRegistrations builds the service; offers decides whether the endpoint
// answers at all (nil: never).
func NewRegistrations(r oauth.RegistrationRepository, offers oauth.Capabilities) *Registrations {
	return &Registrations{repository: r, offers: offers, maxUnused: config.ClientRegistrationMaxUnused}
}

// SetMaxUnused sets how many registrations nobody used may wait (0 keeps
// config.ClientRegistrationMaxUnused).
func (s *Registrations) SetMaxUnused(n int) {
	if n > 0 {
		s.maxUnused = n
	}
}

func (s *Registrations) Register(ctx context.Context, input oauth.ClientRegistration) (oauth.Registered, error) {
	// D28: while no environment takes such clients the endpoint does not
	// exist, so nothing is stored that no server could use.
	if s.offers == nil {
		return oauth.Registered{}, oauth.ErrRegistrationNotOffered()
	}
	offers, err := s.offers.Offered(ctx)
	if err != nil {
		return oauth.Registered{}, err
	}
	if !offers.DynamicRegistration {
		return oauth.Registered{}, oauth.ErrRegistrationNotOffered()
	}
	registered, err := input.Validate()
	if err != nil {
		return oauth.Registered{}, err
	}
	if registered.ClientID, err = oauth.NewDynamicClientID(); err != nil {
		return oauth.Registered{}, err
	}
	registered.CreatedAt = time.Now().UTC().Truncate(time.Second)
	if err = s.repository.SaveRegistration(ctx, registered, s.maxUnused); err != nil {
		return oauth.Registered{}, err
	}
	return registered, nil
}

// PruneRegistrations is the client_registration_prune job: registrations
// never used for config.ClientRegistrationUnusedTTL, and used ones no
// client row holds idle for config.ClientRegistrationIdleTTL, a batch a
// round.
func (s *Registrations) PruneRegistrations(ctx context.Context) (bool, error) {
	now := time.Now()
	n, err := s.repository.PruneRegistrations(ctx, now.Add(-config.ClientRegistrationUnusedTTL), now.Add(-config.ClientRegistrationIdleTTL), config.ClientRegistrationPruneBatch)
	return n >= config.ClientRegistrationPruneBatch, err
}
