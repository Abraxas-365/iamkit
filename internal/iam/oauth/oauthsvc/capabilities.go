package oauthsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Capabilities answers what discovery may advertise (oauth.Offers) from the
// protected resources and the feature flags, cached for
// config.CapabilityCacheTTL (shared across replicas when a store exists).
type Capabilities struct {
	repository oauth.CapabilityRepository
	features   oauth.Features
	cache      cache.Store
}

var _ oauth.Capabilities = (*Capabilities)(nil)

// NewCapabilities builds the reader; features (nil: client metadata
// documents are on wherever a protected resource allows them, dynamic
// registration nowhere) and store (nil: no cache).
func NewCapabilities(r oauth.CapabilityRepository, features oauth.Features, store cache.Store) *Capabilities {
	return &Capabilities{repository: r, features: features, cache: store}
}

const capabilityKey = "oauthcapability:offers:v2"

// Offered reads the offers; an error is returned only when they cannot be
// known (the caller then advertises nothing).
func (c *Capabilities) Offered(ctx context.Context) (oauth.Offers, error) {
	return cache.Read(ctx, c.cache, capabilityKey, config.CapabilityCacheTTL, func() (oauth.Offers, error) {
		return c.read(ctx)
	})
}

func (c *Capabilities) read(ctx context.Context) (oauth.Offers, error) {
	documents, err := c.repository.ClientMetadataEnvironments(ctx)
	if err != nil {
		return oauth.Offers{}, err
	}
	var out oauth.Offers
	if out.ClientMetadataDocuments, err = c.any(ctx, documents, config.FeatureClientMetadataDocuments, true); err != nil {
		return oauth.Offers{}, err
	}
	registered, err := c.repository.DynamicRegistrationEnvironments(ctx)
	if err != nil {
		return oauth.Offers{}, err
	}
	if out.DynamicRegistration, err = c.any(ctx, registered, config.FeatureDynamicClientRegistration, false); err != nil {
		return oauth.Offers{}, err
	}
	return out, nil
}

// any reports whether feature is on in one of environments (unflagged:
// what a nil Features answers).
func (c *Capabilities) any(ctx context.Context, environments []identity.EnvironmentID, feature string, unflagged bool) (bool, error) {
	for _, environment := range environments {
		if c.features == nil {
			return unflagged, nil
		}
		on, err := c.features.Enabled(ctx, environment, feature)
		if err != nil {
			return false, err
		}
		if on {
			return true, nil
		}
	}
	return false, nil
}
