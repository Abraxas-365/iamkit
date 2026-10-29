package oauthsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
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

// NewCapabilities builds the reader; features (nil: the feature is on
// wherever a protected resource allows it) and store (nil: no cache).
func NewCapabilities(r oauth.CapabilityRepository, features oauth.Features, store cache.Store) *Capabilities {
	return &Capabilities{repository: r, features: features, cache: store}
}

const capabilityKey = "oauthcapability:offers"

// Offered reads the offers; an error is returned only when they cannot be
// known (the caller then advertises nothing).
func (c *Capabilities) Offered(ctx context.Context) (oauth.Offers, error) {
	return cache.Read(ctx, c.cache, capabilityKey, config.CapabilityCacheTTL, func() (oauth.Offers, error) {
		return c.read(ctx)
	})
}

func (c *Capabilities) read(ctx context.Context) (oauth.Offers, error) {
	environments, err := c.repository.ClientMetadataEnvironments(ctx)
	if err != nil {
		return oauth.Offers{}, err
	}
	for _, environment := range environments {
		if c.features == nil {
			return oauth.Offers{ClientMetadataDocuments: true}, nil
		}
		on, err := c.features.Enabled(ctx, environment, config.FeatureClientMetadataDocuments)
		if err != nil {
			return oauth.Offers{}, err
		}
		if on {
			return oauth.Offers{ClientMetadataDocuments: true}, nil
		}
	}
	return oauth.Offers{}, nil
}
