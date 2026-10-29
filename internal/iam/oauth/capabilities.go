package oauth

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Offers is what this deployment really takes today, as discovery
// advertises it: a capability is listed only when a client could use it
// (never because the code supports it). Fields are added here as features
// land (e.g. the registration endpoint, only where dynamic client
// registration is enabled in some environment).
type Offers struct {
	// ClientMetadataDocuments: some environment has feature
	// client_metadata_documents on and an active protected resource of it
	// allows client metadata documents.
	ClientMetadataDocuments bool
}

// Capabilities reads Offers (cached briefly, config.CapabilityCacheTTL).
type Capabilities interface {
	Offered(ctx context.Context) (Offers, error)
}

// CapabilityRepository is what the capability read needs from storage.
type CapabilityRepository interface {
	// ClientMetadataEnvironments are the environments with an active
	// protected resource (of an active application) that allows client
	// metadata documents.
	ClientMetadataEnvironments(ctx context.Context) ([]identity.EnvironmentID, error)
}

// With sets the metadata fields that depend on the deployment.
func (d Discovery) With(o Offers) Discovery {
	d.ClientIDMetadataDocumentSupported = o.ClientMetadataDocuments
	return d
}
