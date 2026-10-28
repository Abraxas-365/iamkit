package oauthsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SetExternalClients enables client_id URLs (Client ID Metadata
// Documents): documents reads them, features gates them per environment
// (nil: always on).
func (s *Service) SetExternalClients(documents oauth.MetadataDocuments, features oauth.Features) {
	s.documents, s.features = documents, features
}

func (s *Service) ExternalClient(ctx context.Context, raw string, resource []string) (*oauth.Client, error) {
	if s.documents == nil {
		return nil, errx.Validation("unknown client_id")
	}
	clientID, err := oauth.ParseClientIDURL(raw)
	if err != nil {
		return nil, err
	}
	// The resource names the server, and with it the environment: a URL
	// client exists only for the protected resource it asks for.
	if len(resource) != 1 {
		return nil, errx.Validation("a client identified by a metadata document must name one resource (RFC 8707)")
	}
	uri, err := oauth.CanonicalResource(resource[0])
	if err != nil {
		return nil, err
	}
	target, err := s.repository.ExternalTarget(ctx, uri)
	if err != nil {
		if errx.IsServerError(err) {
			return nil, err
		}
		return nil, errx.Validation("the resource is not a protected resource of this deployment")
	}
	if !target.AllowClientMetadata {
		return nil, errx.Forbidden("this server accepts registered clients only")
	}
	if s.features != nil {
		on, err := s.features.Enabled(ctx, target.Environment, config.FeatureClientMetadataDocuments)
		if err != nil {
			return nil, err
		}
		if !on {
			return nil, errx.Forbidden("this environment does not accept clients identified by a metadata document")
		}
	}
	doc, fetched, err := s.documents.Document(ctx, clientID)
	if err != nil {
		return nil, err
	}
	id, err := s.repository.SaveExternalClient(ctx, target, identity.NewClientID(), doc, fetched, target.Admission(clientID))
	if err != nil {
		return nil, err
	}
	client, err := s.repository.FindActive(ctx, target.Environment, id)
	if err != nil {
		return nil, err
	}
	if client.Admission == oauth.AdmissionBlocked {
		return nil, errx.Forbidden("IT blocked this application for this server")
	}
	return client, nil
}

func (s *Service) GrantClient(ctx context.Context, clientID, kind, signatureHash string) (*oauth.Client, error) {
	if !oauth.ExternalClientID(clientID) || signatureHash == "" {
		return nil, errx.Unauthorized("invalid OAuth client")
	}
	environment, id, err := s.repository.GrantClient(ctx, clientID, kind, signatureHash)
	if err != nil {
		return nil, err
	}
	return s.repository.FindActive(ctx, environment, id)
}
