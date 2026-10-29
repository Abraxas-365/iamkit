package oauthsvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Admissions is what IT does with the clients of metadata documents, the
// allowlist and the presets (see oauth.AdmissionCommands).
type Admissions struct {
	repository oauth.AdmissionRepository
	features   oauth.Features
}

var (
	_ oauth.AdmissionCommands = (*Admissions)(nil)
	_ oauth.AdmissionQueries  = (*Admissions)(nil)
)

// NewAdmissions builds the service; features (nil: never) says whether an
// environment is offered the development presets.
func NewAdmissions(r oauth.AdmissionRepository, features oauth.Features) *Admissions {
	return &Admissions{repository: r, features: features}
}

func (s *Admissions) development(ctx context.Context, environment identity.EnvironmentID) (bool, error) {
	if s.features == nil {
		return false, nil
	}
	return s.features.Enabled(ctx, environment, config.FeatureDevelopmentClients)
}

// client checks the client belongs to the protected resource before an
// action on it, so an id of another server is a 404.
func (s *Admissions) client(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error {
	if protected.IsZero() || client.IsZero() {
		return errx.NotFound("client not found")
	}
	if _, err := s.repository.FindExternalClient(ctx, m.Environment, protected, client); err != nil {
		return err
	}
	return nil
}

func (s *Admissions) ApproveClient(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID, input oauth.Approval) error {
	if err := input.Validate(time.Now()); err != nil {
		return err
	}
	if err := s.client(ctx, m, protected, client); err != nil {
		return err
	}
	m.Action, m.Target = oauth.ActionClientApprove, client.String()
	return s.repository.ApproveClient(ctx, m, protected, client, input)
}

func (s *Admissions) BlockClient(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error {
	if err := s.client(ctx, m, protected, client); err != nil {
		return err
	}
	m.Action, m.Target = oauth.ActionClientBlock, client.String()
	return s.repository.BlockClient(ctx, m, protected, client)
}

func (s *Admissions) UnblockClient(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error {
	if err := s.client(ctx, m, protected, client); err != nil {
		return err
	}
	m.Action, m.Target = oauth.ActionClientUnblock, client.String()
	return s.repository.UnblockClient(ctx, m, protected, client)
}

func (s *Admissions) ForgetClient(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, client identity.ClientID) error {
	if err := s.client(ctx, m, protected, client); err != nil {
		return err
	}
	m.Action, m.Target = oauth.ActionClientForget, client.String()
	return s.repository.ForgetClient(ctx, m, protected, client)
}

func (s *Admissions) CreateAllowlistEntry(ctx context.Context, m oauth.Mutation, input oauth.AllowlistCreate) (oauth.AllowlistEntry, error) {
	development, err := s.development(ctx, m.Environment)
	if err != nil {
		return oauth.AllowlistEntry{}, err
	}
	input, err = input.Resolve(development)
	if err != nil {
		return oauth.AllowlistEntry{}, err
	}
	if input.Protected != nil {
		if _, err = s.repository.FindProtectedResource(ctx, m.Environment, *input.Protected); err != nil {
			return oauth.AllowlistEntry{}, err
		}
	}
	id := identity.NewAllowlistEntryID()
	m.Action, m.Target = oauth.ActionAllowlistCreate, id.String()
	if err = s.repository.CreateAllowlistEntry(ctx, m, id, input); err != nil {
		return oauth.AllowlistEntry{}, err
	}
	return s.repository.FindAllowlistEntry(ctx, m.Environment, id)
}

func (s *Admissions) DeleteAllowlistEntry(ctx context.Context, m oauth.Mutation, entry identity.AllowlistEntryID) error {
	if entry.IsZero() {
		return errx.NotFound("allowlist entry not found")
	}
	m.Action, m.Target = oauth.ActionAllowlistDelete, entry.String()
	return s.repository.DeleteAllowlistEntry(ctx, m, entry)
}

func (s *Admissions) ApplyPreset(ctx context.Context, m oauth.Mutation, input oauth.PresetApply) (oauth.PresetResult, error) {
	if err := input.Validate(); err != nil {
		return oauth.PresetResult{}, err
	}
	p, ok := oauth.FindPreset(input.Preset)
	if !ok {
		return oauth.PresetResult{}, errx.Validation("unknown client preset")
	}
	if p.Mechanism == oauth.PresetTemplate {
		if input.Protected == nil {
			return oauth.PresetResult{}, errx.Validation("protected_resource_id is required for a client template preset")
		}
		return s.CreateClientTemplate(ctx, m, *input.Protected, input)
	}
	entry, err := s.CreateAllowlistEntry(ctx, m, oauth.AllowlistCreate{Protected: input.Protected, Preset: input.Preset})
	if err != nil {
		return oauth.PresetResult{}, err
	}
	return presetResult(p, &entry, nil), nil
}

func presetResult(p oauth.Preset, entry *oauth.AllowlistEntry, client *oauth.TemplateClient) oauth.PresetResult {
	return oauth.PresetResult{Preset: p.Key, Name: p.Name, Mechanism: p.Mechanism, Network: p.Network, Warnings: p.Warnings(), Allowlist: entry, Client: client}
}

func (s *Admissions) CreateClientTemplate(ctx context.Context, m oauth.Mutation, protected identity.ProtectedResourceID, input oauth.PresetApply) (oauth.PresetResult, error) {
	if err := input.Validate(); err != nil {
		return oauth.PresetResult{}, err
	}
	p, ok := oauth.FindPreset(input.Preset)
	if !ok {
		return oauth.PresetResult{}, errx.Validation("unknown client preset")
	}
	if p.Mechanism != oauth.PresetTemplate {
		return oauth.PresetResult{}, errx.Validation("this preset is a client metadata document: add it to the allowlist instead")
	}
	development, err := s.development(ctx, m.Environment)
	if err != nil {
		return oauth.PresetResult{}, err
	}
	if p.DevelopmentOnly && !development {
		return oauth.PresetResult{}, errx.Validation("this preset is offered in development environments only (feature development_clients)")
	}
	resource, err := s.repository.FindProtectedResource(ctx, m.Environment, protected)
	if err != nil {
		return oauth.PresetResult{}, err
	}
	registration := oauth.TemplateRegistration(p, resource.Application, resource.Resource)
	if err = registration.Validate(); err != nil {
		return oauth.PresetResult{}, err
	}
	if err = identity.ValidateClientRedirects(registration.Redirects); err != nil {
		return oauth.PresetResult{}, err
	}
	id := identity.NewClientID()
	got, created, err := s.repository.CreateTemplateClient(ctx, m, id, registration)
	if err != nil {
		return oauth.PresetResult{}, err
	}
	return presetResult(p, nil, &oauth.TemplateClient{ClientID: got, RedirectURIs: registration.Redirects, LoopbackAnyPort: p.LoopbackAnyPort, Created: created}), nil
}

func (s *Admissions) ExpireApprovals(ctx context.Context) (bool, error) {
	n, err := s.repository.ExpireApprovals(ctx, config.ClientExpireBatch)
	return n >= config.ClientExpireBatch, err
}

// ReconcileDocuments: see oauth.AdmissionCommands. An environment's flag is
// read through the feature service (cached, shared by the replicas).
func (s *Admissions) ReconcileDocuments(ctx context.Context) (bool, error) {
	if s.features == nil {
		return false, nil
	}
	environments, err := s.repository.ApprovedEnvironments(ctx)
	if err != nil {
		return false, err
	}
	more := false
	for _, environment := range environments {
		on, err := s.features.Enabled(ctx, environment, config.FeatureClientMetadataDocuments)
		if err != nil {
			return more, err
		}
		if on {
			continue
		}
		n, err := s.repository.DemoteDocuments(ctx, environment, config.ClientExpireBatch)
		if err != nil {
			return more, err
		}
		more = more || n >= config.ClientExpireBatch
	}
	return more, nil
}

func (s *Admissions) ListExternalClients(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, filter oauth.ExternalClientFilter, page query.Pagination) (query.Paginated[oauth.ExternalClientView], error) {
	if err := filter.Validate(); err != nil {
		return query.Paginated[oauth.ExternalClientView]{}, err
	}
	if _, err := s.repository.FindProtectedResource(ctx, environment, protected); err != nil {
		return query.Paginated[oauth.ExternalClientView]{}, err
	}
	return s.repository.ListExternalClients(ctx, environment, protected, filter, page)
}

func (s *Admissions) FindExternalClient(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (oauth.ExternalClientView, error) {
	return s.repository.FindExternalClient(ctx, environment, protected, client)
}

func (s *Admissions) ListAccessRequests(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID, page query.Pagination) (query.Paginated[oauth.AccessRequestView], error) {
	return s.repository.ListAccessRequests(ctx, environment, protected, client, page)
}

func (s *Admissions) ExternalClientImpact(ctx context.Context, environment identity.EnvironmentID, protected identity.ProtectedResourceID, client identity.ClientID) (oauth.ExternalClientImpact, error) {
	return s.repository.ExternalClientImpact(ctx, environment, protected, client)
}

func (s *Admissions) ListAllowlist(ctx context.Context, environment identity.EnvironmentID, protected *identity.ProtectedResourceID, page query.Pagination) (query.Paginated[oauth.AllowlistEntry], error) {
	return s.repository.ListAllowlist(ctx, environment, protected, page)
}

func (s *Admissions) ListPresets(ctx context.Context, environment identity.EnvironmentID) ([]oauth.PresetView, error) {
	development, err := s.development(ctx, environment)
	if err != nil {
		return nil, err
	}
	catalog := oauth.Presets(development)
	out := make([]oauth.PresetView, 0, len(catalog))
	for _, p := range catalog {
		out = append(out, oauth.PresetView{Preset: p, Warnings: p.Warnings()})
	}
	return out, nil
}
