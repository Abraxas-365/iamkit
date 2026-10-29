package oauthsvc

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SetExternalClients enables client_id URLs (Client ID Metadata
// Documents): documents reads them, features gates them per environment
// (nil: always on).
//
// throttle (nil: none) counts network reads of documents per environment.
func (s *Service) SetExternalClients(documents oauth.MetadataDocuments, features oauth.Features, throttle oauth.Throttle) {
	s.documents, s.features, s.throttle = documents, features, throttle
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
		return nil, oauth.WithClient(oauth.ErrClientRegisteredOnly(), target.Environment, clientID.String(), "", "")
	}
	if s.features != nil {
		on, err := s.features.Enabled(ctx, target.Environment, config.FeatureClientMetadataDocuments)
		if err != nil {
			return nil, err
		}
		if !on {
			return nil, oauth.WithClient(oauth.ErrClientDisabled(), target.Environment, clientID.String(), "", "")
		}
	}
	return s.resolve(ctx, target, clientID)
}

// resolve reads the document at clientID and finds the client it names at
// target. An approved client (or one policy approves: allowlist, preset,
// open server) is materialized now; one nobody approved and no row holds is
// only described, with ID zero: it is written when a signed-in user asks
// for access (RequestAccess), so an anonymous request leaves nothing.
func (s *Service) resolve(ctx context.Context, target oauth.ExternalTarget, clientID *url.URL) (*oauth.Client, error) {
	known, err := s.repository.ExternalClientID(ctx, target.Protected, clientID.String())
	if err != nil {
		return nil, err
	}
	doc, fetched, err := s.documents.Document(ctx, clientID, s.admitFetch(ctx, target.Environment, known.IsZero()))
	if err != nil {
		// M-4: an approved client whose document cannot be read now (the
		// host is down or answers an error, or the fetch budget is spent)
		// keeps the metadata it was approved with, for a bounded time.
		if stale, serr := s.stale(ctx, target, known, err); serr != nil || stale != nil {
			return stale, serr
		}
		return nil, err
	}
	admission := target.Admission(clientID)
	if known.IsZero() && admission != oauth.AdmissionApproved {
		unsaved, err := s.repository.UnsavedExternal(ctx, target, doc)
		if unsaved != nil {
			unsaved.MetadataFetched = fetched
		}
		return unsaved, err
	}
	id, err := s.repository.SaveExternalClient(ctx, oauth.ExternalSave{Target: target, ID: identity.NewClientID(), Document: doc, Fetched: fetched, Admission: admission, Source: target.AdmissionSource(clientID)})
	if err != nil {
		return nil, err
	}
	client, err := s.repository.FindExternal(ctx, target.Environment, id)
	if err != nil {
		return nil, err
	}
	if client, err = s.gated(ctx, client); err != nil {
		return nil, err
	}
	if client.Admission == oauth.AdmissionBlocked {
		return nil, oauth.WithClient(oauth.ErrClientBlocked(), client.Environment, client.ExternalID, client.Name, client.LogoURI)
	}
	return client, nil
}

// stale is the client to serve when reading err's document failed: only an
// approved row, only for a failure that says nothing about the document
// (oauth.CodeDocumentUnavailable, oauth.CodeFetchBudget), and only until
// config.ClientMetadataStaleFor after the stored copy could no longer have
// been cached (config.ClientMetadataMaxTTL after it was fetched). Nil when
// err stands. The stored fields are what was approved: a document that
// changed them demoted the client when it was read.
func (s *Service) stale(ctx context.Context, target oauth.ExternalTarget, known identity.ClientID, err error) (*oauth.Client, error) {
	var e *errx.Error
	if known.IsZero() || !errors.As(err, &e) || (e.Code != oauth.CodeDocumentUnavailable && e.Code != oauth.CodeFetchBudget) {
		return nil, nil
	}
	client, ferr := s.repository.FindExternal(ctx, target.Environment, known)
	if ferr != nil {
		return nil, nil
	}
	if client.Admission != oauth.AdmissionApproved || client.MetadataFetched.IsZero() || time.Since(client.MetadataFetched) > config.ClientMetadataMaxTTL+config.ClientMetadataStaleFor {
		return nil, nil
	}
	client, gerr := s.gated(ctx, client)
	if gerr != nil {
		return nil, gerr
	}
	slog.Warn("serving stored client metadata", "client", client.ExternalID, "protected_resource", target.Protected, "fetched", client.MetadataFetched, "reason", e.Code)
	return client, nil
}

// admitFetch counts a network read of a document against the budgets
// (shared by the replicas when the throttle is): the calling address's
// (config.ClientMetadataFetchesPerIPPerMinute), the environment's
// (config.ClientMetadataFetchesPerMinute), and, for a client with no row,
// the share of the environment's that new clients may use
// (config.ClientMetadataNewFetchesPerMinute) — the rest is reserved for
// clients already known, whose documents must stay refreshable while
// strangers flood. Cached documents are free; a throttle that fails
// admits, like the other limits.
func (s *Service) admitFetch(ctx context.Context, environment identity.EnvironmentID, stranger bool) oauth.Fetch {
	if s.throttle == nil {
		return nil
	}
	address := fetchAddress(identity.ClientInfoFrom(ctx).IP)
	env := environment.String()
	return func(ctx context.Context) error {
		take := func(key string, max int64) bool {
			ok, err := s.throttle.Take(ctx, key, max, time.Minute)
			return err != nil || ok
		}
		if address != "" && !take("cimd-fetch-ip:"+env+":"+address, config.ClientMetadataFetchesPerIPPerMinute) {
			return oauth.ErrFetchBudget()
		}
		if stranger && !take("cimd-fetch-new:"+env, config.ClientMetadataNewFetchesPerMinute) {
			return oauth.ErrFetchBudget()
		}
		if !take("cimd-fetch:"+env, config.ClientMetadataFetchesPerMinute) {
			return oauth.ErrFetchBudget()
		}
		return nil
	}
}

// fetchAddress is the budget key of a caller's address: the address, or the
// /64 of an IPv6 one (a host holds a whole /64); "" when unknown.
func fetchAddress(raw string) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	ip = ip.Unmap()
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip.String()
}

func (s *Service) TicketClient(ctx context.Context, ticket oauth.Ticket) (*oauth.Client, error) {
	if !ticket.Client.IsZero() {
		// The ticket's row was stored by the server: either kind.
		return s.Holder(ctx, ticket.Client)
	}
	if ticket.External == nil || s.documents == nil {
		return nil, errx.Validation("invalid client")
	}
	clientID, err := oauth.ParseClientIDURL(*ticket.External)
	if err != nil {
		return nil, err
	}
	target, err := s.repository.ExternalTargetByID(ctx, ticket.Protected)
	if err != nil {
		return nil, err
	}
	return s.resolve(ctx, target, clientID)
}

func (s *Service) RequestAccess(ctx context.Context, client *oauth.Client, user identity.UserID, organization identity.OrganizationID) error {
	if !client.External() || client.Protected == nil || client.Admission == oauth.AdmissionBlocked || s.documents == nil {
		return nil
	}
	target, err := s.repository.ExternalTargetByID(ctx, client.Protected.ID)
	if err != nil {
		return err
	}
	// The document the client was resolved from (M-5: nothing is fetched
	// here): a row not written yet is created from it, pending.
	fetched := client.MetadataFetched
	if fetched.IsZero() {
		fetched = time.Now()
	}
	access := oauth.AccessRequest{Target: target, ID: identity.NewClientID(), Document: client.Document(), Fetched: fetched, User: user, Organization: organization, MaxPending: s.maxPending, MaxPerUser: s.maxPerUser, MaxPerOrganization: s.maxPerOrg, Interval: config.ClientAccessRequestInterval}
	return s.repository.RequestExternalAccess(ctx, access)
}

func (s *Service) Used(ctx context.Context, client *oauth.Client) error {
	if !client.External() || client.ID.IsZero() {
		return nil
	}
	return s.repository.TouchExternal(ctx, client.ID, config.ClientUsedInterval)
}

// SetPendingCap sets how many clients waiting for review an environment
// keeps (default config.ClientMetadataMaxPending).
func (s *Service) SetPendingCap(n int) {
	if n > 0 {
		s.maxPending = n
	}
}

// SetRequestCaps sets how many requests for clients waiting for review a
// user, and an organization, may have (0 keeps the default,
// config.ClientAccessRequestsPerUser / PerOrg).
func (s *Service) SetRequestCaps(user, organization int) {
	if user > 0 {
		s.maxPerUser = user
	}
	if organization > 0 {
		s.maxPerOrg = organization
	}
}

// PruneExternal is the client_pending_prune job: it deletes pending
// clients nobody used for config.ClientPendingRetention, a batch a round.
func (s *Service) PruneExternal(ctx context.Context) (bool, error) {
	n, err := s.repository.PruneExternal(ctx, time.Now().Add(-config.ClientPendingRetention), config.ClientPendingPruneBatch)
	return n >= config.ClientPendingPruneBatch, err
}

func (s *Service) GrantClient(ctx context.Context, clientID, kind, signatureHash string) (*oauth.Client, error) {
	if !oauth.ExternalClientID(clientID) || signatureHash == "" {
		return nil, errx.Unauthorized("invalid OAuth client")
	}
	environment, id, err := s.repository.GrantClient(ctx, clientID, kind, signatureHash)
	if err != nil {
		return nil, err
	}
	client, err := s.repository.FindExternal(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	return s.gated(ctx, client)
}
