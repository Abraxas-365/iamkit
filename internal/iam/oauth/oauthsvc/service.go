package oauthsvc

import (
	"context"
	"crypto/subtle"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"slices"
	"strings"
	"time"
)

type Service struct {
	repository oauth.Repository
	secrets    oauth.Secrets
	passwords  oauth.Passwords
	hints      oauth.Hints
	documents  oauth.MetadataDocuments
	features   oauth.Features
	throttle   oauth.Throttle
	maxPending int
	// maxPerUser and maxPerOrg cap a user's, and an organization's, live
	// access requests for pending clients (M-3).
	maxPerUser, maxPerOrg int
}

func New(r oauth.Repository, s oauth.Secrets, p oauth.Passwords, h oauth.Hints) *Service {
	return &Service{repository: r, secrets: s, passwords: p, hints: h, maxPending: config.ClientMetadataMaxPending, maxPerUser: config.ClientAccessRequestsPerUser, maxPerOrg: config.ClientAccessRequestsPerOrg}
}
func (s *Service) Create(ctx context.Context, environment identity.EnvironmentID, input oauth.Registration) (identity.ClientID, string, error) {
	if err := input.Validate(); err != nil {
		return identity.ClientID{}, "", err
	}
	input.ClientAuth = input.ClientAuth.WithDefaults(input.Public)
	if input.AccessTokenFormat == "" {
		input.AccessTokenFormat = oauth.TokenFormatJWT
	}
	if err := identity.ValidateRedirects(input.Redirects); err != nil {
		return identity.ClientID{}, "", err
	}
	if err := validatePostLogout(input.PostLogoutRedirects); err != nil {
		return identity.ClientID{}, "", err
	}
	input.AllowedOrigins, _ = oauth.Origins(input.AllowedOrigins) // checked by Validate
	raw := ""
	hash := []byte{}
	var err error
	if !input.Public {
		raw, _, err = s.secrets.Generate("ik_client_")
		if err != nil {
			return identity.ClientID{}, "", err
		}
		encoded, hashErr := s.passwords.Hash(raw)
		hash = []byte(encoded)
		err = hashErr
		if err != nil {
			return identity.ClientID{}, "", err
		}
	}
	id := identity.NewClientID()
	return id, raw, s.repository.Create(ctx, environment, id, input, hash)
}
func (s *Service) Update(ctx context.Context, m oauth.Mutation, id identity.ClientID, input oauth.ClientUpdate) error {
	if id.IsZero() {
		return errx.Validation("invalid client")
	}
	if err := input.Validate(); err != nil {
		return err
	}
	if input.Redirects != nil {
		if err := identity.ValidateRedirects(*input.Redirects); err != nil {
			return err
		}
	}
	if input.PostLogoutRedirects != nil {
		if err := validatePostLogout(*input.PostLogoutRedirects); err != nil {
			return err
		}
	}
	if input.AllowedOrigins != nil {
		origins, _ := oauth.Origins(*input.AllowedOrigins) // checked by Validate
		input.AllowedOrigins = &origins
	}
	var auth *identity.ClientAuth
	current, err := s.editable(ctx, m.Environment, id)
	if err != nil {
		return err
	}
	if input.Authentication() || input.GrantTypes != nil || input.HostedLogin != nil || input.Redirects != nil {
		if err = oauth.ValidateClientShape(update(current.GrantTypes, input.GrantTypes), update(current.HostedLogin, input.HostedLogin), update(current.Redirects, input.Redirects)); err != nil {
			return err
		}
		if err = oauth.ValidateExchangeClient(update(current.GrantTypes, input.GrantTypes), current.Public); err != nil {
			return err
		}
	}
	if input.Authentication() {
		next := input.Apply(current.ClientAuth)
		if err := next.Validate(current.Public); err != nil {
			return err
		}
		auth = &next
	}
	return s.repository.Update(ctx, m, id, input, auth)
}

// update is value changed to *next when given.
func update[T any](value T, next *T) T {
	if next != nil {
		return *next
	}
	return value
}

// validatePostLogout checks post_logout_redirect_uris like redirect URIs.
func validatePostLogout(values []string) error {
	if identity.ValidateRedirects(values) != nil {
		return errx.Validation("post_logout_redirect_uris must be absolute HTTPS URLs (http only for localhost, 127.0.0.1 or [::1]) without credentials or fragments")
	}
	return nil
}

// Logout ends the session an ID token names and resolves where the
// browser returns. A post_logout_redirect_uri needs a client (client_id
// or the hint's audience) that registered it exactly.
func (s *Service) Logout(ctx context.Context, input oauth.Logout) (string, identity.EnvironmentID, identity.SessionID, error) {
	var hint oauth.IDTokenHint
	var environment identity.EnvironmentID
	if input.Hint != "" {
		var err error
		if hint, err = s.hints.Parse(ctx, input.Hint); err != nil {
			return "", identity.EnvironmentID{}, identity.SessionID{}, err
		}
		if !input.Client.IsZero() && !hint.Names(input.Client) {
			return "", identity.EnvironmentID{}, identity.SessionID{}, errx.Validation("client_id does not match id_token_hint")
		}
		if input.Client.IsZero() {
			input.Client = hint.Client()
		}
		environment = hint.Environment
	}
	if input.Redirect != "" || (!input.Client.IsZero() && environment.IsZero()) {
		if input.Client.IsZero() {
			return "", identity.EnvironmentID{}, identity.SessionID{}, errx.Validation("post_logout_redirect_uri requires client_id or id_token_hint")
		}
		client, err := s.Client(ctx, input.Client)
		if err != nil {
			return "", identity.EnvironmentID{}, identity.SessionID{}, errx.Validation("unknown client_id")
		}
		if !environment.IsZero() && client.Environment != environment {
			return "", identity.EnvironmentID{}, identity.SessionID{}, errx.Validation("client_id does not match id_token_hint")
		}
		environment = client.Environment
		if input.Redirect != "" && !slices.Contains(client.PostLogoutRedirects, input.Redirect) {
			return "", identity.EnvironmentID{}, identity.SessionID{}, oauth.ErrUnregisteredLogoutRedirect()
		}
	}
	var ended identity.SessionID
	if !hint.Session.IsZero() {
		m := oauth.Mutation{Environment: hint.Environment, Actor: hint.Subject.String(), Action: "oauth.logout", Target: hint.Session.String()}
		if _, err := s.repository.EndSession(ctx, m, hint.Subject, hint.Session); err != nil {
			return "", identity.EnvironmentID{}, identity.SessionID{}, err
		}
		ended = hint.Session
	}
	return input.Back(), environment, ended, nil
}
func (s *Service) Disable(ctx context.Context, m oauth.Mutation, id identity.ClientID) error {
	if id.IsZero() {
		return errx.Validation("invalid client")
	}
	if _, err := s.editable(ctx, m.Environment, id); err != nil {
		return err
	}
	return s.repository.Disable(ctx, m, id)
}

// editable finds a client operators may change: not one IAMKit registers
// itself (the organization admin portal's, turned on and off on its own).
func (s *Service) editable(ctx context.Context, environment identity.EnvironmentID, id identity.ClientID) (oauth.ClientView, error) {
	current, err := s.repository.Find(ctx, environment, id)
	if err != nil {
		return current, err
	}
	if current.System != "" {
		return current, errx.Conflict("this client is managed by IAMKit; use the organization admin portal settings")
	}
	return current, nil
}
func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, filter oauth.ClientFilter, page query.Pagination) (query.Paginated[oauth.ClientView], error) {
	out, err := s.repository.List(ctx, environment, filter, page)
	for i := range out.Items {
		out.Items[i] = out.Items[i].Warned()
	}
	return out, err
}
func (s *Service) Find(ctx context.Context, environment identity.EnvironmentID, id identity.ClientID) (oauth.ClientView, error) {
	if id.IsZero() {
		return oauth.ClientView{}, errx.Validation("invalid client")
	}
	out, err := s.repository.Find(ctx, environment, id)
	if err != nil {
		return oauth.ClientView{}, err
	}
	return out.Warned(), nil
}

// OriginAllowed reports whether a live client allows origin; a value that
// is not a valid origin never is.
func (s *Service) OriginAllowed(ctx context.Context, origin string) (bool, error) {
	normalized, err := oauth.Origins([]string{origin})
	if err != nil {
		return false, nil
	}
	return s.repository.OriginAllowed(ctx, normalized[0])
}
func (s *Service) Client(ctx context.Context, id identity.ClientID) (*oauth.Client, error) {
	return s.lookup(ctx, id, s.repository.FindActive)
}

// Holder: see oauth.Flows.
func (s *Service) Holder(ctx context.Context, id identity.ClientID) (*oauth.Client, error) {
	return s.lookup(ctx, id, s.repository.FindHolder)
}

func (s *Service) lookup(ctx context.Context, id identity.ClientID, find func(context.Context, identity.EnvironmentID, identity.ClientID) (*oauth.Client, error)) (*oauth.Client, error) {
	if id.IsZero() {
		return nil, errx.Validation("invalid client")
	}
	environment, err := s.repository.Environment(ctx, id)
	if err != nil {
		return nil, err
	}
	client, err := find(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	return s.gated(ctx, client)
}

// gated marks an external client Disabled while the environment's
// client_metadata_documents feature is off, so every use of the client
// (refresh, introspection, opaque tokens, tickets) is refused at once
// without waiting for the reconcile job (M-2).
func (s *Service) gated(ctx context.Context, client *oauth.Client) (*oauth.Client, error) {
	if client == nil || !client.External() {
		return client, nil
	}
	on, err := s.sourceOn(ctx, client.Environment, client.Source)
	if err != nil {
		return nil, err
	}
	client.Disabled = client.Disabled || !on
	return client, nil
}

// AccessTokenClient is the live client an opaque access token was issued
// to (key: the stored signature hash).
func (s *Service) AccessTokenClient(ctx context.Context, key string) (*oauth.Client, error) {
	if key == "" {
		return nil, errx.Unauthorized("invalid OAuth token")
	}
	environment, id, err := s.repository.AccessTokenClient(ctx, key)
	if err != nil {
		return nil, err
	}
	client, err := s.repository.FindHolder(ctx, environment, id)
	if err != nil {
		return nil, err
	}
	return s.gated(ctx, client)
}
func (s *Service) Start(ctx context.Context, client *oauth.Client, form string) (string, string, error) {
	ticket, hash, err := s.secrets.Generate("ik_authorize_")
	if err != nil {
		return "", "", err
	}
	binding, bindingHash, err := s.secrets.Generate("ik_browser_")
	if err != nil {
		return "", "", err
	}
	return ticket, binding, s.repository.SaveTicket(ctx, hash, bindingHash, client, form)
}

func (s *Service) Pending(ctx context.Context, ticket, binding string) (oauth.Pending, error) {
	if !strings.HasPrefix(ticket, "ik_authorize_") || binding == "" {
		return oauth.Pending{}, invalidTicket()
	}
	row, err := s.repository.PendingTicket(ctx, s.secrets.Hash(ticket))
	if err != nil {
		return oauth.Pending{}, invalidTicket()
	}
	if subtle.ConstantTimeCompare(row.Binding, s.secrets.Hash(binding)) != 1 {
		return oauth.Pending{}, invalidTicket()
	}
	client, err := s.TicketClient(ctx, row)
	if err != nil {
		return oauth.Pending{}, err
	}
	return oauth.Pending{Client: client, Form: row.Form, Ticket: row}, nil
}

func invalidTicket() error {
	return errx.Unauthorized("invalid authorization ticket or browser binding")
}

func (s *Service) Complete(ctx context.Context, ticket, binding string, approve bool, prepare func(oauth.Ticket, *oauth.Client, oauth.Authorization) error) error {
	if !approve {
		return errx.Forbidden("authorization was not approved")
	}
	// Before the transaction (M-5): peek the ticket without a lock and
	// resolve its client, which may read the client's document and persist
	// the client. Nothing here holds the ticket or a connection.
	hash := s.secrets.Hash(ticket)
	peek, err := s.repository.PendingTicket(ctx, hash)
	if err != nil {
		return invalidTicket()
	}
	// The browser binding before anything else (N-3): a ticket without its
	// browser reads no document and persists nothing. Checked again on the
	// locked row below.
	if subtle.ConstantTimeCompare(peek.Binding, s.secrets.Hash(binding)) != 1 {
		return invalidTicket()
	}
	client, err := s.TicketClient(ctx, peek)
	if err != nil {
		// A refusal (blocked, budget, bad document) keeps its own message
		// for the page (N-11); only an unexpected failure is wrapped.
		var known *errx.Error
		if errx.As(err, &known) {
			return err
		}
		return errx.Wrap(err, "OAuth client lookup failed", errx.TypeInternal)
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Lock order (N-1): the client row before the ticket, as block, demote
	// and forget take them (client, then its tickets). Database reads only:
	// an external client blocked, or whose approval ended, since it was
	// resolved is refused here, and its row is held against a block until
	// this transaction ends. A client not persisted yet (ID zero) is
	// pending, which prepare refuses.
	var state *oauth.AdmissionState
	if client.External() && !client.ID.IsZero() {
		got, err := tx.Admission(ctx, client.ID)
		if err != nil {
			return err
		}
		state = &got
	}
	row, err := tx.Ticket(ctx, hash)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(row.Binding, s.secrets.Hash(binding)) != 1 {
		return invalidTicket()
	}
	if !sameClient(row, peek) {
		return invalidTicket()
	}
	if state != nil && !state.Admitted(time.Now()) {
		if state.Disabled {
			return oauth.Refused(oauth.ErrClientDisabled(), client)
		}
		if state.Admission == oauth.AdmissionBlocked {
			return oauth.Refused(oauth.ErrClientBlocked(), client)
		}
		// Admitted when it was resolved, pending now: refused here. One
		// that was pending already is refused by prepare, which records
		// that this user asked for it.
		if client.Admitted(time.Now()) {
			return oauth.Refused(oauth.ErrAdmissionPending(), client)
		}
	}
	if err = prepare(row, client, tx); err != nil {
		return err
	}
	if err = tx.Consume(ctx, hash); err != nil {
		return err
	}
	return tx.Commit()
}

// sameClient reports whether the locked ticket names the client the peek
// resolved (the ticket row never changes, but the check keeps Complete
// from spending a ticket for a client it did not resolve).
func sameClient(row, peek oauth.Ticket) bool {
	if row.Client != peek.Client || row.Protected != peek.Protected {
		return false
	}
	if (row.External == nil) != (peek.External == nil) {
		return false
	}
	return row.External == nil || *row.External == *peek.External
}

func (s *Service) Access(ctx context.Context, client *oauth.Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error) {
	if session.IsZero() || organization.IsZero() {
		return authentication.Access{}, errx.Unauthorized("invalid session context")
	}
	return s.repository.Access(ctx, client, subject, session, organization)
}
