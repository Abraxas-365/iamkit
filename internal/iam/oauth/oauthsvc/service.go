package oauthsvc

import (
	"context"
	"crypto/subtle"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Service struct {
	repository oauth.Repository
	secrets    oauth.Secrets
	passwords  oauth.Passwords
	hints      oauth.Hints
}

func New(r oauth.Repository, s oauth.Secrets, p oauth.Passwords, h oauth.Hints) *Service {
	return &Service{r, s, p, h}
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
		return errx.Validation("post_logout_redirect_uris must be absolute HTTPS URLs without credentials or fragments")
	}
	return nil
}

// Logout ends the session an ID token names and resolves where the
// browser returns. A post_logout_redirect_uri needs a client (client_id
// or the hint's audience) that registered it exactly.
func (s *Service) Logout(ctx context.Context, input oauth.Logout) (string, identity.EnvironmentID, error) {
	var hint oauth.IDTokenHint
	var environment identity.EnvironmentID
	if input.Hint != "" {
		var err error
		if hint, err = s.hints.Parse(ctx, input.Hint); err != nil {
			return "", identity.EnvironmentID{}, err
		}
		if !input.Client.IsZero() && !hint.Names(input.Client) {
			return "", identity.EnvironmentID{}, errx.Validation("client_id does not match id_token_hint")
		}
		if input.Client.IsZero() {
			input.Client = hint.Client()
		}
		environment = hint.Environment
	}
	if input.Redirect != "" || (!input.Client.IsZero() && environment.IsZero()) {
		if input.Client.IsZero() {
			return "", identity.EnvironmentID{}, errx.Validation("post_logout_redirect_uri requires client_id or id_token_hint")
		}
		client, err := s.Client(ctx, input.Client)
		if err != nil {
			return "", identity.EnvironmentID{}, errx.Validation("unknown client_id")
		}
		if !environment.IsZero() && client.Environment != environment {
			return "", identity.EnvironmentID{}, errx.Validation("client_id does not match id_token_hint")
		}
		environment = client.Environment
		if input.Redirect != "" && !slices.Contains(client.PostLogoutRedirects, input.Redirect) {
			return "", identity.EnvironmentID{}, oauth.ErrUnregisteredLogoutRedirect()
		}
	}
	if !hint.Session.IsZero() {
		m := oauth.Mutation{Environment: hint.Environment, Actor: hint.Subject.String(), Action: "oauth.logout", Target: hint.Session.String()}
		if _, err := s.repository.EndSession(ctx, m, hint.Subject, hint.Session); err != nil {
			return "", identity.EnvironmentID{}, err
		}
	}
	return input.Back(), environment, nil
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
	return s.repository.List(ctx, environment, filter, page)
}
func (s *Service) Find(ctx context.Context, environment identity.EnvironmentID, id identity.ClientID) (oauth.ClientView, error) {
	if id.IsZero() {
		return oauth.ClientView{}, errx.Validation("invalid client")
	}
	return s.repository.Find(ctx, environment, id)
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
	if id.IsZero() {
		return nil, errx.Validation("invalid client")
	}
	environment, err := s.repository.Environment(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.repository.FindActive(ctx, environment, id)
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
	return s.repository.FindActive(ctx, environment, id)
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
	client, err := s.Client(ctx, row.Client)
	if err != nil {
		return oauth.Pending{}, err
	}
	return oauth.Pending{Client: client, Form: row.Form}, nil
}

func invalidTicket() error {
	return errx.Unauthorized("invalid authorization ticket or browser binding")
}

func (s *Service) Complete(ctx context.Context, ticket, binding string, approve bool, prepare func(oauth.Ticket, oauth.Authorization) error) error {
	if !approve {
		return errx.Forbidden("authorization was not approved")
	}
	tx, err := s.repository.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	row, err := tx.Ticket(ctx, s.secrets.Hash(ticket))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(row.Binding, s.secrets.Hash(binding)) != 1 {
		return errx.Unauthorized("invalid authorization ticket or browser binding")
	}
	if err = prepare(row, tx); err != nil {
		return err
	}
	if err = tx.Consume(ctx, s.secrets.Hash(ticket)); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Service) Access(ctx context.Context, client *oauth.Client, subject identity.UserID, session identity.SessionID, organization identity.OrganizationID) (authentication.Access, error) {
	if session.IsZero() || organization.IsZero() {
		return authentication.Access{}, errx.Unauthorized("invalid session context")
	}
	return s.repository.Access(ctx, client, subject, session, organization)
}
func ValidateAuthorization(issuer string, client *oauth.Client, query map[string][]string) error {
	if !strings.HasPrefix(issuer, "https://") {
		return errx.Validation("OIDC requires HTTPS issuer")
	}
	get := func(key string) string {
		v := query[key]
		if len(v) == 0 {
			return ""
		}
		return v[0]
	}
	if get("prompt") != "" || get("max_age") != "" {
		return errx.Validation("prompt and max_age are not supported by the headless authorization interaction")
	}
	for key, v := range query {
		if len(v) != 1 || key == "request" || key == "request_uri" {
			return errx.Validation("invalid authorization request")
		}
	}
	exact := false
	for _, uri := range client.Redirects {
		if uri == get("redirect_uri") {
			exact = true
		}
	}
	if !exact || get("response_type") != "code" || get("code_challenge_method") != "S256" || get("code_challenge") == "" || get("state") == "" || get("nonce") == "" || (get("response_mode") != "" && get("response_mode") != "query") {
		return errx.Validation("code, exact redirect, S256, state and nonce required")
	}
	_, err := oauth.OrganizationHint(query)
	return err
}
func ValidateLogin(access authentication.Token, client *oauth.Client) error {
	if access.Impersonated() || access.Purpose != "application" || access.ApplicationID != client.Application || access.ResourceID != client.Resource {
		return errx.Forbidden("login does not match client")
	}
	return nil
}
func ValidateSession(deadline time.Time) error {
	if !deadline.After(time.Now()) {
		return errx.Unauthorized("session expired")
	}
	return nil
}
