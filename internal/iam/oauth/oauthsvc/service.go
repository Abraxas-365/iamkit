package oauthsvc

import (
	"context"
	"crypto/subtle"
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
}

func New(r oauth.Repository, s oauth.Secrets, p oauth.Passwords) *Service { return &Service{r, s, p} }
func (s *Service) Create(ctx context.Context, environment identity.EnvironmentID, input oauth.Registration) (identity.ClientID, string, error) {
	if err := input.Validate(); err != nil {
		return identity.ClientID{}, "", err
	}
	if err := identity.ValidateRedirects(input.Redirects); err != nil {
		return identity.ClientID{}, "", err
	}
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
func (s *Service) Disable(ctx context.Context, m oauth.Mutation, id identity.ClientID) error {
	if id.IsZero() {
		return errx.Validation("invalid client")
	}
	return s.repository.Disable(ctx, m, id)
}
func (s *Service) List(ctx context.Context, environment identity.EnvironmentID, page query.Pagination) (query.Paginated[oauth.ClientView], error) {
	return s.repository.List(ctx, environment, page)
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
	return nil
}
func ValidateLogin(access authentication.Token, client *oauth.Client) error {
	if !access.ActorID.IsZero() || access.Purpose != "application" || access.ApplicationID != client.Application || access.ResourceID != client.Resource {
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
