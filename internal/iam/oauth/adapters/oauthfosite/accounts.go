package oauthfosite

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
	"github.com/ory/fosite"
)

// Accounts authenticates service accounts at /oauth/token
// (client_credentials) with fosite's client authentication: the account's
// secret (HTTP Basic or form body) or a private_key_jwt assertion. Service
// accounts are not fosite clients of any provider; this is only the
// authentication step, the token is the machine token.
type Accounts struct {
	provider *fosite.Fosite
}

// NewAccounts reads accounts from repository and client key URLs through
// fetcher; assertions must name issuer or its token endpoint as audience.
func NewAccounts(db *sqlx.DB, repository oauth.AccountRepository, issuer string, fetcher fosite.JWKSFetcherStrategy) *Accounts {
	cfg := &fosite.Config{ClientSecretsHasher: digest{}, JWKSFetcherStrategy: fetcher, TokenURL: issuer + "/oauth/token"}
	return &Accounts{provider: &fosite.Fosite{Store: accountStore{repository: repository, assertions: Assertions{db}}, Config: tokenURLs{Config: cfg, issuer: issuer}}}
}

// Authenticate returns the authenticated account of a token request whose
// form is parsed and whose client_id (Basic, form or assertion sub) names
// account. Failures are 401 (invalid_client) unless the lookup itself
// failed (500).
func (a *Accounts) Authenticate(ctx context.Context, account identity.AccountID, r *http.Request) (identity.AccountID, error) {
	ctx = context.WithValue(ctx, ClientContextKey{}, "account:"+account.String())
	client, err := a.provider.AuthenticateClient(ctx, r, r.PostForm)
	if err != nil {
		var custom *errx.Error
		if errors.As(err, &custom) && custom != nil && custom.HTTPStatus >= 500 {
			return identity.AccountID{}, custom
		}
		if errors.Is(err, fosite.ErrServerError) {
			return identity.AccountID{}, errx.Internal("client authentication failed")
		}
		return identity.AccountID{}, errx.Unauthorized("invalid client")
	}
	if client.GetID() != account.String() {
		return identity.AccountID{}, errx.Unauthorized("invalid client")
	}
	return account, nil
}

type accountStore struct {
	repository oauth.AccountRepository
	assertions Assertions
}

func (s accountStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	accountID, err := identity.ParseAccountID(id)
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	account, err := s.repository.FindAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	return authClient(&fosite.DefaultClient{ID: account.ID.String(), Secret: account.Secret, GrantTypes: []string{"client_credentials"}}, account.Auth), nil
}
func (s accountStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return s.assertions.Valid(ctx, jti)
}
func (s accountStore) SetClientAssertionJWT(ctx context.Context, jti string, expires time.Time) error {
	return s.assertions.Use(ctx, jti, expires)
}

// AssertionSubject is the unverified sub of a client_assertion: the
// client_id when the request does not repeat it (RFC 7523 §3). The
// assertion is verified afterwards against that client's keys.
func AssertionSubject(assertion string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Subject
}
