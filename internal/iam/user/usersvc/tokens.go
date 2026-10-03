package usersvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// AccessTokens implements the personal access tokens of machine users.
type AccessTokens struct {
	repository user.AccessTokenRepository
	secrets    user.Secrets
}

func NewAccessTokens(repository user.AccessTokenRepository, secrets user.Secrets) *AccessTokens {
	return &AccessTokens{repository: repository, secrets: secrets}
}

var _ user.AccessTokenCommands = (*AccessTokens)(nil)
var _ user.AccessTokenQueries = (*AccessTokens)(nil)

func (s *AccessTokens) CreateAccessToken(ctx context.Context, m user.Mutation, id identity.UserID, input user.NewAccessToken) (user.IssuedAccessToken, error) {
	if id.IsZero() {
		return user.IssuedAccessToken{}, errx.NotFound("user not found")
	}
	if err := input.Validate(); err != nil {
		return user.IssuedAccessToken{}, err
	}
	ttl, _ := identity.ParseTTL(input.ExpiresIn) // validated
	raw, hash, err := s.secrets.Generate(user.AccessTokenPrefix)
	if err != nil {
		return user.IssuedAccessToken{}, err
	}
	token := user.AccessToken{
		ID:           identity.NewAccessTokenID(),
		User:         id,
		Organization: input.Organization,
		Application:  input.Application,
		Resource:     input.Resource,
		Name:         strings.TrimSpace(input.Name),
		ExpiresAt:    time.Now().Add(ttl).UTC().Truncate(time.Second),
	}
	m.Action = user.ActionAccessTokenCreated
	m.Target = credentialTarget(id, token.ID.String(), "access_token_id")
	stored, err := s.repository.CreateAccessToken(ctx, m, token, hash)
	if err != nil {
		return user.IssuedAccessToken{}, err
	}
	return user.IssuedAccessToken{AccessToken: stored, Token: raw}, nil
}

func (s *AccessTokens) RevokeAccessToken(ctx context.Context, m user.Mutation, id identity.UserID, token identity.AccessTokenID) error {
	if id.IsZero() || token.IsZero() {
		return errx.NotFound("access token not found")
	}
	m.Action = user.ActionAccessTokenRevoked
	m.Target = credentialTarget(id, token.String(), "access_token_id")
	return s.repository.RevokeAccessToken(ctx, m, id, token)
}

func (s *AccessTokens) AccessTokens(ctx context.Context, environment identity.EnvironmentID, id identity.UserID, page query.Pagination) (query.Paginated[user.AccessToken], error) {
	if id.IsZero() {
		return query.Paginated[user.AccessToken]{}, errx.NotFound("user not found")
	}
	return s.repository.AccessTokens(ctx, environment, id, page)
}

// credentialTarget is the audit target of a machine credential: its id,
// with the credential id and the user (the event subject) as event data.
// The user's id comes last, so the activity log names the machine user.
func credentialTarget(id identity.UserID, credential, key string) string {
	return credential + "?" + key + "=" + credential + "&user=" + id.String()
}
