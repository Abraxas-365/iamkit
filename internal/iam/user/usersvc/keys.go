package usersvc

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Keys implements machine users' keys for the JWT-bearer grant.
type Keys struct {
	repository user.KeyRepository
	pairs      user.KeyPairs
}

func NewKeys(repository user.KeyRepository, pairs user.KeyPairs) *Keys {
	return &Keys{repository: repository, pairs: pairs}
}

var _ user.KeyCommands = (*Keys)(nil)
var _ user.KeyQueries = (*Keys)(nil)

func (s *Keys) AddKey(ctx context.Context, m user.Mutation, id identity.UserID, input user.NewKey) (user.IssuedKey, error) {
	if id.IsZero() {
		return user.IssuedKey{}, errx.NotFound("user not found")
	}
	if err := input.Validate(); err != nil {
		return user.IssuedKey{}, err
	}
	key := user.Key{ID: identity.NewUserKeyID(), User: id, ExpiresAt: time.Now().Add(input.TTL()).UTC().Truncate(time.Second)}
	var private string
	if input.Uploaded() {
		parsed, _ := identity.ParsePublicJWK(input.PublicKey) // validated
		public, err := identity.MarshalPublicJWK(parsed)
		if err != nil {
			return user.IssuedKey{}, err
		}
		key.PublicKey = public
	} else {
		public, pem, err := s.pairs.Generate()
		if err != nil {
			return user.IssuedKey{}, err
		}
		key.PublicKey, private = public, pem
	}
	m.Action = user.ActionKeyAdded
	m.Target = key.ID.String()
	stored, err := s.repository.AddKey(ctx, m, key)
	if err != nil {
		return user.IssuedKey{}, err
	}
	return user.IssuedKey{Key: stored, PrivateKey: private}, nil
}

func (s *Keys) RemoveKey(ctx context.Context, m user.Mutation, id identity.UserID, key identity.UserKeyID) error {
	if id.IsZero() || key.IsZero() {
		return errx.NotFound("key not found")
	}
	m.Action = user.ActionKeyRemoved
	m.Target = key.String()
	return s.repository.RemoveKey(ctx, m, id, key)
}

func (s *Keys) Keys(ctx context.Context, environment identity.EnvironmentID, id identity.UserID, page query.Pagination) (query.Paginated[user.Key], error) {
	if id.IsZero() {
		return query.Paginated[user.Key]{}, errx.NotFound("user not found")
	}
	return s.repository.Keys(ctx, environment, id, page)
}
