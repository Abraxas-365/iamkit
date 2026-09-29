package oauthfosite

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

// Signer signs an environment's access and ID tokens with the key the
// keyring names for it (its active key, else the deployment key) and
// writes that key's kid; it verifies by kid, refusing a key another
// environment owns.
type Signer struct {
	Keys        signing.Keyring
	Environment identity.EnvironmentID
}

var _ jwt.Signer = Signer{}

func (s Signer) Generate(ctx context.Context, claims jwt.MapClaims, header jwt.Mapper) (string, string, error) {
	key, err := s.Keys.Signer(ctx, s.Environment)
	if err != nil {
		return "", "", err
	}
	header.Add("kid", key.ID)
	return (&jwt.DefaultSigner{GetPrivateKey: func(context.Context) (any, error) { return key.Private, nil }}).Generate(ctx, claims, header)
}

func (s Signer) Validate(ctx context.Context, token string) (string, error) {
	if _, err := s.Decode(ctx, token); err != nil {
		return "", err
	}
	return s.GetSignature(ctx, token)
}

func (s Signer) Decode(ctx context.Context, token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		if string(t.Method) != signing.Algorithm {
			return nil, errors.New("unexpected signing method")
		}
		kid, _ := t.Header["kid"].(string)
		key, err := s.Keys.Verifier(ctx, kid)
		if err != nil || !key.Allows(s.Environment) {
			return nil, fosite.ErrTokenSignatureMismatch
		}
		return key.Public, nil
	})
}

func (Signer) GetSignature(_ context.Context, token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("header, body and signature must all be set")
	}
	return parts[2], nil
}

func (Signer) Hash(_ context.Context, in []byte) ([]byte, error) {
	sum := sha256.Sum256(in)
	return sum[:], nil
}

func (Signer) GetSigningMethodLength(context.Context) int { return sha256.Size }
