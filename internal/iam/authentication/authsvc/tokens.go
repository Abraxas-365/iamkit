package authsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Tokens struct {
	repository authentication.TokenRepository
	codec      authentication.TokenCodec
	secrets    authentication.Secrets
}

func NewTokens(r authentication.TokenRepository, c authentication.TokenCodec, s authentication.Secrets) *Tokens {
	return &Tokens{r, c, s}
}
func (s *Tokens) KeyID() string { return s.codec.KeyID() }
func (s *Tokens) JWKS() any     { return s.codec.JWKS() }
func (s *Tokens) Issue(input authentication.Token, audience string) (string, error) {
	now := time.Now()
	input.ID = uuid.NewString()
	input.Audience = []string{audience}
	input.IssuedAt = now.Unix()
	input.NotBefore = now.Unix()
	input.ExpiresAt = now.Add(15 * time.Minute).Unix()
	return s.codec.Sign(input)
}
func (s *Tokens) Validate(ctx context.Context, raw, environment, audience string) (authentication.Token, error) {
	var out authentication.Token
	if !identity.ValidID(environment) || audience == "" {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	out, err := s.codec.Verify(raw, audience)
	if err != nil {
		return out, err
	}
	if out.EnvironmentID != environment || !identity.ValidID(out.Subject) || !identity.ValidID(out.ApplicationID) || !identity.ValidID(out.ResourceID) {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	if !(out.Purpose == "application" && identity.ValidID(out.SessionID) && identity.ValidID(out.OrganizationID)) && !(out.Purpose == "machine" && out.SessionID == "" && out.OrganizationID == "") {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	current, err := s.repository.Current(ctx, out, audience)
	if err != nil || !identity.Subset(out.Permissions, current) {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	if out.ActorID != "" {
		active, err := s.repository.ActorActive(ctx, out)
		if err != nil || !active {
			return out, errx.Unauthorized("impersonation actor disabled")
		}
	}
	if out.OAuthClientID != "" {
		parts := strings.Split(raw, ".")
		if len(parts) != 3 || !identity.ValidID(out.OAuthClientID) {
			return out, errx.Unauthorized("invalid OAuth token")
		}
		active, err := s.repository.OAuthActive(ctx, out, parts[2])
		if err != nil || !active {
			return out, errx.Unauthorized("OAuth token revoked")
		}
	}
	return out, nil
}
func (s *Tokens) Machine(ctx context.Context, raw string) (string, error) {
	if !strings.HasPrefix(raw, "ik_svc_") {
		return "", errx.Unauthorized("invalid credentials or access token")
	}
	token, audience, err := s.repository.Machine(ctx, s.secrets.Hash(raw))
	if err != nil {
		return "", err
	}
	return s.Issue(token, audience)
}
func (s *Tokens) Logout(ctx context.Context, token authentication.Token) error {
	if token.Purpose != "application" {
		return errx.Forbidden("insufficient permissions")
	}
	return s.repository.Revoke(ctx, token.EnvironmentID, token.SessionID)
}
func (s *Tokens) Profile(ctx context.Context, token authentication.Token) (authentication.Profile, error) {
	if token.Purpose != "application" {
		return authentication.Profile{}, errx.Forbidden("user session required")
	}
	return s.repository.Profile(ctx, token)
}
func (s *Tokens) Organizations(ctx context.Context, token authentication.Token) ([]authentication.Organization, error) {
	if token.Purpose != "application" {
		return nil, errx.Forbidden("user session required")
	}
	return s.repository.Organizations(ctx, token)
}
func (s *Tokens) UpdateProfile(ctx context.Context, token authentication.Token, name string) error {
	if token.Purpose != "application" || token.ActorID != "" {
		return errx.Forbidden("non-impersonated user session required")
	}
	if strings.TrimSpace(name) == "" {
		return errx.Validation("name required")
	}
	return s.repository.UpdateProfile(ctx, token, name)
}
func (s *Tokens) AddMember(ctx context.Context, token authentication.Token, user string) error {
	if token.Purpose != "application" || !identity.ValidID(user) {
		return errx.Forbidden("insufficient permissions")
	}
	return s.repository.AddMember(ctx, token, user)
}
