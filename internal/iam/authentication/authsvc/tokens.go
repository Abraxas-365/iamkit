package authsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Tokens struct {
	repository authentication.TokenRepository
	codec      authentication.TokenCodec
	secrets    authentication.Secrets
	oauth      authentication.OAuthTokens
}

func NewTokens(r authentication.TokenRepository, c authentication.TokenCodec, s authentication.Secrets, o authentication.OAuthTokens) *Tokens {
	return &Tokens{r, c, s, o}
}
func (s *Tokens) KeyID() string { return s.codec.KeyID() }
func (s *Tokens) JWKS() any     { return s.codec.JWKS() }
func (s *Tokens) Issue(input authentication.Token, audience string) (string, error) {
	now := time.Now()
	input.ID = uuid.NewString()
	input.Audience = []string{audience}
	input.IssuedAt = now.Unix()
	input.NotBefore = now.Unix()
	input.ExpiresAt = now.Add(config.TokenTTL).Unix()
	return s.codec.Sign(input)
}
func (s *Tokens) Validate(ctx context.Context, raw string, audience string, environment identity.EnvironmentID) (authentication.Token, error) {
	var out authentication.Token
	if environment.IsZero() || audience == "" {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	out, err := s.codec.Verify(raw, audience)
	if err != nil {
		return out, err
	}
	if out.EnvironmentID != environment || out.Subject.IsZero() || out.ApplicationID.IsZero() || out.ResourceID.IsZero() {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	if !(out.Purpose == "application" && !out.SessionID.IsZero() && !out.OrganizationID.IsZero()) && !(out.Purpose == "machine" && out.SessionID.IsZero() && out.OrganizationID.IsZero()) {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	current, err := s.repository.Current(ctx, out, environment)
	if err != nil || !identity.Subset(out.Permissions, current) {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	if !out.ActorID.IsZero() {
		active, err := s.repository.ActorActive(ctx, out)
		if err != nil || !active {
			return out, errx.Unauthorized("impersonation actor disabled")
		}
	}
	return out, s.checkOAuth(ctx, raw, out)
}

func (s *Tokens) ValidateSelf(ctx context.Context, raw string) (authentication.Token, error) {
	out, err := s.codec.VerifySelf(raw)
	if err != nil {
		return out, err
	}
	if out.EnvironmentID.IsZero() || out.Subject.IsZero() || out.ApplicationID.IsZero() || out.ResourceID.IsZero() {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	if !(out.Purpose == "application" && !out.SessionID.IsZero() && !out.OrganizationID.IsZero()) && !(out.Purpose == "machine" && out.SessionID.IsZero() && out.OrganizationID.IsZero()) {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	audience := ""
	if len(out.Audience) > 0 {
		audience = out.Audience[0]
	}
	if audience == "" {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	current, err := s.repository.Current(ctx, out, out.EnvironmentID)
	if err != nil || !identity.Subset(out.Permissions, current) {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	if !out.ActorID.IsZero() {
		active, err := s.repository.ActorActive(ctx, out)
		if err != nil || !active {
			return out, errx.Unauthorized("impersonation actor disabled")
		}
	}
	return out, s.checkOAuth(ctx, raw, out)
}

// checkOAuth rejects OAuth-issued access tokens whose grant was revoked
// (refresh/code replay, logout) or expired, or whose client was disabled.
// Tokens not issued through OAuth pass through.
func (s *Tokens) checkOAuth(ctx context.Context, raw string, token authentication.Token) error {
	if token.OAuthClientID.IsZero() {
		return nil
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[2] == "" {
		return errx.Unauthorized("invalid OAuth token")
	}
	if s.oauth == nil {
		return errx.Unauthorized("OAuth token revoked")
	}
	active, err := s.oauth.Active(ctx, token.EnvironmentID, token.OAuthClientID, parts[2])
	if err != nil || !active {
		return errx.Unauthorized("OAuth token revoked")
	}
	return nil
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
	if token.Purpose != "application" || !token.ActorID.IsZero() {
		return errx.Forbidden("non-impersonated user session required")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errx.Validation("name is required")
	}
	return s.repository.UpdateProfile(ctx, token, name)
}
func (s *Tokens) AddMember(ctx context.Context, token authentication.Token, user identity.UserID) error {
	if token.Purpose != "application" || token.OrganizationID.IsZero() {
		return errx.Forbidden("insufficient permissions")
	}
	if user.IsZero() {
		return errx.Validation("user_id is required")
	}
	return s.repository.AddMember(ctx, token, user)
}
