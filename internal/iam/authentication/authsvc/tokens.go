package authsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
)

type Tokens struct {
	repository authentication.TokenRepository
	codec      authentication.TokenCodec
	secrets    authentication.Secrets
	oauth      authentication.OAuthTokens
	usage      authentication.Usage
}

func NewTokens(r authentication.TokenRepository, c authentication.TokenCodec, s authentication.Secrets, o authentication.OAuthTokens) *Tokens {
	return &Tokens{repository: r, codec: c, secrets: s, oauth: o}
}

// SetUsage counts issued access tokens.
func (s *Tokens) SetUsage(u authentication.Usage)       { s.usage = u }
func (s *Tokens) JWKS(ctx context.Context) (any, error) { return s.codec.JWKS(ctx) }
func (s *Tokens) Issue(ctx context.Context, input authentication.Token, audience string) (string, error) {
	now := time.Now()
	input.ID = uuid.NewString()
	input.Audience = []string{audience}
	input.IssuedAt = now.Unix()
	input.NotBefore = now.Unix()
	input.ExpiresAt = now.Add(config.TokenTTL).Unix()
	raw, err := s.codec.Sign(ctx, input)
	if err == nil && s.usage != nil {
		s.usage.Count(ctx, input.EnvironmentID, usage.MetricTokens, 1)
	}
	return raw, err
}
func (s *Tokens) Validate(ctx context.Context, raw string, audience string, environment identity.EnvironmentID) (authentication.Token, error) {
	var out authentication.Token
	if environment.IsZero() || audience == "" {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	if strings.HasPrefix(raw, authentication.AccessTokenPrefix) {
		out, err := s.ValidateAccessToken(ctx, raw)
		if errx.IsServerError(err) {
			return authentication.Token{}, err
		}
		if err != nil || out.EnvironmentID != environment || out.Audience[0] != audience {
			return authentication.Token{}, errx.Unauthorized("invalid credentials or access token")
		}
		return out, nil
	}
	out, err := s.codec.Verify(ctx, raw, audience)
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
	if errx.IsServerError(err) {
		return out, err
	}
	if err != nil || !identity.Subset(out.Permissions, current) {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	if out.Impersonated() {
		active, err := s.repository.ActorActive(ctx, out)
		if errx.IsServerError(err) {
			return out, err
		}
		if err != nil || !active {
			return out, errx.Unauthorized("impersonation actor disabled")
		}
	}
	return out, s.checkOAuth(ctx, raw, out)
}

func (s *Tokens) ValidateSelf(ctx context.Context, raw string) (authentication.Token, error) {
	if strings.HasPrefix(raw, authentication.AccessTokenPrefix) {
		return s.ValidateAccessToken(ctx, raw)
	}
	out, err := s.codec.VerifySelf(ctx, raw)
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
	if errx.IsServerError(err) {
		return out, err
	}
	if err != nil || !identity.Subset(out.Permissions, current) {
		return out, errx.Unauthorized("invalid credentials or access token")
	}
	if out.Impersonated() {
		active, err := s.repository.ActorActive(ctx, out)
		if errx.IsServerError(err) {
			return out, err
		}
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
	if errx.IsServerError(err) {
		return err
	}
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
	return s.Issue(ctx, token, audience)
}
func (s *Tokens) MachineAccount(ctx context.Context, account identity.AccountID) (string, error) {
	token, audience, err := s.repository.MachineAccount(ctx, account)
	if err != nil {
		return "", err
	}
	return s.Issue(ctx, token, audience)
}

// ValidateAccessToken resolves a personal access token used as a bearer.
func (s *Tokens) ValidateAccessToken(ctx context.Context, raw string) (authentication.Token, error) {
	if !strings.HasPrefix(raw, authentication.AccessTokenPrefix) {
		return authentication.Token{}, errx.Unauthorized("invalid credentials or access token")
	}
	pat, err := s.repository.AccessToken(ctx, s.secrets.Hash(raw))
	if err != nil {
		return authentication.Token{}, err
	}
	return pat.Token, nil
}

// ExchangeAccessToken issues an application access token for a personal
// access token. Its session is shared by the token's exchanges while it
// lasts (at most config.SessionTTL, never past the token's expiry), so
// frequent exchanges do not pile up sessions.
func (s *Tokens) ExchangeAccessToken(ctx context.Context, raw string) (string, error) {
	if !strings.HasPrefix(raw, authentication.AccessTokenPrefix) {
		return "", errx.Unauthorized("invalid credentials or access token")
	}
	pat, err := s.repository.AccessToken(ctx, s.secrets.Hash(raw))
	if err != nil {
		return "", err
	}
	now := time.Now()
	expires := now.Add(config.SessionTTL)
	if pat.Expires.Before(expires) {
		expires = pat.Expires
	}
	session, err := s.repository.AccessTokenSession(ctx, pat, identity.NewSessionID(), now.Add(config.TokenTTL), expires)
	if err != nil {
		return "", err
	}
	token := pat.Token
	token.Purpose = authentication.PurposeApplication
	token.SessionID = session
	token.AuthTime = now.Unix()
	return s.Issue(ctx, token, pat.Audience)
}

// KeyGrant answers a machine user's RFC 7523 JWT-bearer assertion with an
// application access token on a session opened with the key.
func (s *Tokens) KeyGrant(ctx context.Context, assertion string, boundary authentication.Context) (string, error) {
	id, err := s.codec.AssertionKey(assertion)
	if err != nil {
		return "", err
	}
	key, err := s.repository.MachineKey(ctx, id)
	if err != nil {
		return "", err
	}
	verified, err := s.codec.VerifyAssertion(ctx, assertion, key)
	if err != nil {
		return "", err
	}
	// The key names the environment; a boundary elsewhere is no match.
	if boundary.EnvironmentID.IsZero() {
		boundary.EnvironmentID = key.Environment
	}
	if boundary.EnvironmentID != key.Environment {
		return "", errx.Unauthorized("invalid credentials or access token")
	}
	now := time.Now()
	expires := now.Add(config.SessionTTL)
	if key.Expires.Before(expires) {
		expires = key.Expires
	}
	grant := authentication.KeyGrant{Key: key, Boundary: boundary, Assertion: verified}
	session, err := s.repository.KeySession(ctx, grant, identity.NewSessionID(), now.Add(config.TokenTTL), expires)
	if err != nil {
		return "", err
	}
	token := authentication.Token{
		Access:    identity.Access{EnvironmentID: boundary.EnvironmentID, OrganizationID: boundary.OrganizationID, ApplicationID: boundary.ApplicationID, ResourceID: boundary.ResourceID, Permissions: session.Permissions},
		Purpose:   authentication.PurposeApplication,
		SessionID: session.Session,
		Subject:   key.User,
		AMR:       []string{authentication.AMRKey},
		AuthTime:  session.Authenticated.Unix(),
	}
	return s.Issue(ctx, token, session.Audience)
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
func (s *Tokens) UpdateProfile(ctx context.Context, token authentication.Token, input authentication.ProfileUpdate) error {
	if token.Purpose != "application" || token.Impersonated() {
		return errx.Forbidden("non-impersonated user session required")
	}
	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return err
	}
	return s.repository.UpdateProfile(ctx, token, input)
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
