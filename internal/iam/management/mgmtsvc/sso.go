package mgmtsvc

import (
	"context"
	"log/slog"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SSO signs operators in through the identity providers the deployment
// configured, and lets owners reset the identities linked to operators.
type SSO struct {
	settings   management.SSOSettings
	provider   management.IdentityProvider
	repository management.SSORepository
	sessions   management.SessionRepository
	secrets    management.Secrets
}

var (
	_ management.SSOFlows         = (*SSO)(nil)
	_ management.IdentityCommands = (*SSO)(nil)
	_ management.IdentityQueries  = (*SSO)(nil)
)

// NewSSO takes settings already validated at startup.
func NewSSO(settings management.SSOSettings, provider management.IdentityProvider, repository management.SSORepository, sessions management.SessionRepository, secrets management.Secrets) *SSO {
	return &SSO{settings: settings, provider: provider, repository: repository, sessions: sessions, secrets: secrets}
}

func (s *SSO) Options(context.Context) management.LoginOptions { return s.settings.Options() }

func (s *SSO) Start(ctx context.Context, id string) (management.SSOStart, error) {
	var out management.SSOStart
	if _, found := s.settings.Provider(id); !found {
		return out, errx.NotFound("operator SSO provider not found")
	}
	state, stateHash, err := s.secrets.Generate("ik_state_")
	if err != nil {
		return out, err
	}
	binding, bindingHash, err := s.secrets.Generate("ik_binding_")
	if err != nil {
		return out, err
	}
	nonce, _, err := s.secrets.Generate("ik_nonce_")
	if err != nil {
		return out, err
	}
	verifier := s.provider.Verifier()
	address, err := s.provider.Authorize(ctx, id, state, nonce, verifier)
	if err != nil {
		return out, err
	}
	row := management.SSOState{Provider: id, Binding: bindingHash, Nonce: nonce, Verifier: verifier}
	if err = s.repository.SaveSSOState(ctx, stateHash, row, time.Now().Add(config.FederationStateTTL)); err != nil {
		return out, err
	}
	return management.SSOStart{URL: address, Binding: binding}, nil
}

func (s *SSO) Callback(ctx context.Context, code, state, binding string) (string, management.Principal, error) {
	raw, p, err := s.callback(ctx, code, state, binding)
	var e *errx.Error
	if err != nil && errx.As(err, &e) && e.Code == management.CodeSSONotAuthorized {
		// The browser only learns the code; the reason is for operators of
		// the deployment.
		slog.WarnContext(ctx, "operator single sign-on refused", "reason", e.Message)
	}
	return raw, p, err
}

func (s *SSO) callback(ctx context.Context, code, state, binding string) (string, management.Principal, error) {
	var none management.Principal
	if code == "" || state == "" || binding == "" {
		return "", none, management.ErrSSOExpired()
	}
	row, err := s.repository.ConsumeSSOState(ctx, s.secrets.Hash(state), s.secrets.Hash(binding))
	if err != nil {
		return "", none, err
	}
	provider, found := s.settings.Provider(row.Provider)
	if !found {
		// Removed from the configuration while the operator was away.
		return "", none, management.ErrSSOExpired()
	}
	claims, err := s.provider.Verify(ctx, provider.ID, code, row.Nonce, row.Verifier)
	if err != nil {
		return "", none, err
	}
	p, linked, err := s.repository.LinkedOperator(ctx, claims.Issuer, claims.Subject)
	if err != nil {
		return "", none, err
	}
	email, err := provider.Admit(claims, linked)
	if err != nil {
		return "", none, err
	}
	if linked {
		err = s.repository.TouchIdentity(ctx, claims.Issuer, claims.Subject)
	} else {
		p, err = s.repository.LinkOperator(ctx, claims.Issuer, claims.Subject, provider.ID, email)
	}
	if err != nil {
		return "", none, err
	}
	raw, hash, err := s.secrets.Generate("ik_sess_")
	if err != nil {
		return "", none, errx.Wrap(err, "session creation failed", errx.TypeInternal)
	}
	now := time.Now()
	p.Method, p.Session, p.AuthTime = management.MethodSSO, identity.NewSessionID(), &now
	if err = s.sessions.CreateSession(ctx, p.Session, p, hash, now.Add(config.OperatorSessionTTL)); err != nil {
		return "", none, err
	}
	slog.InfoContext(ctx, "operator.login", "operator", p.OperatorID.String(), "workspace", p.WorkspaceID.String(), "provider", provider.ID, "method", "sso", "first_link", !linked)
	return raw, p, nil
}

// Identities lists an operator's linked identities: to owners, and to the
// operator themself.
func (s *SSO) Identities(ctx context.Context, p management.Principal, operator identity.OperatorID) ([]management.OperatorIdentity, error) {
	if p.Role != "owner" && p.OperatorID != operator {
		return nil, errx.Forbidden("insufficient permissions")
	}
	if operator.IsZero() {
		return nil, errx.NotFound("resource not found")
	}
	return s.repository.Identities(ctx, p.WorkspaceID, operator)
}

// UnlinkIdentities is the owner's reset, e.g. after the operator's account
// moved to another tenant or provider.
func (s *SSO) UnlinkIdentities(ctx context.Context, p management.Principal, operator identity.OperatorID) error {
	if p.Role != "owner" {
		return errx.Forbidden("insufficient permissions")
	}
	if operator.IsZero() {
		return errx.NotFound("resource not found")
	}
	return s.repository.UnlinkIdentities(ctx, p.WorkspaceID, operator)
}
