package fedmodule

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/federation"
)

// router sends SAML connections to the SAML provider and every other
// connection to the OIDC/OAuth 2.0 provider, so the federation service
// stays protocol-agnostic.
type router struct {
	oidc, saml federation.Provider
}

func (r router) pick(c federation.Connection) federation.Provider {
	if c.Provider == federation.ProviderSAML {
		return r.saml
	}
	return r.oidc
}

func (r router) Approved(c federation.Connection) bool { return r.pick(c).Approved(c) }
func (r router) Prepare(ctx context.Context, c federation.Connection) (federation.Connection, error) {
	return r.pick(c).Prepare(ctx, c)
}
func (r router) Authorize(ctx context.Context, c federation.Connection, state, nonce, verifier string) (string, error) {
	return r.pick(c).Authorize(ctx, c, state, nonce, verifier)
}
func (r router) Verify(ctx context.Context, c federation.Connection, code, nonce, verifier string) (federation.Claims, error) {
	return r.pick(c).Verify(ctx, c, code, nonce, verifier)
}
func (r router) Metadata(ctx context.Context, c federation.Connection) ([]byte, error) {
	return r.pick(c).Metadata(ctx, c)
}

// Verifier is the PKCE verifier; SAML ignores it.
func (r router) Verifier() string { return r.oidc.Verifier() }
func (r router) Callback() string { return r.oidc.Callback() }

var _ federation.Provider = router{}
