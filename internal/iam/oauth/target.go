package oauth

import (
	"slices"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

// CodeInvalidTarget is the RFC 8707 error for a resource indicator the
// client may not use.
const CodeInvalidTarget = "invalid_target"

// ClaimResourceIndicator is the access token claim only resource flow
// tokens carry: the canonical URI of the protected resource the
// authorization named. Resource servers refuse tokens without it, so a plain
// OpenID Connect token of the same client (every permission, no consent)
// never opens them.
const ClaimResourceIndicator = "resource"

// ErrInvalidTarget refuses a resource parameter.
func ErrInvalidTarget(message string) *errx.Error {
	e := errx.Validation(message)
	e.Code = CodeInvalidTarget
	return e
}

// OIDCScopes are the OpenID Connect scopes every client may ask for.
var OIDCScopes = []string{"openid", "profile", "email", "phone", "offline_access"}

// ScopeOfflineAccess asks for a refresh token.
const ScopeOfflineAccess = "offline_access"

// ResolveResource checks the RFC 8707 resource values of a request
// (authorization or token) against the client: none is the plain OpenID
// Connect flow (nil target); exactly one, naming the client's protected
// resource (canonical comparison), is the resource flow. Anything else is
// invalid_target, also for a client whose resource is not a protected one.
func ResolveResource(client *Client, values []string) (*ProtectedTarget, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 1 {
		return nil, ErrInvalidTarget("only one resource may be requested")
	}
	if client.Protected == nil || !SameResource(values[0], client.Protected.URI) {
		return nil, ErrInvalidTarget("the resource is not a protected resource this client may access")
	}
	return client.Protected, nil
}

// ResourceScopes is the scope an authorization for target asks for: the
// requested permissions of its catalog (its default scopes when none is
// requested), the requested OpenID Connect scopes and organization hints,
// and offline_access when the client may refresh (a client of a resource
// server needs no openid to keep its access). Other values are dropped.
func ResourceScopes(target *ProtectedTarget, requested []string, refresh bool) []string {
	out := []string{}
	permissions := false
	for _, s := range requested {
		switch {
		case slices.Contains(target.Scopes, s):
			permissions = true
			out = appendScope(out, s)
		case slices.Contains(OIDCScopes, s) || strings.HasPrefix(s, OrganizationScopePrefix):
			out = appendScope(out, s)
		}
	}
	if !permissions {
		for _, s := range target.DefaultScopes {
			if slices.Contains(target.Scopes, s) {
				out = appendScope(out, s)
			}
		}
	}
	if refresh {
		out = appendScope(out, ScopeOfflineAccess)
	}
	return out
}

// PlainScopes refuses, outside the resource flow, any scope that is not
// OpenID Connect or an organization hint: a resource's permissions are
// scopes only for an authorization that names the resource.
func PlainScopes(requested []string) error {
	for _, s := range requested {
		if !slices.Contains(OIDCScopes, s) && !strings.HasPrefix(s, OrganizationScopePrefix) {
			return errx.Validation("invalid authorization request: scope " + s + " needs the resource parameter")
		}
	}
	return nil
}

// Consented are the permissions among the granted scopes of a resource
// flow authorization (what the user agreed to).
func Consented(target *ProtectedTarget, granted []string) []string {
	out := []string{}
	for _, s := range granted {
		if slices.Contains(target.Scopes, s) {
			out = appendScope(out, s)
		}
	}
	return out
}

// EffectiveScopes are the consented permissions the user still holds:
// recomputed at every issuance, so a refresh never outlives a role change.
func EffectiveScopes(consented, permissions []string) []string {
	out := []string{}
	for _, s := range consented {
		if slices.Contains(permissions, s) {
			out = appendScope(out, s)
		}
	}
	return out
}

// GrantedScopes replaces the permissions among granted with effective,
// keeping the OpenID Connect scopes and hints.
func GrantedScopes(granted, consented, effective []string) []string {
	out := []string{}
	for _, s := range granted {
		if !slices.Contains(consented, s) {
			out = appendScope(out, s)
		}
	}
	for _, s := range effective {
		out = appendScope(out, s)
	}
	return out
}

func appendScope(scopes []string, s string) []string {
	if slices.Contains(scopes, s) {
		return scopes
	}
	return append(scopes, s)
}
