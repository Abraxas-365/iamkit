// Package httpauth integrates resource-bound access validation with the
// standard net/http Handler chain. It has no framework dependency, so it
// works directly with net/http, chi, gorilla/mux, or any router/middleware
// stack built on http.Handler (including adapters shipped by gin, echo,
// etc. for wrapping standard middleware). Use authclient/fiberauth instead
// if the API is built on Fiber v2 — the two packages expose the same
// Authenticate/RequirePermissions/RequireOrganization shape.
package httpauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
)

// errJSON writes a structured JSON error matching the IAMKit error format,
// mirroring authclient/fiberauth's response shape.
func errJSON(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

// Validator resolves a bearer token to trusted claims. Use Client.Introspect
// for live revocation, or authclient.Validate for explicitly offline
// validation against a cached JWKS/RSA key.
type Validator func(context.Context, string) (*authclient.Claims, error)

type (
	claimsKey    struct{}
	principalKey struct{}
)

// APIKeyValidator resolves an API key value (ik_key_…) to the validated key;
// pass Client.ValidateAPIKey of a client built with authclient.WithAudience.
type APIKeyValidator func(context.Context, string) (authclient.APIKey, error)

type config struct{ keys APIKeyValidator }

// Option configures Authenticate.
type Option func(*config)

// AllowAPIKeys lets bearers starting with ik_key_ authenticate as API keys,
// validated by validate on every request (use Client.ValidateAPIKey). Off by
// default: without it an API key is a 401. The key becomes the request's
// Principal; Claims is nil for it.
func AllowAPIKeys(validate APIKeyValidator) Option {
	return func(c *config) { c.keys = validate }
}

// Authenticate wraps next, extracting the bearer token, resolving it via
// validate (or, with AllowAPIKeys, an ik_key_ bearer via the API key
// validator), and storing the principal on the request context.
// Missing/invalid tokens produce 401 and next is never called.
func Authenticate(validate Validator, next http.Handler, options ...Option) http.Handler {
	var cfg config
	for _, option := range options {
		option(&cfg)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := strings.Fields(r.Header.Get("Authorization"))
		if len(value) != 2 || !strings.EqualFold(value[0], "Bearer") {
			errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
			return
		}
		ctx := r.Context()
		if authclient.IsAPIKey(value[1]) {
			if cfg.keys == nil {
				errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
				return
			}
			key, err := cfg.keys(ctx, value[1])
			if err != nil || key.ID == "" {
				errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
				return
			}
			ctx = context.WithValue(ctx, principalKey{}, &authclient.Principal{APIKey: &key})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		if validate == nil {
			errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
			return
		}
		claims, err := validate(ctx, value[1])
		if err != nil || claims == nil {
			errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
			return
		}
		ctx = context.WithValue(ctx, claimsKey{}, claims)
		ctx = context.WithValue(ctx, principalKey{}, &authclient.Principal{Claims: claims})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Middleware adapts Authenticate to the common func(http.Handler) http.Handler
// signature expected by chi, gorilla/mux and similar routers.
func Middleware(validate Validator, options ...Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return Authenticate(validate, next, options...) }
}

// Claims returns the token claims stored by Authenticate, or nil if the
// request context has none (Authenticate did not run or failed, or the
// request authenticated with an API key: see Principal).
func Claims(r *http.Request) *authclient.Claims {
	claims, _ := r.Context().Value(claimsKey{}).(*authclient.Claims)
	return claims
}

// Principal returns who Authenticate admitted — token claims or an API key,
// with the organization, permissions and (for keys) owner — or nil.
func Principal(r *http.Request) *authclient.Principal {
	principal, _ := r.Context().Value(principalKey{}).(*authclient.Principal)
	return principal
}

// APIKey returns the validated API key of the request, or nil when it
// authenticated with a token (or not at all).
func APIKey(r *http.Request) *authclient.APIKey {
	if p := Principal(r); p != nil {
		return p.APIKey
	}
	return nil
}

// RequirePermissions wraps next, requiring every listed permission to be
// held by the request's principal (token or API key, set by Authenticate).
// Missing principal produces 401; missing permissions produce 403.
func RequirePermissions(next http.Handler, required ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := Principal(r)
		if principal == nil {
			errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
			return
		}
		for _, permission := range required {
			if permission == "" || !principal.HasPermission(permission) {
				errJSON(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePermissionsMiddleware adapts RequirePermissions to
// func(http.Handler) http.Handler for router-level composition.
func RequirePermissionsMiddleware(required ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return RequirePermissions(next, required...)
	}
}

// RequireOrganization wraps next, requiring the principal to act in the
// given organization id: an "application"-purpose token bound to it or an
// API key of it. Compare the requested/trusted organization to the
// principal — never trust a route parameter as authority on its own.
func RequireOrganization(next http.Handler, id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := Principal(r)
		if principal == nil {
			errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
			return
		}
		if !principal.OrganizationBound(id) {
			errJSON(w, http.StatusForbidden, "FORBIDDEN", "organization mismatch")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireOrganizationMiddleware adapts RequireOrganization to
// func(http.Handler) http.Handler for router-level composition.
func RequireOrganizationMiddleware(id string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return RequireOrganization(next, id) }
}
