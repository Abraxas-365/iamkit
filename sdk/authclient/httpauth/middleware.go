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

type claimsKey struct{}

// Authenticate wraps next, extracting the bearer token, resolving it via
// validate, and storing the resulting claims on the request context.
// Missing/invalid tokens produce 401 and next is never called.
func Authenticate(validate Validator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := strings.Fields(r.Header.Get("Authorization"))
		if validate == nil || len(value) != 2 || !strings.EqualFold(value[0], "Bearer") {
			errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
			return
		}
		claims, err := validate(r.Context(), value[1])
		if err != nil || claims == nil {
			errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
	})
}

// Middleware adapts Authenticate to the common func(http.Handler) http.Handler
// signature expected by chi, gorilla/mux and similar routers.
func Middleware(validate Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return Authenticate(validate, next) }
}

// Claims returns the claims stored by Authenticate, or nil if the request
// context has none (e.g. Authenticate was not run or failed).
func Claims(r *http.Request) *authclient.Claims {
	claims, _ := r.Context().Value(claimsKey{}).(*authclient.Claims)
	return claims
}

// RequirePermissions wraps next, requiring every listed permission to be
// present in the request's claims (set by Authenticate). Missing claims
// produce 401; missing permissions produce 403.
func RequirePermissions(next http.Handler, required ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := Claims(r)
		if claims == nil {
			errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
			return
		}
		for _, permission := range required {
			if permission == "" || !claims.HasPermission(permission) {
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

// RequireOrganization wraps next, requiring the claims to be an
// "application"-purpose token bound to the given organization id. Compare
// the requested/trusted organization to claims — never trust a route
// parameter as authority on its own.
func RequireOrganization(next http.Handler, id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := Claims(r)
		if claims == nil {
			errJSON(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid bearer token")
			return
		}
		if id == "" || claims.Purpose != "application" || claims.OrganizationID != id {
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
