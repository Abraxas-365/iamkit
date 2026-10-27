package resourceserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

type claimsKey struct{}

// FromContext returns the claims Protect stored on the request context.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*Claims)
	return c, ok
}

// MetadataHandler serves the protected resource metadata (GET and the CORS
// preflight, Access-Control-Allow-Origin *: browser-based MCP clients read
// it). Mount it at every path of MetadataPaths, or use Mount.
func (s *Server) MetadataHandler() http.Handler {
	body, _ := json.Marshal(s.Metadata())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		switch r.Method {
		case http.MethodOptions:
			h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "*")
			h.Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet, http.MethodHead:
			h.Set("Content-Type", "application/json")
			h.Set("Cache-Control", "public, max-age=3600")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				w.Write(body)
			}
		default:
			h.Set("Allow", "GET, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// Mount registers the metadata handler on mux at every metadata path.
func (s *Server) Mount(mux *http.ServeMux) {
	handler := s.MetadataHandler()
	for _, path := range s.MetadataPaths() {
		mux.Handle(path, handler)
	}
}

// Protect wraps next: a request needs a valid token for the resource with
// every one of scopes (none: any valid token), else 401 or 403 with the
// WWW-Authenticate challenge. The claims are on the request context
// (FromContext); the Authorization header is removed so the client's token
// is never passed on.
func (s *Server) Protect(next http.Handler, scopes ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		claims, err := s.Verify(r.Context(), Bearer(r.Header.Get("Authorization")))
		if err == nil {
			err = Require(claims, scopes...)
		}
		if err != nil {
			s.Deny(w, err, scopes)
			return
		}
		r = r.Clone(context.WithValue(r.Context(), claimsKey{}, claims))
		r.Header.Del("Authorization")
		next.ServeHTTP(w, r)
	})
}

// Deny writes the 401/403 answer for err (see Challenge). Handlers use it
// for per-operation step-up: Require(claims, "mcp:tools:write") failing →
// Deny, and the client asks the user for the wider scope.
func (s *Server) Deny(w http.ResponseWriter, err error, scopes []string) {
	h := w.Header()
	if errors.Is(err, ErrUnavailable) {
		// Not the token's fault: no challenge, so the client keeps it.
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Type", "application/json")
		h.Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "temporarily_unavailable"})
		return
	}
	status, challenge := s.Challenge(err, scopes)
	h.Set("WWW-Authenticate", challenge)
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "application/json")
	h.Add("Access-Control-Expose-Headers", "WWW-Authenticate")
	w.WriteHeader(status)
	code := "invalid_token"
	if status == http.StatusForbidden {
		code = "insufficient_scope"
	} else if errors.Is(err, ErrNoToken) {
		code = "unauthorized"
	}
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// RequireScopes is a convenience for handlers behind Protect: it checks the
// request's claims hold scopes and writes the 403 otherwise (false).
func (s *Server) RequireScopes(w http.ResponseWriter, r *http.Request, scopes ...string) bool {
	claims, ok := FromContext(r.Context())
	if !ok {
		s.Deny(w, ErrNoToken, scopes)
		return false
	}
	if err := Require(claims, scopes...); err != nil {
		s.Deny(w, err, scopes)
		return false
	}
	return true
}
