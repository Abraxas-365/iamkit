package httpauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
)

func ok(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }

func TestMiddleware(t *testing.T) {
	validate := func(context.Context, string) (*authclient.Claims, error) {
		return &authclient.Claims{Purpose: "application", OrganizationID: "org", Permissions: []string{"read"}}, nil
	}
	mux := http.NewServeMux()
	mux.Handle("/", Authenticate(validate, RequireOrganization(RequirePermissions(http.HandlerFunc(ok), "read"), "org")))
	mux.Handle("/denied", Authenticate(validate, RequirePermissions(http.HandlerFunc(ok), "write")))

	for _, test := range []struct {
		path, token string
		status      int
	}{{"/", "", 401}, {"/", "valid", 204}, {"/denied", "valid", 403}} {
		r := httptest.NewRequest("GET", test.path, nil)
		if test.token != "" {
			r.Header.Set("Authorization", "Bearer "+test.token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s: got %d, want %d", test.path, w.Code, test.status)
		}
	}
}

func TestMiddlewareAdapters(t *testing.T) {
	validate := func(context.Context, string) (*authclient.Claims, error) {
		return &authclient.Claims{Purpose: "application", OrganizationID: "org", Permissions: []string{"read"}}, nil
	}
	handler := Middleware(validate)(RequireOrganizationMiddleware("org")(RequirePermissionsMiddleware("read")(http.HandlerFunc(ok))))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer valid")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("got %d, want 204", w.Code)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer valid")
	w = httptest.NewRecorder()
	Middleware(validate)(RequireOrganizationMiddleware("other")(http.HandlerFunc(ok))).ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("got %d, want 403", w.Code)
	}
}

func TestErrorResponseFormat(t *testing.T) {
	validate := func(context.Context, string) (*authclient.Claims, error) {
		return &authclient.Claims{Purpose: "application", Permissions: []string{"read"}}, nil
	}
	handler := Authenticate(validate, RequirePermissions(http.HandlerFunc(ok), "admin"))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer valid")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON content-type, got %s", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %s", cc)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatal("expected error object in response")
	}
	if errObj["code"] != "FORBIDDEN" {
		t.Fatalf("expected FORBIDDEN code, got %v", errObj["code"])
	}
}

func TestClaimsNilWithoutAuthenticate(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if Claims(r) != nil {
		t.Fatal("expected nil claims without Authenticate")
	}
}
