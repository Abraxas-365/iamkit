package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
)

type stubIntrospector struct {
	claims *authclient.Claims
	err    error
}

func (s stubIntrospector) Introspect(ctx context.Context, token, issuer, audience, environment, application, resource string) (*authclient.Claims, error) {
	return s.claims, s.err
}

func TestTenantAndPermissionEnforcement(t *testing.T) {
	for _, tc := range []struct {
		name, header, org, purpose string
		permissions                []string
		err                        error
		status                     int
	}{
		{name: "allowed", header: "Bearer test", org: "acme", purpose: "application", permissions: []string{"invoices:read"}, status: 200},
		{name: "missing token", status: 401},
		{name: "invalid token", header: "Bearer test", err: errors.New("invalid"), status: 401},
		{name: "wrong tenant", header: "Bearer test", org: "other", purpose: "application", permissions: []string{"invoices:read"}, status: 403},
		{name: "missing permission", header: "Bearer test", org: "acme", purpose: "application", status: 403},
		{name: "wrong purpose", header: "Bearer test", org: "acme", purpose: "machine", permissions: []string{"invoices:read"}, status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := stubIntrospector{claims: &authclient.Claims{OrganizationID: tc.org, Purpose: tc.purpose, Permissions: tc.permissions}, err: tc.err}
			r := httptest.NewRequest("GET", "/organizations/acme/invoices", nil)
			r.Header.Set("Authorization", tc.header)
			w := httptest.NewRecorder()
			routes(client, "issuer", "audience", "env", "app", "resource").ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d, want %d", w.Code, tc.status)
			}
		})
	}
}
