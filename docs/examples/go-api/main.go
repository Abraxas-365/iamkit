package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
)

func required(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}

type introspector interface {
	Introspect(ctx context.Context, token, issuer, audience, environment, application, resource string) (*authclient.Claims, error)
}

func routes(client introspector, issuer, audience, env, app, resource string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /organizations/{organization}/invoices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "unauthorized", 401)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		claims, err := client.Introspect(ctx, parts[1], issuer, audience, env, app, resource)
		if err != nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		// Tenant match is mandatory even when a token has the right permission.
		if claims.Purpose != "application" || claims.OrganizationID != r.PathValue("organization") || !claims.HasPermission("invoices:read") {
			http.Error(w, "forbidden", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Real queries must also constrain organization_id to claims.OrganizationID.
		_ = json.NewEncoder(w).Encode(map[string]any{"organization_id": claims.OrganizationID, "items": []any{}})
	})
	return mux
}

func main() {
	base, issuer := required("IAMKIT_URL"), required("JWT_ISSUER")
	env, app, resource := required("ENVIRONMENT_ID"), required("APPLICATION_ID"), required("RESOURCE_ID")
	audience := required("AUDIENCE")
	client := authclient.New(base, authclient.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))
	server := &http.Server{Addr: "127.0.0.1:8090", Handler: routes(client, issuer, audience, env, app, resource), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	fmt.Println("Example API listening on http://127.0.0.1:8090")
	log.Fatal(server.ListenAndServe())
}
