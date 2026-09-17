package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/migrations"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestIdentityIsolationJourney(t *testing.T) {
	if os.Getenv("IAMKIT_TEST_E2E") != "1" {
		t.Skip("run make test-e2e with Docker")
	}
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine", postgres.WithDatabase("iamkit_test"), postgres.WithUsername("test"), postgres.WithPassword("test"), postgres.BasicWaitStrategies())
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Terminate(ctx)
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = migrations.Apply(ctx, db); err != nil {
		t.Fatal("migration replay:", err)
	}
	if _, err = db.Exec(`UPDATE iamkit_migrations SET checksum='tampered' WHERE name='001_identity.up.sql'`); err != nil {
		t.Fatal(err)
	}
	if err = migrations.Apply(ctx, db); err == nil {
		t.Fatal("changed checksum accepted")
	}
	owner, err := bootstrap.Management(db).Bootstrap(ctx, "owner@example.com", "Workspace A")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.Management(db).Bootstrap(ctx, "other@example.com", "B"); err == nil {
		t.Fatal("bootstrap replay allowed")
	}
	key, err := bootstrap.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	mail := &capturedMail{}
	s := bootstrap.New(db, key, "https://iam.example", mail)
	app := s.App()
	defer app.Shutdown()
	call := func(method, path, token string, body any, want int) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := app.Test(r, 10000)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var result map[string]any
		if resp.StatusCode != 204 {
			if err = json.NewDecoder(resp.Body).Decode(&result); err != nil && want != 201 {
				t.Fatalf("decode %s: %v", path, err)
			}
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s: got %d want %d: %v", method, path, resp.StatusCode, want, result)
		}
		return result
	}
	makeID := func(path string, body any) string {
		t.Helper()
		return call("POST", path, owner, body, 201)["id"].(string)
	}
	p := makeID("/management/v1/projects", fiber.Map{"name": "Product"})
	env := makeID("/management/v1/projects/"+p+"/environments", fiber.Map{"name": "production"})
	dev := makeID("/management/v1/projects/"+p+"/environments", fiber.Map{"name": "development"})
	base := "/management/v1/environments/" + env
	devbase := "/management/v1/environments/" + dev
	user := makeID(base+"/users", fiber.Map{"name": "Alice", "email": "alice@example.com", "password": "correct horse battery"})
	devuser := makeID(devbase+"/users", fiber.Map{"name": "Alice", "email": "alice@example.com", "password": "different password!"})
	member := makeID(base+"/users", fiber.Map{"name": "Bob", "email": "bob@example.com", "password": "correct horse battery"})
	orgA := makeID(base+"/organizations", fiber.Map{"name": "Acme"})
	orgB := makeID(base+"/organizations", fiber.Map{"name": "Globex"})
	client := makeID(base+"/applications", fiber.Map{"name": "iam", "redirect_uris": []string{"https://app.example/callback"}})
	resource := makeID(base+"/resources", fiber.Map{"name": "Billing", "audience": "https://billing.example", "permissions": []string{"invoices:read", "invoices:write"}})
	devresource := makeID(devbase+"/resources", fiber.Map{"name": "Billing", "audience": "https://billing.example", "permissions": []string{"invoices:read"}})
	call("POST", base+"/application-resources", owner, fiber.Map{"application_id": client, "resource_id": devresource}, 409)
	call("POST", base+"/application-resources", owner, fiber.Map{"application_id": client, "resource_id": resource}, 201)
	call("POST", base+"/memberships", owner, fiber.Map{"organization_id": orgA, "user_id": devuser, "role": "owner"}, 409)
	for _, org := range []string{orgA, orgB} {
		call("POST", base+"/memberships", owner, fiber.Map{"organization_id": org, "user_id": user, "role": "owner"}, 201)
	}
	grant := fiber.Map{"organization_id": orgA, "user_id": user, "resource_id": resource, "permissions": []string{"iam:*"}}
	call("PUT", base+"/grants", owner, grant, 400)
	grant["permissions"] = []string{"invoices:read"}
	call("PUT", base+"/grants", owner, grant, 200)
	login := fiber.Map{"environment_id": env, "organization_id": orgA, "application_id": client, "resource_id": resource, "email": "alice@example.com", "password": "correct horse battery"}
	token := call("POST", "/identity/v1/login", "", login, 200)["access_token"].(string)
	check := fiber.Map{"environment_id": env, "audience": "https://billing.example"}
	if call("POST", "/identity/v1/introspect", token, check, 200)["active"] != true {
		t.Fatal("valid access rejected")
	}
	if call("POST", "/identity/v1/introspect", token, fiber.Map{"environment_id": dev, "audience": "https://billing.example"}, 200)["active"] != false {
		t.Fatal("token crossed environment")
	}
	if call("POST", "/identity/v1/introspect", token, fiber.Map{"environment_id": env, "audience": "wrong"}, 200)["active"] != false {
		t.Fatal("token crossed audience")
	}
	call("POST", "/management/v1/projects", token, fiber.Map{"name": "escalation"}, 401)
	call("POST", "/identity/v1/machine-token", owner, nil, 401)
	login["organization_id"] = orgB
	call("POST", "/identity/v1/login", "", login, 401) // membership alone is not application access
	grant["organization_id"] = orgB
	grant["permissions"] = []string{"invoices:write"}
	grantID := call("PUT", base+"/grants", owner, grant, 200)["id"].(string)
	tokenB := call("POST", "/identity/v1/login", "", login, 200)["access_token"].(string)
	claimsB := call("POST", "/identity/v1/introspect", tokenB, check, 200)["claims"].(map[string]any)
	if claimsB["organization_id"] != orgB || claimsB["sub"] != user {
		t.Fatal("membership duplicated identity")
	}
	call("POST", "/identity/v1/memberships", token, fiber.Map{"environment_id": env, "audience": "https://billing.example", "user_id": member}, 201)
	call("POST", "/identity/v1/memberships", token, fiber.Map{"environment_id": env, "audience": "https://billing.example", "user_id": devuser}, 409)
	// Even a correctly signed legacy-shaped token carrying iam:* has no management authority.
	old := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://iam.example", "sub": user, "org_id": orgA, "scopes": []string{"iam:*"}, "aud": "https://billing.example", "exp": time.Now().Add(time.Hour).Unix()})
	oldraw, _ := old.SignedString(key)
	call("POST", "/management/v1/projects", oldraw, fiber.Map{"name": "escalation"}, 401)
	if call("POST", "/identity/v1/introspect", oldraw, check, 200)["active"] != false {
		t.Fatal("legacy token accepted")
	}
	service := call("POST", base+"/service-accounts", owner, fiber.Map{"name": "worker", "application_id": client, "resource_id": resource, "permissions": []string{"invoices:read"}}, 201)
	machine := call("POST", "/identity/v1/machine-token", service["secret"].(string), nil, 200)["access_token"].(string)
	call("POST", "/management/v1/projects", machine, fiber.Map{"name": "escalation"}, 401)
	if call("POST", "/identity/v1/introspect", machine, check, 200)["active"] != true {
		t.Fatal("machine rejected")
	}
	call("DELETE", base+"/service-accounts/"+service["id"].(string), owner, nil, 204)
	if call("POST", "/identity/v1/introspect", machine, check, 200)["active"] != false {
		t.Fatal("revoked machine accepted")
	}
	call("POST", "/identity/v1/logout", token, check, 204)
	if call("POST", "/identity/v1/introspect", token, check, 200)["active"] != false {
		t.Fatal("logout ignored")
	}
	call("DELETE", base+"/grants/"+grantID, owner, nil, 204)
	call("PUT", base+"/grants", owner, grant, 200)
	if call("POST", "/identity/v1/introspect", tokenB, check, 200)["active"] != false {
		t.Fatal("recreated grant revived token")
	}
	tokenB = call("POST", "/identity/v1/login", "", login, 200)["access_token"].(string)
	call("DELETE", base+"/organizations/"+orgB+"/members/"+user, owner, nil, 204)
	if call("POST", "/identity/v1/introspect", tokenB, check, 200)["active"] != false {
		t.Fatal("removed membership accepted")
	}
	migrationJourney(t, call, mail, owner, base, devbase, env, orgA, user, member, client, resource)
	oidcJourney(t, app, call, owner, base, env, orgA, client, resource)
	federationJourney(t, app, key, call, owner, base, env, orgA, user, client, resource)
	// Separate workspace cannot manage this environment, even with a valid owner key.
	workspaceB, operatorB := uuid.NewString(), uuid.NewString()
	foreign, hash, _ := mgmtsecret.Secret("ik_mgmt_")
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO workspaces(id,name) VALUES($1,'B')`, []any{workspaceB}},
		{`INSERT INTO operators(id,email) VALUES($1,'b@example.com')`, []any{operatorB}},
		{`INSERT INTO workspace_members(workspace_id,operator_id,role) VALUES($1,$2,'owner')`, []any{workspaceB, operatorB}},
		{`INSERT INTO management_keys(id,workspace_id,operator_id,secret_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')`, []any{uuid.NewString(), workspaceB, operatorB, hash}},
	} {
		if _, err = db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	call("POST", base+"/organizations", foreign, fiber.Map{"name": "intrusion"}, 404)
	viewer := call("POST", "/management/v1/operators", owner, fiber.Map{"email": "viewer@example.com", "role": "viewer"}, 201)["secret"].(string)
	call("POST", "/management/v1/projects", viewer, fiber.Map{"name": "forbidden"}, 403)
	call("POST", base+"/organizations", viewer, fiber.Map{"name": "forbidden"}, 403)
	viewerKey := call("POST", "/management/v1/keys", viewer, nil, 201)
	call("DELETE", "/management/v1/keys/"+viewerKey["id"].(string), viewer, nil, 204)
	call("GET", "/management/v1/me", viewerKey["secret"].(string), nil, 401)
	replacement := call("POST", "/management/v1/operators", owner, fiber.Map{"email": "viewer@example.com", "role": "viewer"}, 201)
	call("GET", "/management/v1/me", replacement["secret"].(string), nil, 200)
	call("POST", "/management/v1/operators", owner, fiber.Map{"email": "viewer@example.com", "role": "admin"}, 409)
	admin := call("POST", "/management/v1/operators", owner, fiber.Map{"email": "admin@example.com", "role": "admin"}, 201)
	adminKey := admin["secret"].(string)
	secondKey := call("POST", "/management/v1/keys", adminKey, nil, 201)["secret"].(string)
	call("DELETE", "/management/v1/operators/"+admin["operator_id"].(string), owner, nil, 204)
	call("GET", "/management/v1/me", adminKey, nil, 401)
	call("GET", "/management/v1/me", secondKey, nil, 401)
	for range 35 {
		call("POST", "/identity/v1/introspect", token, check, 200)
	}
	ownerPrincipal, err := bootstrap.Management(db).Authenticate(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE management_keys SET expires_at=now()-interval '1 second' WHERE operator_id=$1`, ownerPrincipal.OperatorID); err != nil {
		t.Fatal(err)
	}
	call("GET", "/management/v1/me", owner, nil, 401)
	recovered, err := bootstrap.Management(db).RecoverOwner(ctx, ownerPrincipal.WorkspaceID, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	call("GET", "/management/v1/me", recovered, nil, 200)
	if _, err = bootstrap.Management(db).RecoverOwner(ctx, ownerPrincipal.WorkspaceID, "viewer@example.com"); err == nil {
		t.Fatal("recovery promoted viewer")
	}
	// Database composite constraints protect isolation independently of handlers.
	_, err = db.Exec(`INSERT INTO grants(id,environment_id,organization_id,user_id,resource_id) VALUES($1,$2,$3,$4,$5)`, uuid.NewString(), env, orgA, user, devresource)
	if err == nil {
		t.Fatal("database allowed cross-environment grant")
	}
	var iamApps int
	if err = db.Get(&iamApps, `SELECT count(*) FROM applications`); err != nil {
		t.Fatal(err)
	}
	if iamApps != 1 {
		t.Fatal(fmt.Sprintf("unexpected implicit applications: %d", iamApps))
	}
}
