package e2e_test

// Shared testcontainers harness for focused e2e tests.
//
// One Postgres container is started per `go test` run (TestMain). Migrations
// are applied once to a template database; every test gets its own database
// cloned from that template, so tests are isolated and fast.
//
// Run: make test-e2e   (IAMKIT_TEST_E2E=1, requires Docker)

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/migrations"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	adminDSN string // connection to the container's maintenance database
	dbSeq    atomic.Int64
)

const templateDB = "iamkit_template"

func TestMain(m *testing.M) {
	if os.Getenv("IAMKIT_TEST_E2E") != "1" {
		os.Exit(m.Run()) // every test skips itself
	}
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("iamkit_test"), postgres.WithUsername("test"), postgres.WithPassword("test"),
		postgres.BasicWaitStrategies())
	if err != nil {
		fmt.Fprintln(os.Stderr, "start postgres:", err)
		os.Exit(1)
	}
	code := func() int {
		defer pg.Terminate(ctx)
		if adminDSN, err = pg.ConnectionString(ctx, "sslmode=disable"); err != nil {
			fmt.Fprintln(os.Stderr, "dsn:", err)
			return 1
		}
		if err = prepareTemplate(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "template:", err)
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

func prepareTemplate(ctx context.Context) error {
	admin, err := sqlx.Connect("postgres", adminDSN)
	if err != nil {
		return err
	}
	defer admin.Close()
	if _, err = admin.Exec(`CREATE DATABASE ` + templateDB); err != nil {
		return err
	}
	tpl, err := sqlx.Connect("postgres", withDB(adminDSN, templateDB))
	if err != nil {
		return err
	}
	defer tpl.Close()
	return migrations.Apply(ctx, tpl)
}

func withDB(dsn, name string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		panic(err)
	}
	u.Path = "/" + name
	return u.String()
}

// requireE2E skips unless IAMKIT_TEST_E2E=1.
func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("IAMKIT_TEST_E2E") != "1" {
		t.Skip("set IAMKIT_TEST_E2E=1 (make test-e2e) — requires Docker")
	}
}

// freshDB returns a migrated database private to this test, dropped on cleanup.
func freshDB(t *testing.T) *sqlx.DB {
	t.Helper()
	requireE2E(t)
	name := fmt.Sprintf("iamkit_t%d", dbSeq.Add(1))
	admin, err := sqlx.Connect("postgres", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(`CREATE DATABASE ` + name + ` TEMPLATE ` + templateDB); err != nil {
		t.Fatal(err)
	}
	db, err := sqlx.Connect("postgres", withDB(adminDSN, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		if a, err := sqlx.Connect("postgres", adminDSN); err == nil {
			a.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
			a.Close()
		}
	})
	return db
}

// Harness is a running IAMKit app on a private database with an owner key.
type Harness struct {
	t     *testing.T
	DB    *sqlx.DB
	App   *fiber.App
	Key   *rsa.PrivateKey
	Mail  *capturedMail
	Owner string // operator X-API-Key
}

func newHarness(t *testing.T) *Harness {
	t.Helper()
	db := freshDB(t)
	owner, err := bootstrap.Management(db).Bootstrap(context.Background(), "owner@example.com", "Workspace")
	if err != nil {
		t.Fatal(err)
	}
	key, err := bootstrap.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	mail := &capturedMail{}
	app := bootstrap.New(db, key, "https://iam.example", mail).App()
	t.Cleanup(func() { app.Shutdown() })
	return &Harness{t: t, DB: db, App: app, Key: key, Mail: mail, Owner: owner}
}

// Response is a decoded HTTP response.
type Response struct {
	Status int
	Body   string
	JSON   map[string]any
}

// Do sends a request. token: "ik_svc_…" or a JWT → Bearer, other "ik_…" → X-API-Key.
func (h *Harness) Do(method, path, token string, body any) Response {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, path, reader)
	r.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(token, "ik_") && !strings.HasPrefix(token, "ik_svc_") {
		r.Header.Set("X-API-Key", token)
	} else if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := h.App.Test(r, 10000)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := Response{Status: res.StatusCode, Body: string(raw)}
	_ = json.Unmarshal(raw, &out.JSON)
	return out
}

// Must sends a request and fails the test unless the status matches.
func (h *Harness) Must(method, path, token string, body any, want int) Response {
	h.t.Helper()
	res := h.Do(method, path, token, body)
	if res.Status != want {
		h.t.Fatalf("%s %s: got %d want %d: %s", method, path, res.Status, want, res.Body)
	}
	return res
}

// ID creates a resource as the owner and returns its "id".
func (h *Harness) ID(method, path string, body any) string {
	h.t.Helper()
	res := h.Do(method, path, h.Owner, body)
	if res.Status != 200 && res.Status != 201 {
		h.t.Fatalf("%s %s: got %d: %s", method, path, res.Status, res.Body)
	}
	id, _ := res.JSON["id"].(string)
	if id == "" {
		h.t.Fatalf("%s %s: no id in %s", method, path, res.Body)
	}
	return id
}

// Env is a ready-to-use environment: one org, app, resource and a user
// ("alice") who is a member with invoices:read and can log in.
type Env struct {
	*Harness
	EnvID, Base      string // environment id, management base path
	Org, Client, Res string
	Alice            string
	AliceEmail, Pass string
	Audience         string
}

func newEnv(t *testing.T) *Env {
	t.Helper()
	h := newHarness(t)
	project := h.ID("POST", "/management/v1/projects", fiber.Map{"name": "Product"})
	id := h.ID("POST", "/management/v1/projects/"+project+"/environments", fiber.Map{"name": "production"})
	e := &Env{Harness: h, EnvID: id, Base: "/management/v1/environments/" + id,
		AliceEmail: "alice@example.com", Pass: "correct horse battery", Audience: "https://billing.example"}
	e.Org = h.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Acme"})
	e.Client = h.ID("POST", e.Base+"/applications", fiber.Map{"name": "web", "redirect_uris": []string{"https://app.example/callback"}})
	e.Res = h.ID("POST", e.Base+"/resources", fiber.Map{"name": "Billing", "prefix": "invoices", "audience": e.Audience, "permissions": []string{"invoices:read", "invoices:write"}})
	h.Must("POST", e.Base+"/application-resources", h.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.Res}, 201)
	e.Alice = e.User("Alice", e.AliceEmail)
	e.Join(e.Org, e.Alice)
	e.Grant(e.Org, e.Alice, e.Res, "invoices:read")
	return e
}

// User creates a user with the shared test password.
func (e *Env) User(name, email string) string {
	e.t.Helper()
	return e.ID("POST", e.Base+"/users", fiber.Map{"name": name, "email": email, "password": e.Pass})
}

// Join adds user to org via the management API.
func (e *Env) Join(org, user string) {
	e.t.Helper()
	e.Must("POST", e.Base+"/memberships", e.Owner, fiber.Map{"organization_id": org, "user_id": user}, 201)
}

// Grant gives user permissions on resource within org.
func (e *Env) Grant(org, user, resource string, permissions ...string) {
	e.t.Helper()
	e.Must("PUT", e.Base+"/grants", e.Owner, fiber.Map{"organization_id": org, "user_id": user, "resource_id": resource, "permissions": permissions}, 200)
}

// IAMResource returns the environment's built-in "iam" resource id.
func (e *Env) IAMResource() string {
	e.t.Helper()
	var id string
	if err := e.DB.Get(&id, `SELECT id FROM resources WHERE environment_id=$1 AND prefix='iam'`, e.EnvID); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// LoginBody is the password-login request for email/password in e.Org.
func (e *Env) LoginBody(email, password string) fiber.Map {
	return fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res, "email": email, "password": password}
}

// Login returns an access token for email in e.Org, failing the test otherwise.
func (e *Env) Login(email string) string {
	e.t.Helper()
	return e.Must("POST", "/identity/v1/login", "", e.LoginBody(email, e.Pass), 200).JSON["access_token"].(string)
}

// Members returns the user IDs of org's members.
func (e *Env) Members(org string) []string {
	e.t.Helper()
	res := e.Must("GET", e.Base+"/organizations/"+org+"/members", e.Owner, nil, 200)
	items, _ := res.JSON["items"].([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.(map[string]any)["user_id"].(string))
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
