package e2e_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/cache/cacheredis"
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/gofiber/fiber/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const redisImage = "redis:7-alpine"

// startRedis runs a Redis container and returns its redis:// URL and the
// container (to stop it).
func startRedis(t *testing.T) (string, testcontainers.Container) {
	t.Helper()
	requireE2E(t)
	ctx := context.Background()
	c, err := testcontainers.Run(ctx, redisImage, testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategyAndDeadline(60*time.Second, wait.ForLog("Ready to accept connections")))
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := c.PortEndpoint(ctx, "6379/tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	return "redis://" + endpoint + "/0", c
}

func openRedis(t *testing.T, url string) *cacheredis.Client {
	t.Helper()
	c, err := cacheredis.Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestRedisSharedState: two replicas (two apps on one database) with one
// Redis share per-IP rate limits, per-minute environment limits and cache
// invalidation; with Redis down they fall back to the database and their
// own counters.
func TestRedisSharedState(t *testing.T) {
	url, container := startRedis(t)
	deployment, err := usage.ParseDeployment("requests_per_minute=1000")
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, bootstrap.WithLimits(deployment), bootstrap.WithRedis(openRedis(t, url)))
	sealer, err := cryptox.Parse(testEncryptionKey, "")
	if err != nil {
		t.Fatal(err)
	}
	replica := bootstrap.New(e.DB, e.Key, "https://iam.example", e.Mail, bootstrap.WithSealer(sealer), bootstrap.WithLimits(deployment), bootstrap.WithRedis(openRedis(t, url))).App()
	t.Cleanup(func() { replica.Shutdown() })
	// call sends a request to one replica; token as in Harness.Do.
	call := func(app *fiber.App, method, path, token string) (int, map[string]any) {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		switch {
		case strings.HasPrefix(token, "ik_"):
			r.Header.Set("X-API-Key", token)
		case token != "":
			r.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := app.Test(r, 10000)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}

	if health := e.Must("GET", "/health", "", nil, 200).JSON; health["cache"] != "up" {
		t.Fatalf("health = %v", health)
	}

	// requests_per_minute counts across replicas.
	e.Must("PUT", e.Base+"/limits", e.Owner, fiber.Map{"requests_per_minute": 4}, 200)
	token := e.scopedToken("iam:users:read")
	api := "/api/v1/environments/" + e.EnvID + "/users"
	for range 2 {
		e.Must("GET", api, token, nil, 200)
	}
	bearer := func(app *fiber.App) int { status, _ := call(app, "GET", api, token); return status }
	if bearer(replica) != 200 || bearer(replica) != 200 {
		t.Fatal("replica refused requests under the limit")
	}
	if got := bearer(replica); got != 429 {
		t.Fatalf("fifth request across replicas = %d, want 429", got)
	}
	e.Must("PUT", e.Base+"/limits", e.Owner, fiber.Map{}, 200)

	// Per-IP limiters are shared too: /identity/v1/login allows 30 a minute.
	login := "/identity/v1/login"
	for i := range 30 {
		app := e.App.App
		if i%2 == 1 {
			app = replica
		}
		if got, _ := call(app, "POST", login, ""); got == 429 {
			t.Fatalf("login %d limited early", i+1)
		}
	}
	if got, _ := call(replica, "POST", login, ""); got != 429 {
		t.Fatalf("31st login across replicas = %d, want 429", got)
	}

	// A feature change on one replica reaches the other at once (the
	// writer deletes the shared entry).
	features := e.Base + "/features/beta_languages"
	if on := e.Must("GET", features, e.Owner, nil, 200).JSON["enabled"]; on != true {
		t.Fatalf("beta_languages = %v", on)
	}
	enabled := func(app *fiber.App) any { _, body := call(app, "GET", features, e.Owner); return body["enabled"] }
	_ = enabled(replica) // warm the replica's read
	e.Must("PUT", features, e.Owner, fiber.Map{"enabled": false}, 200)
	if got := enabled(replica); got != false {
		t.Fatalf("replica read a stale override: %v", got)
	}

	// Redis down: /health says so but stays 200, reads use the database,
	// limits count per replica.
	if err := container.Stop(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if health := e.Must("GET", "/health", "", nil, 200).JSON; health["cache"] != "down" {
		t.Fatalf("health with redis down = %v", health)
	}
	e.Must("PUT", features, e.Owner, fiber.Map{"enabled": true}, 200)
	if got := enabled(replica); got != true {
		t.Fatalf("redis down: override = %v", got)
	}
	e.Must("GET", api, token, nil, 200)
}
