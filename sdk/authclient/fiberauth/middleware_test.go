package fiberauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/sdk/authclient"
	"github.com/gofiber/fiber/v2"
)

func TestMiddleware(t *testing.T) {
	app := fiber.New()
	app.Use(Authenticate(func(context.Context, string) (*authclient.Claims, error) {
		return &authclient.Claims{Purpose: "application", OrganizationID: "org", Permissions: []string{"read"}}, nil
	}))
	app.Get("/", RequireOrganization("org"), RequirePermissions("read"), func(c *fiber.Ctx) error { return c.SendStatus(204) })
	app.Get("/denied", RequirePermissions("write"), func(c *fiber.Ctx) error { return c.SendStatus(204) })
	for _, test := range []struct {
		path, token string
		status      int
	}{{"/", "", 401}, {"/", "valid", 204}, {"/denied", "valid", 403}} {
		r := httptest.NewRequest("GET", test.path, nil)
		if test.token != "" {
			r.Header.Set("Authorization", "Bearer "+test.token)
		}
		res, err := app.Test(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != test.status {
			t.Fatalf("%s: %d", test.path, res.StatusCode)
		}
	}
}

func TestErrorResponseFormat(t *testing.T) {
	app := fiber.New()
	app.Use(Authenticate(func(context.Context, string) (*authclient.Claims, error) {
		return &authclient.Claims{Purpose: "application", Permissions: []string{"read"}}, nil
	}))
	app.Get("/", RequirePermissions("admin"), func(c *fiber.Ctx) error { return c.SendStatus(204) })

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer valid")
	res, err := app.Test(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON content-type, got %s", ct)
	}
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %s", cc)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	errObj, ok := body["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object in response")
	}
	if errObj["code"] != "FORBIDDEN" {
		t.Fatalf("expected FORBIDDEN code, got %v", errObj["code"])
	}
}

func TestAllowAPIKeys(t *testing.T) {
	tokens := func(context.Context, string) (*authclient.Claims, error) {
		return &authclient.Claims{Purpose: "application", OrganizationID: "org", Permissions: []string{"read"}}, nil
	}
	keys := func(_ context.Context, value string) (authclient.APIKey, error) {
		if value != "ik_key_good" {
			return authclient.APIKey{}, context.Canceled
		}
		return authclient.APIKey{ID: "k1", OrganizationID: "org", Permissions: []string{"read"}, Owner: authclient.APIKeyOwner{Type: "organization"}}, nil
	}
	build := func(options ...Option) *fiber.App {
		app := fiber.New()
		app.Use(Authenticate(tokens, options...))
		app.Get("/", RequireOrganization("org"), RequirePermissions("read"), func(c *fiber.Ctx) error {
			who := "token"
			if key := APIKey(c); key != nil {
				who = key.ID + ":" + Principal(c).Owner().Type
				if Claims(c) != nil {
					who = "both"
				}
			}
			return c.SendString(who)
		})
		app.Get("/denied", RequirePermissions("write"), func(c *fiber.Ctx) error { return c.SendStatus(204) })
		app.Get("/other", RequireOrganization("other"), func(c *fiber.Ctx) error { return c.SendStatus(204) })
		return app
	}
	for _, test := range []struct {
		name, path, token string
		options           []Option
		status            int
		body              string
	}{
		{"key allowed", "/", "ik_key_good", []Option{AllowAPIKeys(keys)}, 200, "k1:organization"},
		{"key refused by validator", "/", "ik_key_bad", []Option{AllowAPIKeys(keys)}, 401, ""},
		{"key without the option", "/", "ik_key_good", nil, 401, ""},
		{"key lacking permission", "/denied", "ik_key_good", []Option{AllowAPIKeys(keys)}, 403, ""},
		{"key of another organization", "/other", "ik_key_good", []Option{AllowAPIKeys(keys)}, 403, ""},
		{"token still works", "/", "jwt", []Option{AllowAPIKeys(keys)}, 200, "token"},
		{"token without the option", "/", "jwt", nil, 200, "token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", test.path, nil)
			r.Header.Set("Authorization", "Bearer "+test.token)
			res, err := build(test.options...).Test(r)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != test.status {
				t.Fatalf("status = %d", res.StatusCode)
			}
			if test.body != "" {
				raw, _ := io.ReadAll(res.Body)
				if string(raw) != test.body {
					t.Fatalf("body = %q", raw)
				}
			}
		})
	}
}
