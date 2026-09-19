package fiberauth

import (
	"context"
	"encoding/json"
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
