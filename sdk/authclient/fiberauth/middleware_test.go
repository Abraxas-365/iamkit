package fiberauth

import (
	"context"
	"net/http/httptest"
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
