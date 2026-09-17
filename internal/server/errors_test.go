package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/gofiber/fiber/v2"
	"github.com/lib/pq"
)

func TestNilInternalError(t *testing.T) {
	if internalError(nil) != nil {
		t.Fatal("nil became a typed error")
	}
}

func TestErrorHandler(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"validation", errx.Validation("invalid request"), 400, "VALIDATION"},
		{"wrapped", fmt.Errorf("context: %w", errx.NotFound("resource not found")), 404, "NOT_FOUND"},
		{"unauthorized", errx.Unauthorized("invalid credential"), 401, "AUTHORIZATION"},
		{"forbidden", errx.Forbidden("insufficient permissions"), 403, "FORBIDDEN"},
		{"conflict", errx.Conflict("already exists"), 409, "CONFLICT"},
		{"internal", errx.Wrap(errors.New("secret-database"), "secret-message", errx.TypeInternal).WithDetail("secret-detail", true), 500, "INTERNAL"},
		{"unknown", errors.New("secret-unknown"), 500, "INTERNAL"},
		{"framework", fmt.Errorf("wrapped: %w", fiber.NewError(400, "secret-parser")), 400, "HTTP_400"},
		{"rate limit", fiber.ErrTooManyRequests, 429, "HTTP_429"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New(fiber.Config{ErrorHandler: errorHandler})
			app.Get("/", func(c *fiber.Ctx) error { return tc.err })
			res, err := app.Test(httptest.NewRequest("GET", "/", nil))
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Error errx.Error `json:"error"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != tc.status || envelope.Error.HTTPStatus != tc.status || envelope.Error.Code != tc.code {
				t.Fatalf("status=%d body=%s", res.StatusCode, body)
			}
			if strings.Contains(string(body), "secret-") {
				t.Fatalf("leaked internals: %s", body)
			}
			if res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("error response must not be cached")
			}
		})
	}
}

func TestConflictError(t *testing.T) {
	for _, code := range []pq.ErrorCode{"23505", "23503", "08006"} {
		cause := &pq.Error{Code: code, Detail: "sensitive database detail"}
		err := conflictError(cause, "conflicting resource")
		var custom *errx.Error
		if !errors.As(err, &custom) || !errors.Is(err, cause) {
			t.Fatal("missing custom error or cause")
		}
		want := 409
		if code == "08006" {
			want = 500
		}
		if custom.HTTPStatus != want {
			t.Fatalf("code %s: got %d, want %d", code, custom.HTTPStatus, want)
		}
	}
}

func TestInternalErrorPreservesCustomError(t *testing.T) {
	original := errx.Forbidden("insufficient permissions")
	if internalError(original) != original {
		t.Fatal("lost custom error")
	}
}
