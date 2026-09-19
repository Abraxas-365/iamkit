package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/gofiber/fiber/v2"
	"github.com/lib/pq"
)

func internalError(err error) error {
	if err == nil {
		return nil
	}
	var custom *errx.Error
	if errors.As(err, &custom) {
		return err
	}
	return errx.Wrap(err, "internal server error", errx.TypeInternal)
}

// Only known constraint violations are conflicts, not database outages.
func conflictError(err error, message string) error {
	var database *pq.Error
	if errors.As(err, &database) && (database.Code == "23505" || database.Code == "23503") {
		return errx.Wrap(err, message, errx.TypeConflict)
	}
	return internalError(err)
}

func errorHandler(c *fiber.Ctx, err error) error {
	var custom *errx.Error
	if !errors.As(err, &custom) || custom == nil {
		var framework *fiber.Error
		if errors.As(err, &framework) && framework.Code >= 400 && framework.Code < 500 {
			custom = errx.Validation(http.StatusText(framework.Code))
			custom.Code = fmt.Sprintf("HTTP_%d", framework.Code)
			custom.HTTPStatus = framework.Code
		} else {
			custom = errx.Internal("internal server error")
		}
	}
	// 5xx causes never reach the client, so they must be logged here or lost.
	if custom.HTTPStatus >= 500 {
		slog.ErrorContext(c.Context(), "request failed",
			"method", c.Method(),
			"path", c.Path(),
			"status", custom.HTTPStatus,
			"code", custom.Code,
			"err", custom.Error(),
		)
	}
	// Never serialize causes or internal details, including wrapped database errors.
	public := *custom
	public.Err = nil
	public.Details = nil
	if public.HTTPStatus >= 500 {
		public.Message = http.StatusText(public.HTTPStatus)
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(public.HTTPStatus).JSON(fiber.Map{"error": &public})
}
