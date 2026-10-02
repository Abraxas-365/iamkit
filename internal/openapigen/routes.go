package openapigen

import (
	"reflect"
	"runtime"

	"github.com/gofiber/fiber/v2"
)

// Routes lists the app's routes with the source of each final handler.
func Routes(app *fiber.App) []Route {
	var out []Route
	seen := map[string]bool{}
	for _, r := range app.GetRoutes(true) {
		switch r.Method {
		case fiber.MethodGet, fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete:
		default:
			continue
		}
		if len(r.Handlers) == 0 || seen[r.Method+" "+r.Path] {
			continue
		}
		seen[r.Method+" "+r.Path] = true
		fn := runtime.FuncForPC(reflect.ValueOf(r.Handlers[len(r.Handlers)-1]).Pointer())
		file, line := fn.FileLine(fn.Entry())
		out = append(out, Route{Method: r.Method, Path: r.Path, Handler: fn.Name(), File: file, Line: line})
	}
	return out
}
