// Package httpx provides small HTTP handler helpers.
package httpx

import (
	"strconv"

	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/gofiber/fiber/v2"
)

// PaginationFromCtx reads ?limit=, ?offset= and ?search= from the request.
func PaginationFromCtx(c *fiber.Ctx) query.Pagination {
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))
	return query.Pagination{Limit: limit, Offset: offset, Search: c.Query("search")}.Normalize()
}
