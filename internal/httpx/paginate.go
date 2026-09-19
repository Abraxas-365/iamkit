// Package httpx provides small HTTP handler helpers.
package httpx

import "github.com/gofiber/fiber/v2"

// Page carries pagination metadata in API responses.
type Page struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// Paginated is the standard list response envelope.
type Paginated[T any] struct {
	Items []T  `json:"items"`
	Page  Page `json:"page"`
}

// Pagination holds limit/offset parsed from query params.
// Used by repository methods that paginate at the DB level.
type Pagination struct {
	Limit  int
	Offset int
}

// PaginationFromCtx reads ?limit= and ?offset= from the request.
// When limit is 0 a default of 50 is used. Max limit is 200.
func PaginationFromCtx(c *fiber.Ctx) Pagination {
	limit := c.QueryInt("limit", 50)
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := c.QueryInt("offset", 0)
	if offset < 0 {
		offset = 0
	}
	return Pagination{Limit: limit, Offset: offset}
}

// NewPaginated creates a paginated response, slicing items in memory.
// Use for endpoints that haven't migrated to DB-level pagination yet.
// When limit is 0 the full slice (from offset) is returned.
func NewPaginated[T any](c *fiber.Ctx, items []T) Paginated[T] {
	total := len(items)
	limit := c.QueryInt("limit", 0)
	if limit < 0 {
		limit = 0
	}
	offset := c.QueryInt("offset", 0)
	if offset < 0 {
		offset = 0
	}
	if offset > len(items) {
		offset = len(items)
	}
	items = items[offset:]
	if limit > 0 && limit < len(items) {
		items = items[:limit]
	}
	if items == nil {
		items = []T{}
	}
	return Paginated[T]{
		Items: items,
		Page:  Page{Total: total, Limit: limit, Offset: offset},
	}
}

// NewPaginatedDB creates a paginated response from pre-sliced DB results.
// total comes from a COUNT(*) query; items are already LIMIT/OFFSET'd.
func NewPaginatedDB[T any](items []T, total int, p Pagination) Paginated[T] {
	if items == nil {
		items = []T{}
	}
	return Paginated[T]{
		Items: items,
		Page:  Page{Total: total, Limit: p.Limit, Offset: p.Offset},
	}
}
