// Package query owns the pagination types used by paginated list queries
// across every domain module. It is transport-agnostic — no HTTP or
// framework imports — so ports.go files can depend on it without pulling
// in Fiber. See internal/httpx for the Fiber-specific bridge that produces
// a Pagination from an HTTP request.
package query

import "strings"

// Pagination holds limit/offset/search for paginated queries.
type Pagination struct {
	Limit  int
	Offset int
	Search string
}

// DefaultLimit is applied when the caller sends zero or negative.
const DefaultLimit = 20

// MaxLimit caps runaway requests.
const MaxLimit = 100

// Normalize clamps Limit to [1, MaxLimit] and Offset to >= 0.
func (p Pagination) Normalize() Pagination {
	if p.Limit <= 0 {
		p.Limit = DefaultLimit
	}
	if p.Limit > MaxLimit {
		p.Limit = MaxLimit
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}

// Page carries pagination metadata in API responses — the effective
// limit/offset the server applied (after clamping) plus the total match
// count.
type Page struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// Paginated is the standard paginated response envelope. Wire format:
// {"items": [...], "page": {"total": N, "limit": N, "offset": N}}.
type Paginated[T any] struct {
	Items []T  `json:"items"`
	Page  Page `json:"page"`
}

// NewPaginated builds a Paginated envelope from items, a total count, and
// the pagination that was applied. It never returns a nil Items slice.
func NewPaginated[T any](items []T, total int, p Pagination) Paginated[T] {
	if items == nil {
		items = []T{}
	}
	return Paginated[T]{Items: items, Page: Page{Total: total, Limit: p.Limit, Offset: p.Offset}}
}

// EscapeLike escapes LIKE/ILIKE metacharacters (% and _) and wraps the
// result in % on both sides for a contains-match pattern.
// Returns "" when the input is empty — callers should skip the ILIKE clause.
func EscapeLike(s string) string {
	if s == "" {
		return ""
	}
	r := strings.NewReplacer("%", `\%`, "_", `\_`)
	return "%" + r.Replace(s) + "%"
}
