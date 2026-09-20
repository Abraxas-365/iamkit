package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/mattn/go-isatty"
)

// printer handles output formatting: JSON for pipes, tables for terminals.
type printer struct {
	out    io.Writer
	isTTY  bool
	format string // "", "json", "table"
}

func newPrinter() *printer {
	f := flagOutput
	isTTY := isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
	return &printer{out: os.Stdout, isTTY: isTTY, format: f}
}

func (p *printer) wantJSON() bool {
	if p.format == "json" {
		return true
	}
	if p.format == "table" {
		return false
	}
	return !p.isTTY
}

// JSON prints raw JSON with indentation.
func (p *printer) JSON(data json.RawMessage) {
	var buf []byte
	// Try to pretty-print
	var v any
	if json.Unmarshal(data, &v) == nil {
		buf, _ = json.MarshalIndent(v, "", "  ")
	} else {
		buf = data
	}
	fmt.Fprintln(p.out, string(buf))
}

// created prints a creation result. ID to stdout, message to stderr.
func (p *printer) created(entity string, data json.RawMessage) {
	if p.wantJSON() {
		p.JSON(data)
		return
	}
	var obj map[string]any
	if json.Unmarshal(data, &obj) == nil {
		if id, ok := obj["id"]; ok {
			fmt.Fprintf(os.Stderr, "Created %s: %v\n", entity, id)
			fmt.Fprintln(p.out, id)
			return
		}
	}
	p.JSON(data)
}

// detail prints a single entity in key-value format.
func (p *printer) detail(data json.RawMessage) {
	if p.wantJSON() {
		p.JSON(data)
		return
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		p.JSON(data)
		return
	}
	w := tabwriter.NewWriter(p.out, 0, 0, 2, ' ', 0)
	for _, k := range sortedKeys(obj) {
		v := obj[k]
		switch val := v.(type) {
		case []any:
			if len(val) == 0 {
				fmt.Fprintf(w, "%s:\t—\n", k)
				continue
			}
			for i, item := range val {
				label := k + ":"
				if i > 0 {
					label = ""
				}
				fmt.Fprintf(w, "%s\t%v\n", label, item)
			}
		default:
			fmt.Fprintf(w, "%s:\t%v\n", k, v)
		}
	}
	w.Flush()
}

// table prints a list as a table.
func (p *printer) table(data json.RawMessage, columns []string, rowFn func(map[string]any) []string) {
	if p.wantJSON() {
		p.JSON(data)
		return
	}

	items, page := parseList(data)

	w := tabwriter.NewWriter(p.out, 0, 0, 2, ' ', 0)
	// Header
	fmt.Fprintln(w, strings.Join(columns, "\t"))
	for _, item := range items {
		row := rowFn(item)
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	w.Flush()

	// Pagination footer
	if page != nil {
		total, _ := page["total"].(float64)
		limit, _ := page["limit"].(float64)
		offset, _ := page["offset"].(float64)
		end := int(offset) + int(limit)
		if end > int(total) {
			end = int(total)
		}
		fmt.Fprintf(os.Stderr, "\nShowing %d–%d of %.0f\n", int(offset)+1, end, total)
	}
}

// ok prints a success message to stderr for mutating operations with no body.
func (p *printer) ok(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}

// parseList extracts items and page from the standard paginated envelope,
// or treats the data as a bare array.
func parseList(data json.RawMessage) ([]map[string]any, map[string]any) {
	// Try paginated envelope: {"items": [...], "page": {...}}
	var envelope struct {
		Items []map[string]any `json:"items"`
		Page  map[string]any   `json:"page"`
	}
	if json.Unmarshal(data, &envelope) == nil && envelope.Items != nil {
		return envelope.Items, envelope.Page
	}
	// Bare array
	var arr []map[string]any
	if json.Unmarshal(data, &arr) == nil {
		return arr, nil
	}
	return nil, nil
}

// sortedKeys returns map keys in a stable order.
func sortedKeys(m map[string]any) []string {
	// Preferred order for common fields
	order := []string{"id", "name", "email", "prefix", "audience", "active",
		"role", "permissions", "redirect_uris", "operator_id", "workspace_id",
		"application_id", "application_name", "resource_id", "resource_name",
		"organization_id", "organization_name", "user_id", "user_name",
		"expires_at", "revoked_at", "created_at", "updated_at", "secret",
		"otp_enabled", "email_verified", "metadata", "issuer", "client_id",
		"linked", "webhook_url"}
	seen := map[string]bool{}
	var result []string
	for _, k := range order {
		if _, ok := m[k]; ok {
			result = append(result, k)
			seen[k] = true
		}
	}
	for k := range m {
		if !seen[k] {
			result = append(result, k)
		}
	}
	return result
}

// collapsePerms formats a permission list for table display.
func collapsePerms(v any) string {
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return "—"
	}
	const maxShow = 3
	var parts []string
	for i, p := range arr {
		if i >= maxShow {
			parts = append(parts, fmt.Sprintf("+%d more", len(arr)-maxShow))
			break
		}
		parts = append(parts, fmt.Sprintf("%v", p))
	}
	return strings.Join(parts, ", ")
}

// str safely extracts a string from a map.
func str(m map[string]any, key string) string {
	v, _ := m[key]
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// activeStr returns "active"/"inactive" from a bool field.
func activeStr(m map[string]any, key string) string {
	v, ok := m[key].(bool)
	if !ok {
		return "—"
	}
	if v {
		return "active"
	}
	return "inactive"
}

// truncateID shortens a UUID for table display.
func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}
