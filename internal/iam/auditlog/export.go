package auditlog

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
)

// Export formats.
const (
	FormatNDJSON = "ndjson"
	FormatCSV    = "csv"
)

// ValidFormat reports whether format is an export format.
func ValidFormat(format string) bool { return format == FormatNDJSON || format == FormatCSV }

// ExportHeaders are the Content-Type and attachment file name of an export.
func ExportHeaders(format string) (contentType, name string) {
	if format == FormatCSV {
		return "text/csv; charset=utf-8", "audit-logs.csv"
	}
	return "application/x-ndjson", "audit-logs.ndjson"
}

// CSVColumns are the columns of the CSV export.
var CSVColumns = []string{"id", "occurred_at", "organization_id", "action", "version", "actor_type", "actor_id", "actor_name",
	"targets", "location", "user_agent", "metadata"}

// Encoder returns the function that writes one event to w in the format
// (NDJSON: one event per line; CSV: a header row first, then one row per
// event, flushed per row).
func Encoder(w io.Writer, format string) func(Event) error {
	if format != FormatCSV {
		enc := json.NewEncoder(w)
		return func(e Event) error { return enc.Encode(e) }
	}
	out := csv.NewWriter(w)
	header := false
	return func(e Event) error {
		if !header {
			header = true
			if err := out.Write(CSVColumns); err != nil {
				return err
			}
		}
		if err := out.Write(CSVRow(e)); err != nil {
			return err
		}
		out.Flush()
		return out.Error()
	}
}

// CSVRow is the event as the cells of CSVColumns, formula-safe.
func CSVRow(e Event) []string {
	targets, _ := json.Marshal(e.Targets)
	metadata := string(e.Metadata)
	if metadata == "" {
		metadata = "{}"
	}
	cells := []string{e.ID.String(), e.OccurredAt.UTC().Format(time.RFC3339Nano), e.Organization.String(), e.Action, strconv.Itoa(e.Version),
		e.Actor.Type, e.Actor.ID, e.Actor.Name, string(targets), e.Context.Location, e.Context.UserAgent, metadata}
	for i, cell := range cells {
		cells[i] = SafeCell(cell)
	}
	return cells
}

// SafeCell prefixes ' to a cell a spreadsheet would read as a formula.
func SafeCell(cell string) string {
	if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
		return "'" + cell
	}
	return cell
}
