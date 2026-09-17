package logx

import (
	"encoding/json"
	"fmt"
	"time"
)

// Formatter is the interface for log formatters
type Formatter interface {
	Format(entry *LogEntry) ([]byte, error)
}

// LogEntry represents a single log entry
type LogEntry struct {
	Level     Level
	Message   string
	Fields    Fields
	Data      interface{}
	Error     error
	Timestamp time.Time
	Caller    string
}

// Fields is a map of structured data
type Fields map[string]interface{}

// formatTimestamp formats the timestamp based on the config
func formatTimestamp(t time.Time, format string) string {
	switch format {
	case "unix":
		return fmt.Sprintf("%d", t.Unix())
	case "unixmilli":
		return fmt.Sprintf("%d", t.UnixMilli())
	default:
		return t.Format(format)
	}
}

// prettyJSON formats data as pretty JSON
func prettyJSON(data interface{}) string {
	if data == nil {
		return ""
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", data)
	}
	return string(bytes)
}

// compactJSON formats data as compact JSON
func compactJSON(data interface{}) string {
	if data == nil {
		return ""
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Sprintf("%+v", data)
	}
	return string(bytes)
}
