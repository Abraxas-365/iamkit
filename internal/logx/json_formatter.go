package logx

import (
	"encoding/json"
	"time"
)

// JSONFormatter formats logs as JSON
type JSONFormatter struct {
	config *Config
}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter(config *Config) *JSONFormatter {
	return &JSONFormatter{config: config}
}

// Format formats a log entry as JSON
func (f *JSONFormatter) Format(entry *LogEntry) ([]byte, error) {
	data := make(map[string]interface{})

	// Always include level and message
	data["level"] = entry.Level.String()
	data["message"] = entry.Message

	// Timestamp
	if f.config.EnableTimestamp {
		if f.config.TimeFormat == "unix" {
			data["timestamp"] = entry.Timestamp.Unix()
		} else if f.config.TimeFormat == "unixmilli" {
			data["timestamp"] = entry.Timestamp.UnixMilli()
		} else {
			data["timestamp"] = entry.Timestamp.Format(time.RFC3339Nano)
		}
	}

	// Caller
	if f.config.EnableCaller && entry.Caller != "" {
		data["caller"] = entry.Caller
	}

	// Fields
	if len(entry.Fields) > 0 {
		for k, v := range entry.Fields {
			data[k] = v
		}
	}

	// Error
	if entry.Error != nil {
		data["error"] = entry.Error.Error()
	}

	// Structured data
	if entry.Data != nil {
		data["data"] = entry.Data
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Add newline
	result := append(bytes, '\n')
	return result, nil
}

// CloudWatchFormatter formats logs for AWS CloudWatch
type CloudWatchFormatter struct {
	*JSONFormatter
}

// NewCloudWatchFormatter creates a new CloudWatch formatter
func NewCloudWatchFormatter(config *Config) *CloudWatchFormatter {
	return &CloudWatchFormatter{
		JSONFormatter: NewJSONFormatter(config),
	}
}

// Format formats a log entry for CloudWatch
func (f *CloudWatchFormatter) Format(entry *LogEntry) ([]byte, error) {
	data := make(map[string]interface{})

	// CloudWatch standard fields
	data["level"] = entry.Level.String()
	data["msg"] = entry.Message
	data["time"] = entry.Timestamp.Format(time.RFC3339Nano)

	// Caller
	if f.config.EnableCaller && entry.Caller != "" {
		data["caller"] = entry.Caller
	}

	// Fields
	if len(entry.Fields) > 0 {
		for k, v := range entry.Fields {
			data[k] = v
		}
	}

	// Error
	if entry.Error != nil {
		data["error"] = entry.Error.Error()
		data["error_type"] = "error"
	}

	// Structured data
	if entry.Data != nil {
		data["data"] = entry.Data
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Add newline
	result := append(bytes, '\n')
	return result, nil
}
