package logx

import (
	"os"
	"strings"
	"time"
)

// Format represents the output format
type Format string

const (
	// FormatConsole outputs colored console logs (default)
	FormatConsole Format = "console"
	// FormatJSON outputs JSON formatted logs
	FormatJSON Format = "json"
	// FormatCloudWatch outputs CloudWatch compatible JSON
	FormatCloudWatch Format = "cloudwatch"
)

// Config holds the logger configuration
type Config struct {
	// Level is the minimum log level to output
	Level Level

	// Format is the output format
	Format Format

	// EnableColors enables colored output (only for console format)
	EnableColors bool

	// EnableCaller adds file and line number to logs
	EnableCaller bool

	// EnableTimestamp adds timestamp to logs
	EnableTimestamp bool

	// TimeFormat is the time format to use (defaults to RFC3339)
	TimeFormat string

	// Output is where to write logs (defaults to os.Stdout)
	Output *os.File
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Level:           LevelInfo,
		Format:          FormatConsole,
		EnableColors:    true,
		EnableCaller:    false,
		EnableTimestamp: true,
		TimeFormat:      time.RFC3339,
		Output:          os.Stdout,
	}
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() *Config {
	config := DefaultConfig()

	// LOG_LEVEL
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		config.Level = ParseLevel(level)
	}

	// LOG_FORMAT
	if format := os.Getenv("LOG_FORMAT"); format != "" {
		switch strings.ToLower(format) {
		case "json":
			config.Format = FormatJSON
		case "cloudwatch":
			config.Format = FormatCloudWatch
		case "console":
			config.Format = FormatConsole
		}
	}

	// LOG_COLOR
	if color := os.Getenv("LOG_COLOR"); color != "" {
		config.EnableColors = strings.ToLower(color) == "true" || color == "1"
	}

	// LOG_CALLER
	if caller := os.Getenv("LOG_CALLER"); caller != "" {
		config.EnableCaller = strings.ToLower(caller) == "true" || caller == "1"
	}

	// LOG_TIME_FORMAT
	if timeFormat := os.Getenv("LOG_TIME_FORMAT"); timeFormat != "" {
		switch strings.ToUpper(timeFormat) {
		case "RFC3339":
			config.TimeFormat = time.RFC3339
		case "RFC3339NANO":
			config.TimeFormat = time.RFC3339Nano
		case "RFC822":
			config.TimeFormat = time.RFC822
		case "UNIX":
			config.TimeFormat = "unix"
		case "UNIXMILLI":
			config.TimeFormat = "unixmilli"
		default:
			config.TimeFormat = timeFormat
		}
	}

	return config
}
