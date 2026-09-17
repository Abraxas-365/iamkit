package logx

import (
	"strings"
)

// Level represents logging level
type Level uint8

const (
	// LevelTrace is the most verbose level
	LevelTrace Level = iota
	// LevelDebug for debugging information
	LevelDebug
	// LevelInfo for informational messages
	LevelInfo
	// LevelWarn for warning messages
	LevelWarn
	// LevelError for error messages
	LevelError
	// LevelFatal for fatal messages (will exit)
	LevelFatal
	// LevelOff disables all logging
	LevelOff
)

// String returns the string representation of the log level
func (l Level) String() string {
	switch l {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	case LevelOff:
		return "OFF"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a string into a Level
func ParseLevel(level string) Level {
	switch strings.ToUpper(level) {
	case "TRACE":
		return LevelTrace
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR":
		return LevelError
	case "FATAL":
		return LevelFatal
	case "OFF":
		return LevelOff
	default:
		return LevelInfo
	}
}

// Enabled checks if a level is enabled for the current log level
func (l Level) Enabled(target Level) bool {
	return l <= target
}
