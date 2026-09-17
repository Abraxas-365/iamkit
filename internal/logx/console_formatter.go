package logx

import (
	"fmt"
	"strings"
)

// ANSI color codes (Rust-inspired)
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorWhite  = "\033[97m"
	colorGreen  = "\033[32m"

	colorBoldRed    = "\033[1;31m"
	colorBoldYellow = "\033[1;33m"
	colorBoldWhite  = "\033[1;97m"
	colorBoldCyan   = "\033[1;36m"
	colorBoldGreen  = "\033[1;32m"
)

// ConsoleFormatter formats logs for console output with colors
type ConsoleFormatter struct {
	config *Config
}

// NewConsoleFormatter creates a new console formatter
func NewConsoleFormatter(config *Config) *ConsoleFormatter {
	return &ConsoleFormatter{config: config}
}

// Format formats a log entry for console output
func (f *ConsoleFormatter) Format(entry *LogEntry) ([]byte, error) {
	var builder strings.Builder

	// Timestamp
	if f.config.EnableTimestamp {
		timestamp := formatTimestamp(entry.Timestamp, f.config.TimeFormat)
		if f.config.EnableColors {
			builder.WriteString(colorGray)
			builder.WriteString(timestamp)
			builder.WriteString(colorReset)
		} else {
			builder.WriteString(timestamp)
		}
		builder.WriteString(" ")
	}

	// Level with color
	levelStr := f.formatLevel(entry.Level)
	builder.WriteString(levelStr)
	builder.WriteString(" ")

	// Caller
	if f.config.EnableCaller && entry.Caller != "" {
		if f.config.EnableColors {
			builder.WriteString(colorGray)
			builder.WriteString("[")
			builder.WriteString(entry.Caller)
			builder.WriteString("]")
			builder.WriteString(colorReset)
		} else {
			builder.WriteString("[")
			builder.WriteString(entry.Caller)
			builder.WriteString("]")
		}
		builder.WriteString(" ")
	}

	// Message
	if f.config.EnableColors {
		builder.WriteString(colorWhite)
		builder.WriteString(entry.Message)
		builder.WriteString(colorReset)
	} else {
		builder.WriteString(entry.Message)
	}

	// Fields
	if len(entry.Fields) > 0 {
		builder.WriteString(" ")
		if f.config.EnableColors {
			builder.WriteString(colorCyan)
		}

		i := 0
		for k, v := range entry.Fields {
			if i > 0 {
				builder.WriteString(" ")
			}
			builder.WriteString(k)
			builder.WriteString("=")
			builder.WriteString(fmt.Sprintf("%v", v))
			i++
		}

		if f.config.EnableColors {
			builder.WriteString(colorReset)
		}
	}

	// Error
	if entry.Error != nil {
		builder.WriteString("\n")
		if f.config.EnableColors {
			builder.WriteString(colorRed)
			builder.WriteString("  ╰─→ error: ")
			builder.WriteString(entry.Error.Error())
			builder.WriteString(colorReset)
		} else {
			builder.WriteString("  error: ")
			builder.WriteString(entry.Error.Error())
		}
	}

	// Structured data
	if entry.Data != nil {
		builder.WriteString("\n")
		prettyData := prettyJSON(entry.Data)

		if f.config.EnableColors {
			builder.WriteString(colorGray)
		}

		// Indent each line
		lines := strings.Split(prettyData, "\n")
		for _, line := range lines {
			builder.WriteString("  ")
			builder.WriteString(line)
			builder.WriteString("\n")
		}

		if f.config.EnableColors {
			builder.WriteString(colorReset)
		}
	} else {
		builder.WriteString("\n")
	}

	return []byte(builder.String()), nil
}

// formatLevel formats the level with appropriate color
func (f *ConsoleFormatter) formatLevel(level Level) string {
	if !f.config.EnableColors {
		return fmt.Sprintf("[%s]", level.String())
	}

	switch level {
	case LevelTrace:
		return fmt.Sprintf("%s[TRACE]%s", colorGray, colorReset)
	case LevelDebug:
		return fmt.Sprintf("%s[DEBUG]%s", colorBoldCyan, colorReset)
	case LevelInfo:
		return fmt.Sprintf("%s[INFO ]%s", colorBoldGreen, colorReset)
	case LevelWarn:
		return fmt.Sprintf("%s[WARN ]%s", colorBoldYellow, colorReset)
	case LevelError:
		return fmt.Sprintf("%s[ERROR]%s", colorBoldRed, colorReset)
	case LevelFatal:
		return fmt.Sprintf("%s[FATAL]%s", colorBoldRed, colorReset)
	default:
		return fmt.Sprintf("[%s]", level.String())
	}
}
