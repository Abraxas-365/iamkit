package logx

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Logger is the main logger instance
type Logger struct {
	config    *Config
	formatter Formatter
	mu        sync.Mutex
	writer    io.Writer
	exitFunc  func(int)
}

// NewLogger creates a new logger with the given config
func NewLogger(config *Config) *Logger {
	if config == nil {
		config = DefaultConfig()
	}

	var formatter Formatter
	switch config.Format {
	case FormatJSON:
		formatter = NewJSONFormatter(config)
	case FormatCloudWatch:
		formatter = NewCloudWatchFormatter(config)
	default:
		formatter = NewConsoleFormatter(config)
	}

	writer := config.Output
	if writer == nil {
		writer = os.Stdout
	}

	return &Logger{
		config:    config,
		formatter: formatter,
		writer:    writer,
		exitFunc:  os.Exit,
	}
}

// SetLevel sets the log level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config.Level = level
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config.Level
}

// SetOutput sets the output writer
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writer = w
}

// log is the internal logging method
func (l *Logger) log(level Level, msg string, fields Fields, data interface{}, err error) {
	// Check if level is enabled
	if !l.config.Level.Enabled(level) {
		return
	}

	entry := &LogEntry{
		Level:     level,
		Message:   msg,
		Fields:    fields,
		Data:      data,
		Error:     err,
		Timestamp: time.Now(),
	}

	// Get caller info if enabled
	if l.config.EnableCaller {
		entry.Caller = getCaller(3)
	}

	// Format the entry
	formatted, formatErr := l.formatter.Format(entry)
	if formatErr != nil {
		fmt.Fprintf(os.Stderr, "Error formatting log: %v\n", formatErr)
		return
	}

	// Write to output
	l.mu.Lock()
	defer l.mu.Unlock()

	_, writeErr := l.writer.Write(formatted)
	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "Error writing log: %v\n", writeErr)
	}
}

// WithField creates a new entry with a field
func (l *Logger) WithField(key string, value interface{}) *Entry {
	entry := newEntry(l)
	return entry.WithField(key, value)
}

// WithFields creates a new entry with fields
func (l *Logger) WithFields(fields Fields) *Entry {
	entry := newEntry(l)
	return entry.WithFields(fields)
}

// WithError creates a new entry with an error
func (l *Logger) WithError(err error) *Entry {
	entry := newEntry(l)
	return entry.WithError(err)
}

// WithStruct creates a new entry with structured data
func (l *Logger) WithStruct(data interface{}) *Entry {
	entry := newEntry(l)
	return entry.WithStruct(data)
}

// exit calls the exit function (useful for testing)
func (l *Logger) exit(code int) {
	l.exitFunc(code)
}

// getCaller returns the file and line number of the caller
func getCaller(skip int) string {
	_, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "???"
	}

	// Get just the filename, not the full path
	parts := strings.Split(file, "/")
	file = parts[len(parts)-1]

	return fmt.Sprintf("%s:%d", file, line)
}
