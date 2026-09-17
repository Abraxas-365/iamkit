package logx

import (
	"context"
	"fmt"
	"os"
)

var (
	// defaultLogger is the global logger instance
	defaultLogger *Logger
)

func init() {
	// Initialize with config from environment
	defaultLogger = NewLogger(LoadFromEnv())
}

// SetDefaultLogger sets the default logger
func SetDefaultLogger(logger *Logger) {
	defaultLogger = logger
}

// GetDefaultLogger returns the default logger
func GetDefaultLogger() *Logger {
	return defaultLogger
}

// SetLevel sets the log level for the default logger
func SetLevel(level Level) {
	defaultLogger.SetLevel(level)
}

// SetOutput sets the output for the default logger
func SetOutput(w *os.File) {
	defaultLogger.SetOutput(w)
}

// ============================================================================
// Simple Logging Functions
// ============================================================================

// Trace logs a trace level message
func Trace(msg string) {
	defaultLogger.log(LevelTrace, msg, nil, nil, nil)
}

// Debug logs a debug level message
func Debug(msg string) {
	defaultLogger.log(LevelDebug, msg, nil, nil, nil)
}

// Info logs an info level message
func Info(msg string) {
	defaultLogger.log(LevelInfo, msg, nil, nil, nil)
}

// Warn logs a warning level message
func Warn(msg string) {
	defaultLogger.log(LevelWarn, msg, nil, nil, nil)
}

// Error logs an error level message
func Error(msg string) {
	defaultLogger.log(LevelError, msg, nil, nil, nil)
}

// Fatal logs a fatal level message and exits
func Fatal(msg string) {
	defaultLogger.log(LevelFatal, msg, nil, nil, nil)
	defaultLogger.exit(1)
}

// ============================================================================
// Formatted Logging Functions
// ============================================================================

// Tracef logs a formatted trace message
func Tracef(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	defaultLogger.log(LevelTrace, msg, nil, nil, nil)
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	defaultLogger.log(LevelDebug, msg, nil, nil, nil)
}

// Infof logs a formatted info message
func Infof(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	defaultLogger.log(LevelInfo, msg, nil, nil, nil)
}

// Warnf logs a formatted warning message
func Warnf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	defaultLogger.log(LevelWarn, msg, nil, nil, nil)
}

// Errorf logs a formatted error message
func Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	defaultLogger.log(LevelError, msg, nil, nil, nil)
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	defaultLogger.log(LevelFatal, msg, nil, nil, nil)
	defaultLogger.exit(1)
}

// ============================================================================
// Structured Logging
// ============================================================================

// WithFields creates a new logger entry with fields
func WithFields(fields Fields) *Entry {
	return defaultLogger.WithFields(fields)
}

// WithField creates a new logger entry with a single field
func WithField(key string, value interface{}) *Entry {
	return defaultLogger.WithField(key, value)
}

// WithContext creates a new logger entry with context
func WithContext(ctx context.Context) *Entry {
	entry := newEntry(defaultLogger)
	return entry.WithContext(ctx)
}

// WithError creates a new logger entry with an error field
func WithError(err error) *Entry {
	return defaultLogger.WithError(err)
}

// WithStruct creates a new logger entry with structured data
func WithStruct(data interface{}) *Entry {
	return defaultLogger.WithStruct(data)
}

// ============================================================================
// Panic Functions
// ============================================================================

// Panic logs a message and panics
func Panic(msg string) {
	defaultLogger.log(LevelError, msg, nil, nil, nil)
	panic(msg)
}

// Panicf logs a formatted message and panics
func Panicf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	defaultLogger.log(LevelError, msg, nil, nil, nil)
	panic(msg)
}
