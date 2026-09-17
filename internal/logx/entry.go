package logx

import (
	"context"
	"fmt"
)

// Entry allows for building up log entries with multiple fields
type Entry struct {
	logger *Logger
	fields Fields
	data   interface{}
	err    error
	ctx    context.Context
}

// newEntry creates a new entry
func newEntry(logger *Logger) *Entry {
	return &Entry{
		logger: logger,
		fields: make(Fields),
	}
}

// WithField adds a field to the entry (chainable)
func (e *Entry) WithField(key string, value interface{}) *Entry {
	e.fields[key] = value
	return e
}

// WithFields adds multiple fields to the entry (chainable)
func (e *Entry) WithFields(fields Fields) *Entry {
	for k, v := range fields {
		e.fields[k] = v
	}
	return e
}

// WithError adds an error field (chainable)
func (e *Entry) WithError(err error) *Entry {
	e.err = err
	if err != nil {
		e.fields["error"] = err.Error()
	}
	return e
}

// WithContext adds context (chainable)
func (e *Entry) WithContext(ctx context.Context) *Entry {
	e.ctx = ctx
	return e
}

// WithStruct adds structured data (chainable)
func (e *Entry) WithStruct(data interface{}) *Entry {
	e.data = data
	return e
}

// Trace logs at trace level
func (e *Entry) Trace(msg string) {
	e.logger.log(LevelTrace, msg, e.fields, e.data, e.err)
}

// Debug logs at debug level
func (e *Entry) Debug(msg string) {
	e.logger.log(LevelDebug, msg, e.fields, e.data, e.err)
}

// Info logs at info level
func (e *Entry) Info(msg string) {
	e.logger.log(LevelInfo, msg, e.fields, e.data, e.err)
}

// Warn logs at warn level
func (e *Entry) Warn(msg string) {
	e.logger.log(LevelWarn, msg, e.fields, e.data, e.err)
}

// Error logs at error level
func (e *Entry) Error(msg string) {
	e.logger.log(LevelError, msg, e.fields, e.data, e.err)
}

// Fatal logs at fatal level and exits
func (e *Entry) Fatal(msg string) {
	e.logger.log(LevelFatal, msg, e.fields, e.data, e.err)
	e.logger.exit(1)
}

// Tracef logs formatted trace message
func (e *Entry) Tracef(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	e.logger.log(LevelTrace, msg, e.fields, e.data, e.err)
}

// Debugf logs formatted debug message
func (e *Entry) Debugf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	e.logger.log(LevelDebug, msg, e.fields, e.data, e.err)
}

// Infof logs formatted info message
func (e *Entry) Infof(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	e.logger.log(LevelInfo, msg, e.fields, e.data, e.err)
}

// Warnf logs formatted warn message
func (e *Entry) Warnf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	e.logger.log(LevelWarn, msg, e.fields, e.data, e.err)
}

// Errorf logs formatted error message
func (e *Entry) Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	e.logger.log(LevelError, msg, e.fields, e.data, e.err)
}

// Fatalf logs formatted fatal message and exits
func (e *Entry) Fatalf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	e.logger.log(LevelFatal, msg, e.fields, e.data, e.err)
	e.logger.exit(1)
}
