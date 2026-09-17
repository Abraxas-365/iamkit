package errx

import (
	"fmt"
	"sync"
)

// ErrorCode represents a registered error code
type ErrorCode struct {
	Code       string
	Type       Type
	HTTPStatus int
	Message    string
}

// Registry manages error codes for a module
type Registry struct {
	prefix string
	codes  map[string]*ErrorCode
	mu     sync.RWMutex
}

// NewRegistry creates a new error registry with a prefix
func NewRegistry(prefix string) *Registry {
	return &Registry{
		prefix: prefix,
		codes:  make(map[string]*ErrorCode),
	}
}

// Register registers a new error code
func (r *Registry) Register(code string, errType Type, httpStatus int, message string) *ErrorCode {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullCode := fmt.Sprintf("%s_%s", r.prefix, code)

	errorCode := &ErrorCode{
		Code:       fullCode,
		Type:       errType,
		HTTPStatus: httpStatus,
		Message:    message,
	}

	r.codes[code] = errorCode
	return errorCode
}

// New creates a new error from a registered code
func (r *Registry) New(code *ErrorCode) *Error {
	return &Error{
		Code:       code.Code,
		Message:    code.Message,
		Type:       code.Type,
		HTTPStatus: code.HTTPStatus,
		Details:    make(map[string]interface{}),
	}
}

// NewWithMessage creates a new error with a custom message
func (r *Registry) NewWithMessage(code *ErrorCode, message string) *Error {
	return &Error{
		Code:       code.Code,
		Message:    message,
		Type:       code.Type,
		HTTPStatus: code.HTTPStatus,
		Details:    make(map[string]interface{}),
	}
}

// Get retrieves a registered error code
func (r *Registry) Get(code string) (*ErrorCode, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	errorCode, exists := r.codes[code]
	return errorCode, exists
}

// Codes returns all registered error codes
func (r *Registry) Codes() map[string]*ErrorCode {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to prevent external modifications
	codes := make(map[string]*ErrorCode, len(r.codes))
	for k, v := range r.codes {
		codes[k] = v
	}
	return codes
}
