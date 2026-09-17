package errx

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Error represents a rich error with context and metadata
type Error struct {
	// Code is the unique error code
	Code string `json:"code"`

	// Message is the human-readable error message
	Message string `json:"message"`

	// Type categorizes the error
	Type Type `json:"type"`

	// HTTPStatus is the suggested HTTP status code
	HTTPStatus int `json:"http_status"`

	// Details contains additional context about the error
	Details map[string]interface{} `json:"details,omitempty"`

	// Err is the underlying error (not exported in JSON)
	Err error `json:"-"`
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *Error) Unwrap() error {
	return e.Err
}

// WithDetail adds a detail to the error and returns the error for chaining
func (e *Error) WithDetail(key string, value interface{}) *Error {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithDetails adds multiple details to the error
func (e *Error) WithDetails(details map[string]interface{}) *Error {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// MarshalJSON implements json.Marshaler
func (e *Error) MarshalJSON() ([]byte, error) {
	type Alias Error
	return json.Marshal((*Alias)(e))
}

// New creates a new Error
func New(message string, errType Type) *Error {
	return &Error{
		Code:       string(errType),
		Message:    message,
		Type:       errType,
		HTTPStatus: typeToHTTPStatus(errType),
		Details:    make(map[string]interface{}),
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, message string, errType Type) *Error {
	if err == nil {
		return nil
	}

	// If it's already an Error, preserve its semantics entirely
	var existingErr *Error
	if errors.As(err, &existingErr) {
		return &Error{
			Code:       existingErr.Code,
			Message:    message,
			Type:       existingErr.Type,
			HTTPStatus: existingErr.HTTPStatus,
			Details:    existingErr.Details,
			Err:        err,
		}
	}

	return &Error{
		Code:       string(errType),
		Message:    message,
		Type:       errType,
		HTTPStatus: typeToHTTPStatus(errType),
		Details:    make(map[string]interface{}),
		Err:        err,
	}
}

// Wrapf wraps an error with a formatted message
func Wrapf(err error, errType Type, format string, args ...interface{}) *Error {
	return Wrap(err, fmt.Sprintf(format, args...), errType)
}

// Is checks if an error matches the target error
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// typeToHTTPStatus maps error types to HTTP status codes
func typeToHTTPStatus(t Type) int {
	switch t {
	case TypeValidation:
		return 400 // Bad Request
	case TypeAuthorization:
		return 401 // Unauthorized
	case TypeNotFound:
		return 404 // Not Found
	case TypeConflict:
		return 409 // Conflict
	case TypeBusiness:
		return 422 // Unprocessable Entity
	case TypeExternal:
		return 502 // Bad Gateway
	case TypeInternal:
		return 500 // Internal Server Error
	default:
		return 500
	}
}

func (r *Registry) NewWithCause(code *ErrorCode, cause error) *Error {
	return &Error{
		Code:       code.Code,
		Message:    code.Message,
		Type:       code.Type,
		HTTPStatus: code.HTTPStatus,
		Details:    make(map[string]interface{}),
		Err:        cause,
	}
}
