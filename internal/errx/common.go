package errx

// Common error constructors for convenience

// Internal creates an internal server error
func Internal(message string) *Error {
	return New(message, TypeInternal)
}

// Validation creates a validation error
func Validation(message string) *Error {
	return New(message, TypeValidation)
}

// NotFound creates a not found error
func NotFound(message string) *Error {
	return New(message, TypeNotFound)
}

// Unauthorized creates an authorization error
func Unauthorized(message string) *Error {
	return New(message, TypeAuthorization)
}

// Forbidden creates an authorization error for an authenticated caller without access.
func Forbidden(message string) *Error {
	err := New(message, TypeAuthorization)
	err.Code = "FORBIDDEN"
	err.HTTPStatus = 403
	return err
}

// Conflict creates a conflict error
func Conflict(message string) *Error {
	return New(message, TypeConflict)
}

// TooManyRequests creates a 429 error for a caller that must wait (e.g. a
// locked second factor).
func TooManyRequests(message string) *Error {
	err := New(message, TypeBusiness)
	err.Code = "TOO_MANY_REQUESTS"
	err.HTTPStatus = 429
	return err
}

// Business creates a business logic error
func Business(message string) *Error {
	return New(message, TypeBusiness)
}

// External creates an external service error
func External(message string) *Error {
	return New(message, TypeExternal)
}
