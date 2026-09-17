package errx

// Type represents the category of error
type Type string

const (
	// TypeInternal represents internal server errors
	TypeInternal Type = "INTERNAL"

	// TypeValidation represents validation errors
	TypeValidation Type = "VALIDATION"

	// TypeAuthorization represents authorization/authentication errors
	TypeAuthorization Type = "AUTHORIZATION"

	// TypeNotFound represents resource not found errors
	TypeNotFound Type = "NOT_FOUND"

	// TypeConflict represents resource conflict errors
	TypeConflict Type = "CONFLICT"

	// TypeBusiness represents business logic errors
	TypeBusiness Type = "BUSINESS"

	// TypeExternal represents errors from external services
	TypeExternal Type = "EXTERNAL"
)

// String returns the string representation of the error type
func (t Type) String() string {
	return string(t)
}
