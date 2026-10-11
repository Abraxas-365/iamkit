package auditlog

import (
	"strconv"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

func coded(message, code string) *errx.Error {
	e := errx.Business(message)
	e.Code = code
	return e
}

// ErrUnknownAction is 422 UNKNOWN_AUDIT_ACTION: the action is not
// registered in the environment.
func ErrUnknownAction(name string) error {
	return coded("action "+name+" is not registered in this environment", "UNKNOWN_AUDIT_ACTION")
}

// ErrUnknownOrganization is 422: the organization is not in the environment.
func ErrUnknownOrganization() error {
	return coded("organization_id does not name an organization of this environment", "UNKNOWN_ORGANIZATION")
}

// ErrVersion is 422: the event names a version other than the current one.
func ErrVersion(current int) error {
	return coded("version must be the action's current version, "+strconv.Itoa(current), "AUDIT_ACTION_VERSION")
}

// ErrTargetType is 422: the target's type is not one the action accepts.
func ErrTargetType(field, typ string) error {
	return coded(field+".type "+typ+" is not one of the action's target_types", "AUDIT_TARGET_TYPE")
}

// ErrSchema is 422: the event does not match the action's JSON Schema.
func ErrSchema(field, detail string) error {
	return coded(field+" does not match the action schema: "+detail, "AUDIT_SCHEMA_VIOLATION")
}

// ErrKeyReused is 409: the Idempotency-Key was used with another request.
func ErrKeyReused() error {
	e := errx.Conflict("the Idempotency-Key was already used with a different request")
	e.Code = "IDEMPOTENCY_KEY_REUSED"
	return e
}

// ErrBodyTooLarge is 413: the request body passes config.AuditLogMaxBody.
func ErrBodyTooLarge() error {
	e := errx.Validation("the request body is too large")
	e.Code = "BODY_TOO_LARGE"
	e.HTTPStatus = 413
	return e
}

// ErrActionNotFound / ErrEventNotFound are the 404s.
func ErrActionNotFound() error { return errx.NotFound("audit log action not found") }
func ErrEventNotFound() error  { return errx.NotFound("audit log event not found") }
