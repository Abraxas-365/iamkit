package identity

import (
	"database/sql/driver"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/google/uuid"
)

// ID is a validated UUID identity. The zero value is invalid.
// The phantom type parameter provides compile-time discrimination
// between entity kinds without runtime cost.
type ID[T any] struct{ v uuid.UUID }

// ParseID parses a raw string into a typed ID, returning a validation
// error if the string is not a valid UUID.
func ParseID[T any](raw string) (ID[T], error) {
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return ID[T]{}, errx.Validation(tagName[T]() + " must be a valid UUID")
	}
	return ID[T]{v: parsed}, nil
}

// MustParseID is like ParseID but panics on invalid input.
// Use only in tests and static initialization.
func MustParseID[T any](raw string) ID[T] {
	id, err := ParseID[T](raw)
	if err != nil {
		panic(err)
	}
	return id
}

// NewID generates a new random UUID for the given entity kind.
func NewID[T any]() ID[T] { return ID[T]{v: uuid.New()} }

func (id ID[T]) String() string  { return id.v.String() }
func (id ID[T]) IsZero() bool    { return id.v == uuid.Nil }
func (id ID[T]) UUID() uuid.UUID { return id.v }

// MarshalText implements encoding.TextMarshaler (used by encoding/json).
func (id ID[T]) MarshalText() ([]byte, error) {
	if id.IsZero() {
		return []byte(""), nil
	}
	return []byte(id.v.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler (used by encoding/json).
func (id *ID[T]) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		id.v = uuid.Nil
		return nil
	}
	parsed, err := uuid.Parse(string(b))
	if err != nil {
		return errx.Validation(tagName[T]() + " must be a valid UUID")
	}
	id.v = parsed
	return nil
}

// Value implements database/sql/driver.Valuer.
func (id ID[T]) Value() (driver.Value, error) {
	if id.IsZero() {
		return nil, nil
	}
	return id.v.String(), nil
}

// Scan implements database/sql.Scanner.
func (id *ID[T]) Scan(src any) error {
	if src == nil {
		id.v = uuid.Nil
		return nil
	}
	switch v := src.(type) {
	case string:
		parsed, err := uuid.Parse(v)
		if err != nil {
			return errx.Validation(tagName[T]() + " must be a valid UUID")
		}
		id.v = parsed
	case []byte:
		parsed, err := uuid.ParseBytes(v)
		if err != nil {
			return errx.Validation(tagName[T]() + " must be a valid UUID")
		}
		id.v = parsed
	default:
		return errx.Internal("cannot scan into " + tagName[T]())
	}
	return nil
}

// ---------- Entity tags (unexported, zero-size) ----------

type (
	environmentTag  struct{}
	organizationTag struct{}
	applicationTag  struct{}
	resourceTag     struct{}
	userTag         struct{}
	sessionTag      struct{}
	roleTag         struct{}
	grantTag        struct{}
	connectionTag   struct{}
	workspaceTag    struct{}
	projectTag      struct{}
	operatorTag     struct{}
	credentialTag   struct{}
	unitTag         struct{}
	positionTag     struct{}
	assignmentTag   struct{}
	challengeTag    struct{}
	accountTag      struct{} // service account
	clientTag       struct{} // oauth client
	keyTag          struct{} // management key
)

// tagName returns a human-readable name for error messages.
func tagName[T any]() string {
	var zero T
	switch any(zero).(type) {
	case environmentTag:
		return "environment_id"
	case organizationTag:
		return "organization_id"
	case applicationTag:
		return "application_id"
	case resourceTag:
		return "resource_id"
	case userTag:
		return "user_id"
	case sessionTag:
		return "session_id"
	case roleTag:
		return "role_id"
	case grantTag:
		return "grant_id"
	case connectionTag:
		return "connection_id"
	case workspaceTag:
		return "workspace_id"
	case projectTag:
		return "project_id"
	case operatorTag:
		return "operator_id"
	case credentialTag:
		return "credential_id"
	case unitTag:
		return "unit_id"
	case positionTag:
		return "position_id"
	case assignmentTag:
		return "assignment_id"
	case challengeTag:
		return "challenge_id"
	case accountTag:
		return "service_account_id"
	case clientTag:
		return "client_id"
	case keyTag:
		return "key_id"
	default:
		return "id"
	}
}

// ---------- Public type aliases ----------

type (
	EnvironmentID  = ID[environmentTag]
	OrganizationID = ID[organizationTag]
	ApplicationID  = ID[applicationTag]
	ResourceID     = ID[resourceTag]
	UserID         = ID[userTag]
	SessionID      = ID[sessionTag]
	RoleID         = ID[roleTag]
	GrantID        = ID[grantTag]
	ConnectionID   = ID[connectionTag]
	WorkspaceID    = ID[workspaceTag]
	ProjectID      = ID[projectTag]
	OperatorID     = ID[operatorTag]
	CredentialID   = ID[credentialTag]
	UnitID         = ID[unitTag]
	PositionID     = ID[positionTag]
	AssignmentID   = ID[assignmentTag]
	ChallengeID    = ID[challengeTag]
	AccountID      = ID[accountTag]
	ClientID       = ID[clientTag]
	KeyID          = ID[keyTag]
)

// ---------- Typed constructors (callable from outside the package) ----------

func NewEnvironmentID() EnvironmentID   { return NewID[environmentTag]() }
func NewOrganizationID() OrganizationID { return NewID[organizationTag]() }
func NewApplicationID() ApplicationID   { return NewID[applicationTag]() }
func NewResourceID() ResourceID         { return NewID[resourceTag]() }
func NewUserID() UserID                 { return NewID[userTag]() }
func NewSessionID() SessionID           { return NewID[sessionTag]() }
func NewRoleID() RoleID                 { return NewID[roleTag]() }
func NewGrantID() GrantID               { return NewID[grantTag]() }
func NewConnectionID() ConnectionID     { return NewID[connectionTag]() }
func NewWorkspaceID() WorkspaceID       { return NewID[workspaceTag]() }
func NewProjectID() ProjectID           { return NewID[projectTag]() }
func NewOperatorID() OperatorID         { return NewID[operatorTag]() }
func NewCredentialID() CredentialID     { return NewID[credentialTag]() }
func NewUnitID() UnitID                 { return NewID[unitTag]() }
func NewPositionID() PositionID         { return NewID[positionTag]() }
func NewAssignmentID() AssignmentID     { return NewID[assignmentTag]() }
func NewChallengeID() ChallengeID       { return NewID[challengeTag]() }
func NewAccountID() AccountID           { return NewID[accountTag]() }
func NewClientID() ClientID             { return NewID[clientTag]() }
func NewKeyID() KeyID                   { return NewID[keyTag]() }

// ---------- Typed parsers (callable from outside the package) ----------

func ParseEnvironmentID(raw string) (EnvironmentID, error)   { return ParseID[environmentTag](raw) }
func ParseOrganizationID(raw string) (OrganizationID, error) { return ParseID[organizationTag](raw) }
func ParseApplicationID(raw string) (ApplicationID, error)   { return ParseID[applicationTag](raw) }
func ParseResourceID(raw string) (ResourceID, error)         { return ParseID[resourceTag](raw) }
func ParseUserID(raw string) (UserID, error)                 { return ParseID[userTag](raw) }
func ParseSessionID(raw string) (SessionID, error)           { return ParseID[sessionTag](raw) }
func ParseRoleID(raw string) (RoleID, error)                 { return ParseID[roleTag](raw) }
func ParseGrantID(raw string) (GrantID, error)               { return ParseID[grantTag](raw) }
func ParseConnectionID(raw string) (ConnectionID, error)     { return ParseID[connectionTag](raw) }
func ParseWorkspaceID(raw string) (WorkspaceID, error)       { return ParseID[workspaceTag](raw) }
func ParseProjectID(raw string) (ProjectID, error)           { return ParseID[projectTag](raw) }
func ParseOperatorID(raw string) (OperatorID, error)         { return ParseID[operatorTag](raw) }
func ParseCredentialID(raw string) (CredentialID, error)     { return ParseID[credentialTag](raw) }
func ParseUnitID(raw string) (UnitID, error)                 { return ParseID[unitTag](raw) }
func ParsePositionID(raw string) (PositionID, error)         { return ParseID[positionTag](raw) }
func ParseAssignmentID(raw string) (AssignmentID, error)     { return ParseID[assignmentTag](raw) }
func ParseChallengeID(raw string) (ChallengeID, error)       { return ParseID[challengeTag](raw) }
func ParseAccountID(raw string) (AccountID, error)           { return ParseID[accountTag](raw) }
func ParseClientID(raw string) (ClientID, error)             { return ParseID[clientTag](raw) }
func ParseKeyID(raw string) (KeyID, error)                   { return ParseID[keyTag](raw) }

// MustParse convenience functions — panic on invalid input; use in tests and static init.
func MustParseEnvironmentID(raw string) EnvironmentID   { return MustParseID[environmentTag](raw) }
func MustParseOrganizationID(raw string) OrganizationID { return MustParseID[organizationTag](raw) }
func MustParseApplicationID(raw string) ApplicationID   { return MustParseID[applicationTag](raw) }
func MustParseResourceID(raw string) ResourceID         { return MustParseID[resourceTag](raw) }
func MustParseUserID(raw string) UserID                 { return MustParseID[userTag](raw) }
func MustParseSessionID(raw string) SessionID           { return MustParseID[sessionTag](raw) }
func MustParseRoleID(raw string) RoleID                 { return MustParseID[roleTag](raw) }
func MustParseGrantID(raw string) GrantID               { return MustParseID[grantTag](raw) }
func MustParseConnectionID(raw string) ConnectionID     { return MustParseID[connectionTag](raw) }
func MustParseWorkspaceID(raw string) WorkspaceID       { return MustParseID[workspaceTag](raw) }
func MustParseProjectID(raw string) ProjectID           { return MustParseID[projectTag](raw) }
func MustParseOperatorID(raw string) OperatorID         { return MustParseID[operatorTag](raw) }
func MustParseCredentialID(raw string) CredentialID     { return MustParseID[credentialTag](raw) }
func MustParseUnitID(raw string) UnitID                 { return MustParseID[unitTag](raw) }
func MustParsePositionID(raw string) PositionID         { return MustParseID[positionTag](raw) }
func MustParseAssignmentID(raw string) AssignmentID     { return MustParseID[assignmentTag](raw) }
func MustParseChallengeID(raw string) ChallengeID       { return MustParseID[challengeTag](raw) }
func MustParseAccountID(raw string) AccountID           { return MustParseID[accountTag](raw) }
func MustParseClientID(raw string) ClientID             { return MustParseID[clientTag](raw) }
func MustParseKeyID(raw string) KeyID                   { return MustParseID[keyTag](raw) }
