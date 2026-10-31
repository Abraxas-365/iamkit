package iamclient

import "context"

// Event retention classes: Event.RetentionClass.
const (
	RetentionClassSecurity = "security"
	RetentionClassDefault  = "default"
)

// RetentionSeconds is a value per retention class, in seconds.
type RetentionSeconds struct {
	Security int64 `json:"security"`
	Default  int64 `json:"default"`
}

// EventRetention is how long an environment keeps its events. The
// deployment sets a ceiling per class (IAMKIT_SECURITY_EVENT_RETENTION,
// IAMKIT_EVENT_RETENTION); the environment's own values can only shorten
// them. SecuritySeconds and DefaultSeconds are the environment's own
// values (nil: the ceiling); Effective is what events are pruned by.
type EventRetention struct {
	SecuritySeconds *int64           `json:"security_retention_seconds"`
	DefaultSeconds  *int64           `json:"default_retention_seconds"`
	Ceilings        RetentionSeconds `json:"ceilings"`
	Effective       RetentionSeconds `json:"effective"`
}

// EventRetentionInput replaces the environment's values: nil keeps the
// deployment's ceiling, a number (at least 86400, at most the ceiling —
// otherwise 422 RETENTION_OUT_OF_RANGE) shortens it.
type EventRetentionInput struct {
	SecuritySeconds *int64 `json:"security_retention_seconds"`
	DefaultSeconds  *int64 `json:"default_retention_seconds"`
}

// EventRetention returns the environment's event retention.
func (e Environment) EventRetention(ctx context.Context) (EventRetention, error) {
	var out EventRetention
	err := e.operation(ctx, "GET", []string{"event-retention"}, nil, &out)
	return out, err
}

// SetEventRetention replaces the environment's event retention. Workspace
// owners only; audited as event_retention.updated.
func (e Environment) SetEventRetention(ctx context.Context, input EventRetentionInput) (EventRetention, error) {
	var out EventRetention
	err := e.operation(ctx, "PUT", []string{"event-retention"}, input, &out)
	return out, err
}
