package auditlog

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ActionCommands change the catalog of registered actions (audited).
type ActionCommands interface {
	CreateAction(ctx context.Context, m Mutation, input ActionInput) (Action, error)
	UpdateAction(ctx context.Context, m Mutation, action identity.AuditActionID, input ActionUpdate) (Action, error)
	// DeleteAction removes the action; its events keep the name.
	DeleteAction(ctx context.Context, m Mutation, action identity.AuditActionID) error
}

// ActionQueries read the catalog.
type ActionQueries interface {
	ListActions(ctx context.Context, environment identity.EnvironmentID) ([]Action, error)
	FindAction(ctx context.Context, environment identity.EnvironmentID, action identity.AuditActionID) (Action, error)
}

// ActionRepository persists the catalog.
type ActionRepository interface {
	// CreateAction stores the action (version 1) and records the audit
	// entry in one transaction; a taken name is a conflict.
	CreateAction(ctx context.Context, m Mutation, action Action) error
	// UpdateAction stores the action's description, target types and
	// schema; bump raises its version in the same statement. The audit
	// entry is written in the same transaction.
	UpdateAction(ctx context.Context, m Mutation, action Action, bump bool) error
	DeleteAction(ctx context.Context, m Mutation, action identity.AuditActionID) error
	FindAction(ctx context.Context, environment identity.EnvironmentID, action identity.AuditActionID) (Action, error)
	FindActionByName(ctx context.Context, environment identity.EnvironmentID, name string) (Action, error)
	ListActions(ctx context.Context, environment identity.EnvironmentID) ([]Action, error)
	CountActions(ctx context.Context, environment identity.EnvironmentID) (int, error)
}

// EventCommands emit events.
type EventCommands interface {
	// Emit validates and stores one event. key is the optional
	// Idempotency-Key: the same key with the same request answers the
	// first receipt, another request is 409 IDEMPOTENCY_KEY_REUSED.
	Emit(ctx context.Context, environment identity.EnvironmentID, input Input, key string) (Receipt, error)
	// Prune deletes events past the retention (the audit_log_prune job);
	// more asks for another round at once.
	Prune(ctx context.Context) (more bool, err error)
}

// EventQueries read the log.
type EventQueries interface {
	List(ctx context.Context, environment identity.EnvironmentID, filter Filter, limit int) (Page, error)
	Find(ctx context.Context, environment identity.EnvironmentID, event identity.AuditEventID) (Event, error)
	// Export reads the matching events oldest first, from filter.After, in
	// batches, until the newest; write's error stops it.
	Export(ctx context.Context, environment identity.EnvironmentID, filter Filter, write func(Event) error) error
}

// EventRepository persists events. It writes nothing to IAMKit's own
// event log.
type EventRepository interface {
	OrganizationExists(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID) (bool, error)
	// Insert stores the event. With an Idempotency whose key is taken
	// (even by a concurrent insert) nothing is stored and the existing
	// row's receipt and request hash come back with Replayed set.
	Insert(ctx context.Context, event Event, idempotency *Idempotency) (Inserted, error)
	// FindKey reads the event an Idempotency-Key created, if any.
	FindKey(ctx context.Context, environment identity.EnvironmentID, key string) (Inserted, bool, error)
	Find(ctx context.Context, environment identity.EnvironmentID, event identity.AuditEventID) (Event, error)
	// List pages by seq (keyset): oldest first from filter.After, else
	// newest first below filter.Before.
	List(ctx context.Context, environment identity.EnvironmentID, filter Filter, limit int) ([]Event, error)
	// Prune deletes up to batch events created before cutoff in one
	// transaction and reports how many.
	Prune(ctx context.Context, cutoff time.Time, batch int) (int, error)
}

// SchemaValidator compiles and applies the JSON Schemas of actions
// (draft 2020-12, remote references refused).
type SchemaValidator interface {
	Check(schema json.RawMessage) error
	Validate(schema, document json.RawMessage) error
}

// Usage meters ingest (usage.Commands): Admit takes a slot of the
// environment's audit_events_per_minute, Count adds accepted events to
// today's usage.
type Usage interface {
	Admit(ctx context.Context, environment identity.EnvironmentID, limit string) error
	Count(ctx context.Context, environment identity.EnvironmentID, metric string, n int64)
}
