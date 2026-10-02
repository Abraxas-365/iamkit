// Package event is IAMKit's semantic event log: what changed (user.created,
// role.updated, session.revoked, …), who did it and to what. Events are
// written in the same transaction as the change (the events table is a
// transactional outbox) and are thin: they carry the subject and the ids
// of related entities, never secrets or full records — read the current
// state through the API. Webhooks and the change history read them.
package event

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Actor kinds.
const (
	ActorOperator       = "operator"
	ActorUser           = "user"
	ActorServiceAccount = "service_account"
	// ActorDirectory is a SCIM provisioning credential.
	ActorDirectory = "directory"
	ActorSystem    = "system"
)

type Actor struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
}

type Subject struct {
	Kind string `json:"kind,omitempty"`
	ID   string `json:"id,omitempty"`
}

type Event struct {
	ID           int64                    `json:"id"`
	Environment  identity.EnvironmentID   `json:"environment_id"`
	Type         string                   `json:"type"`
	Actor        Actor                    `json:"actor"`
	Subject      Subject                  `json:"subject"`
	Organization *identity.OrganizationID `json:"organization_id,omitempty"`
	Data         json.RawMessage          `json:"data"`
	OccurredAt   time.Time                `json:"occurred_at"`
}

// Filter narrows the event log. With After (0 = the beginning) the log is
// read oldest first from that id, a feed cursor; otherwise newest first,
// below Before when set.
type Filter struct {
	// Types are exact types (user.created) or families (user.*).
	Types   []string
	Subject string
	// SubjectKind limits the log to one kind of subject (user, role, …);
	// with Subject it is one entity's history.
	SubjectKind string
	After       *int64
	Before      int64
	// Organization limits the log to one organization's events.
	Organization identity.OrganizationID
}

// ExportBatch is how many events one export query reads.
const ExportBatch = 1000

// MaxTypes caps the types one filter may name.
const MaxTypes = 20

// Page limits.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Page is one page of the log. Next is the cursor for the following page:
// with After, pass it as after (the newest id returned, or the cursor
// itself when nothing new arrived); without After, pass it as before (the
// oldest id returned, 0 when the log is exhausted).
type Page struct {
	Items []Event `json:"items"`
	Next  int64   `json:"next"`
}

// Limit clamps a requested page size.
func Limit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	return min(n, MaxLimit)
}

var typePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// ValidType reports whether s is shaped like an event type
// (dotted lowercase words, e.g. user.created).
func ValidType(s string) bool { return typePattern.MatchString(s) }

func (f Filter) Validate() error {
	if len(f.Types) > MaxTypes {
		return errx.Validation("type may name at most 20 event types")
	}
	for _, t := range f.Types {
		if !ValidType(t) && !(strings.HasSuffix(t, ".*") && ValidPrefix(strings.TrimSuffix(t, ".*"))) {
			return errx.Validation("type must be event types such as user.created or user.*")
		}
	}
	if (f.After != nil && *f.After < 0) || f.Before < 0 {
		return errx.Validation("after and before must be event ids")
	}
	if f.After != nil && f.Before != 0 {
		return errx.Validation("after and before cannot be combined")
	}
	if len(f.Subject) > 128 {
		return errx.Validation("subject is too long")
	}
	if f.SubjectKind != "" && !ValidPrefix(f.SubjectKind) {
		return errx.Validation("subject_kind must be a subject kind such as user")
	}
	return nil
}

var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidPrefix reports whether s is one event type family (the part before the dot).
func ValidPrefix(s string) bool { return prefixPattern.MatchString(s) }

type actorKey struct{}

// WithActor records who acts in ctx, for writes whose repository method
// takes no Mutation (creates, legacy grant and membership edits); the HTTP
// authentication middlewares set it.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// ActorFrom returns the actor WithActor stored, "" (the system) when none.
func ActorFrom(ctx context.Context) string {
	s, _ := ctx.Value(actorKey{}).(string)
	return s
}
