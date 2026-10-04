// Package eventpg writes and reads the semantic event log (the events
// table). Every *pg adapter records its audited changes
// through Audit, which writes the audit_events row the console shows and
// the event it describes in the caller's transaction; changes without an
// audit entry (creates, memberships) use Emit. Like authpg.Resolve this is
// shared SQL other adapters may import.
package eventpg

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// Execer is a transaction (or, for single-statement changes, a database).
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Audit records one audited change: its audit_events row and, when the
// action + target describe one (event.Classify), its semantic event.
func Audit(ctx context.Context, tx Execer, environment identity.EnvironmentID, actor, action, target string) error {
	return AuditWith(ctx, tx, environment, actor, action, target, nil)
}

// AuditWith is Audit adding ids the target does not name (e.g. the user of
// a session target) to the event's data.
func AuditWith(ctx context.Context, tx Execer, environment identity.EnvironmentID, actor, action, target string, data map[string]any) error {
	return AuditSubject(ctx, tx, environment, actor, action, target, "", data)
}

// AuditSubject is AuditWith naming the subject the target does not (the
// new row of a create route, whose classified subject id is empty); an id
// the target names wins.
func AuditSubject(ctx context.Context, tx Execer, environment identity.EnvironmentID, actor, action, target, subject string, data map[string]any) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(environment_id,actor_id,action,target_id) VALUES($1,$2,$3,$4)`, environment, actor, action, target); err != nil {
		return failure(err)
	}
	c, ok := event.Classify(action, target)
	if !ok {
		return nil
	}
	for k, v := range data {
		c.Data[k] = v
	}
	if c.Subject.ID == "" {
		c.Subject.ID = subject
	}
	return Emit(ctx, tx, environment, actor, c.Type, c.Subject, c.Data)
}

// System records the classified event of an action IAMKit took on its own
// (actor kind system). There is no audit row: audit_events names a
// person or credential.
func System(ctx context.Context, tx Execer, environment identity.EnvironmentID, action, target string) error {
	c, ok := event.Classify(action, target)
	if !ok {
		return nil
	}
	return Emit(ctx, tx, environment, "", c.Type, c.Subject, c.Data)
}

// Tx runs fn in a transaction, for single-statement changes that gain an
// event. fn's error is returned as is (callers map constraint errors).
func Tx(ctx context.Context, db *sqlx.DB, fn func(tx *sqlx.Tx) error) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return failure(tx.Commit())
}

// UserCreated records a new user and, when it joined one, its first
// membership. origin names the path: api, signup, invitation, federation,
// scim. actor is who created it (the user itself for self-service paths).
func UserCreated(ctx context.Context, tx Execer, environment identity.EnvironmentID, actor string, user identity.UserID, organization identity.OrganizationID, origin string) error {
	data := map[string]any{"user_id": user.String(), "origin": origin}
	if !organization.IsZero() {
		data["organization_id"] = organization.String()
	}
	if err := Emit(ctx, tx, environment, actor, event.UserCreated, event.Subject{Kind: "user", ID: user.String()}, data); err != nil {
		return err
	}
	if organization.IsZero() {
		return nil
	}
	return Membership(ctx, tx, environment, actor, event.MembershipCreated, organization, user)
}

// Membership records a membership change (membership.created, …).
func Membership(ctx context.Context, tx Execer, environment identity.EnvironmentID, actor, typ string, organization identity.OrganizationID, user identity.UserID) error {
	return Emit(ctx, tx, environment, actor, typ, event.Subject{Kind: "user", ID: user.String()},
		map[string]any{"organization_id": organization.String(), "user_id": user.String()})
}

// Record writes one event for a change made on behalf of the request's
// actor (event.ActorFrom: the authenticated user, service account or
// operator; the system when none).
func Record(ctx context.Context, tx Execer, environment identity.EnvironmentID, typ string, subject event.Subject, data map[string]any) error {
	return Emit(ctx, tx, environment, event.ActorFrom(ctx), typ, subject, data)
}

// Emit writes one event. actor is the acting user, service account or
// operator id ("" = the system; the kind is resolved by trigger); an
// organization_id in data also fills the organization column.
func Emit(ctx context.Context, tx Execer, environment identity.EnvironmentID, actor, typ string, subject event.Subject, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return errx.Wrap(err, "encode event", errx.TypeInternal)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO events(environment_id,type,actor_id,subject_kind,subject_id,organization_id,data)
		VALUES($1,$2,$3,$4,$5,CASE WHEN $6::jsonb->>'organization_id' ~ '^[0-9a-fA-F-]{36}$' THEN ($6::jsonb->>'organization_id')::uuid END,$6::jsonb)`,
		environment, typ, actor, subject.Kind, subject.ID, string(raw))
	return failure(err)
}

func failure(err error) error {
	if err == nil {
		return nil
	}
	return errx.Wrap(err, "event persistence failed", errx.TypeInternal)
}
