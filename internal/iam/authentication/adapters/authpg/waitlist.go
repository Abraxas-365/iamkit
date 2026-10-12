package authpg

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/jmoiron/sqlx"
)

var _ authentication.WaitlistRepository = (*Repository)(nil)

const waitlistColumns = `id,environment_id,email,name,locale,status,created_at,decided_at,decided_by,expires_at,completed_user_id`

func waitlistSubject(id identity.WaitlistEntryID) event.Subject {
	return event.Subject{Kind: "waitlist_entry", ID: id.String()}
}

// JoinWaitlist adds a pending entry unless the address already has an open
// one or the environment is at its pending cap. An approval that expired
// unused goes back to pending (else the address would be stuck). The event
// carries the email domain only, never the address.
func (t *SignupTransaction) JoinWaitlist(ctx context.Context, j authentication.WaitlistJoin) (bool, error) {
	var pending int
	if err := t.tx.GetContext(ctx, &pending, `SELECT count(*) FROM waitlist_entries WHERE environment_id=$1 AND status='pending'`, j.Environment); err != nil {
		return false, failure(err)
	}
	if pending >= config.WaitlistMaxPending {
		// Silent to the person (the answer never differs); loud to the
		// operator, who otherwise sees a full list and nothing else.
		slog.WarnContext(ctx, "waitlist full: join dropped", "environment", j.Environment, "pending", pending)
		return false, nil
	}
	id := j.ID
	err := t.tx.GetContext(ctx, &id, `UPDATE waitlist_entries SET status='pending', decided_at=NULL, decided_by='', expires_at=NULL, token_hash=NULL, created_at=now()
		WHERE environment_id=$1 AND email=$2 AND status='approved' AND expires_at<=now() RETURNING id`, j.Environment, j.Email)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := t.tx.ExecContext(ctx, `INSERT INTO waitlist_entries(id,environment_id,email,name,locale) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT (environment_id,email) WHERE status IN ('pending','approved','rejected') DO NOTHING`,
			j.ID, j.Environment, j.Email, j.Name, j.Locale)
		if err != nil {
			return false, failure(err)
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return false, failure(err)
		}
	case err != nil:
		return false, failure(err)
	}
	err = eventpg.Emit(ctx, t.tx, j.Environment, "", event.WaitlistJoined, waitlistSubject(id), map[string]any{"email_domain": identity.EmailDomain(j.Email)})
	return err == nil, err
}

// WaitlistToken resolves an approval token hash to its live entry.
func (t *SignupTransaction) WaitlistToken(ctx context.Context, environment identity.EnvironmentID, hash []byte) (authentication.WaitlistToken, error) {
	var out authentication.WaitlistToken
	err := t.tx.GetContext(ctx, &out, `SELECT id,email FROM waitlist_entries
		WHERE environment_id=$1 AND token_hash=$2 AND status='approved' AND expires_at>now()`, environment, hash)
	if errors.Is(err, sql.ErrNoRows) {
		return authentication.WaitlistToken{}, authentication.ErrWaitlistToken()
	}
	return out, failure(err)
}

// completeWaitlist marks the approved entry of a sign-up completed, in the
// sign-up's transaction. The approval must still be valid for the address;
// else the whole sign-up fails and no account is created.
func (t *SignupTransaction) completeWaitlist(ctx context.Context, j authentication.Joining) error {
	res, err := t.tx.ExecContext(ctx, `UPDATE waitlist_entries SET status='completed', completed_user_id=$3, token_hash=NULL
		WHERE id=$1 AND environment_id=$2 AND email=$4 AND status='approved' AND expires_at>now()`, j.WaitlistEntry, j.Environment, j.User, j.Email)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return failure(err)
		}
		return authentication.ErrWaitlistToken()
	}
	return eventpg.Emit(ctx, t.tx, j.Environment, j.User.String(), event.WaitlistCompleted, waitlistSubject(j.WaitlistEntry), map[string]any{"user_id": j.User.String()})
}

func (r *Repository) ListWaitlist(ctx context.Context, environment identity.EnvironmentID, filter authentication.WaitlistFilter, page query.Pagination) (query.Paginated[authentication.WaitlistEntry], error) {
	page = page.Normalize()
	where := `environment_id=$1 AND ($2='' OR status=$2) AND ($3='' OR starts_with(email,lower($3)))`
	var total int
	if err := r.db.GetContext(ctx, &total, `SELECT count(*) FROM waitlist_entries WHERE `+where, environment, filter.Status, filter.Email); err != nil {
		return query.Paginated[authentication.WaitlistEntry]{}, failure(err)
	}
	items := []authentication.WaitlistEntry{}
	if err := r.db.SelectContext(ctx, &items, `SELECT `+waitlistColumns+` FROM waitlist_entries WHERE `+where+`
		ORDER BY created_at DESC,id LIMIT $4 OFFSET $5`, environment, filter.Status, filter.Email, page.Limit, page.Offset); err != nil {
		return query.Paginated[authentication.WaitlistEntry]{}, failure(err)
	}
	return query.NewPaginated(items, total, page), nil
}

func (r *Repository) FindWaitlist(ctx context.Context, environment identity.EnvironmentID, id identity.WaitlistEntryID) (authentication.WaitlistEntry, error) {
	var out authentication.WaitlistEntry
	err := r.db.GetContext(ctx, &out, `SELECT `+waitlistColumns+` FROM waitlist_entries WHERE environment_id=$1 AND id=$2`, environment, id)
	if errors.Is(err, sql.ErrNoRows) {
		return out, errx.NotFound("waitlist entry not found")
	}
	return out, failure(err)
}

func (r *Repository) PendingWaitlist(ctx context.Context, environment identity.EnvironmentID, limit int) ([]authentication.WaitlistEntry, error) {
	out := []authentication.WaitlistEntry{}
	err := r.db.SelectContext(ctx, &out, `SELECT `+waitlistColumns+` FROM waitlist_entries WHERE environment_id=$1 AND status='pending'
		ORDER BY created_at,id LIMIT $2`, environment, limit)
	return out, failure(err)
}

// decide runs one audited state change of an entry; change reports the
// updated entry. No row means the entry is missing or already finished.
func (r *Repository) decide(ctx context.Context, m authentication.Mutation, id identity.WaitlistEntryID, change func(tx *sqlx.Tx) (authentication.WaitlistEntry, error)) (authentication.WaitlistEntry, error) {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return authentication.WaitlistEntry{}, failure(err)
	}
	defer tx.Rollback()
	entry, err := change(tx)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if err = tx.GetContext(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM waitlist_entries WHERE environment_id=$1 AND id=$2)`, m.Environment, id); err != nil {
			return authentication.WaitlistEntry{}, failure(err)
		}
		if exists {
			return authentication.WaitlistEntry{}, authentication.ErrWaitlistNotDecidable()
		}
		return authentication.WaitlistEntry{}, errx.NotFound("waitlist entry not found")
	}
	if err != nil {
		return authentication.WaitlistEntry{}, failure(err)
	}
	if err = audit(ctx, tx, m); err != nil {
		return authentication.WaitlistEntry{}, err
	}
	return entry, commit(tx, "save waitlist entry")
}

func (r *Repository) ApproveWaitlist(ctx context.Context, m authentication.Mutation, a authentication.WaitlistApproval) (authentication.WaitlistEntry, error) {
	return r.decide(ctx, m, a.ID, func(tx *sqlx.Tx) (authentication.WaitlistEntry, error) {
		var out authentication.WaitlistEntry
		err := tx.GetContext(ctx, &out, `UPDATE waitlist_entries SET status='approved', token_hash=$3, expires_at=$4, decided_at=now(), decided_by=$5
			WHERE environment_id=$1 AND id=$2 AND status IN ('pending','approved') RETURNING `+waitlistColumns, m.Environment, a.ID, a.TokenHash, a.ExpiresAt, m.Actor)
		return out, err
	})
}

func (r *Repository) RejectWaitlist(ctx context.Context, m authentication.Mutation, id identity.WaitlistEntryID) (authentication.WaitlistEntry, error) {
	return r.decide(ctx, m, id, func(tx *sqlx.Tx) (authentication.WaitlistEntry, error) {
		var out authentication.WaitlistEntry
		err := tx.GetContext(ctx, &out, `UPDATE waitlist_entries SET status='rejected', token_hash=NULL, expires_at=NULL, decided_at=now(), decided_by=$3
			WHERE environment_id=$1 AND id=$2 AND status IN ('pending','approved') RETURNING `+waitlistColumns, m.Environment, id, m.Actor)
		return out, err
	})
}

// PruneWaitlist deletes up to limit completed or rejected entries decided
// before the cutoff. Completing an entry sets no timestamp of its own, so a
// completed entry ages from its approval (decided_at); created_at stands in
// for rows without one. Pending and approved entries are never touched: the
// status is checked again on the locked row, so an entry reopened meanwhile
// stays. No audit row and no event: this is retention, not a decision.
func (r *Repository) PruneWaitlist(ctx context.Context, before time.Time, limit int) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM waitlist_entries WHERE id IN (
		SELECT id FROM waitlist_entries
		WHERE status IN ('completed','rejected') AND COALESCE(decided_at, created_at) < $1
		ORDER BY COALESCE(decided_at, created_at) LIMIT $2 FOR UPDATE SKIP LOCKED)
		AND status IN ('completed','rejected')`, before, limit)
	if err != nil {
		return 0, failure(err)
	}
	n, err := res.RowsAffected()
	return int(n), failure(err)
}

func (r *Repository) DeleteWaitlist(ctx context.Context, m authentication.Mutation, id identity.WaitlistEntryID) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return failure(err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM waitlist_entries WHERE environment_id=$1 AND id=$2`, m.Environment, id)
	if err != nil {
		return failure(err)
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return failure(err)
		}
		return errx.NotFound("waitlist entry not found")
	}
	if err = audit(ctx, tx, m); err != nil {
		return err
	}
	return commit(tx, "delete waitlist entry")
}
