package logstreampg

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type headRow struct {
	ID          int64                  `db:"id"`
	Stream      identity.LogStreamID   `db:"stream_id"`
	Environment identity.EnvironmentID `db:"environment_id"`
	Batch       *int64                 `db:"batch"`
	Destination string                 `db:"destination"`
	Config      []byte                 `db:"config"`
	Secrets     pq.StringArray         `db:"secrets"`
}

type claimedRow struct {
	ID       int64     `db:"id"`
	Source   string    `db:"source"`
	Seq      int64     `db:"source_seq"`
	Attempts int       `db:"attempts"`
	First    time.Time `db:"first_attempt_at"`
}

// ClaimBatches leases each active stream's oldest pending batch once it is
// due. The head row is locked with FOR UPDATE SKIP LOCKED, re-checking
// status and next_attempt_at on the latest row version, so a head another
// replica just leased (now in the future) or finished is skipped. A batch
// keeps its rows across retries: rows already carrying a batch value are
// the same batch again; otherwise the oldest pending rows without one form
// it, capped by LogStreamBatchSize and LogStreamBatchBytes.
func (r *Repository) ClaimBatches(ctx context.Context, limit int, lease time.Duration) ([]logstream.Batch, error) {
	var out []logstream.Batch
	err := eventpg.Tx(ctx, r.db, func(tx *sqlx.Tx) error {
		heads := []headRow{}
		if err := tx.SelectContext(ctx, &heads, `WITH heads AS (
			SELECT DISTINCT ON (d.stream_id) d.id
			FROM log_stream_deliveries d JOIN log_streams s ON s.id = d.stream_id AND s.active
			WHERE d.status = 'pending'
			ORDER BY d.stream_id, d.id
		), due AS (
			SELECT d.id FROM log_stream_deliveries d JOIN heads h ON h.id = d.id
			WHERE d.status = 'pending' AND d.next_attempt_at <= now()
			-- An operator retry can make an older batch the head while a
			-- newer one is leased or backing off: wait for it, so one batch
			-- per stream is ever in flight.
			AND NOT EXISTS (SELECT 1 FROM log_stream_deliveries x
				WHERE x.stream_id = d.stream_id AND x.status = 'pending' AND x.attempts > 0
				AND x.next_attempt_at > now() AND x.batch IS DISTINCT FROM d.batch)
			ORDER BY d.next_attempt_at LIMIT $1 FOR UPDATE OF d SKIP LOCKED
		)
		SELECT d.id, d.stream_id, d.environment_id, d.batch, s.destination, s.config, `+secretsColumn+` AS secrets
		FROM due JOIN log_stream_deliveries d ON d.id = due.id JOIN log_streams s ON s.id = d.stream_id
		ORDER BY d.id`, limit); err != nil {
			return failure(err)
		}
		for _, h := range heads {
			b, ok, err := r.claim(ctx, tx, h, lease)
			if err != nil {
				return err
			}
			if ok {
				out = append(out, b)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repository) claim(ctx context.Context, tx *sqlx.Tx, h headRow, lease time.Duration) (logstream.Batch, bool, error) {
	var rows []claimedRow
	var err error
	if h.Batch != nil {
		err = tx.SelectContext(ctx, &rows, `SELECT id, source, source_seq, attempts, COALESCE(first_attempt_at, now()) AS first_attempt_at
			FROM log_stream_deliveries WHERE stream_id = $1 AND batch = $2 AND status = 'pending' ORDER BY id`, h.Stream, *h.Batch)
	} else {
		err = tx.SelectContext(ctx, &rows, `SELECT id, source, source_seq, attempts, COALESCE(first_attempt_at, now()) AS first_attempt_at
			FROM log_stream_deliveries WHERE stream_id = $1 AND batch IS NULL AND status = 'pending' ORDER BY id LIMIT $2`,
			h.Stream, config.LogStreamBatchSize)
	}
	if err != nil {
		return logstream.Batch{}, false, failure(err)
	}
	if len(rows) == 0 {
		return logstream.Batch{}, false, nil
	}
	records, err := loadRecords(ctx, tx, h.Environment, rows)
	if err != nil {
		return logstream.Batch{}, false, err
	}
	var kept []claimedRow
	var pruned []int64
	var batch logstream.Batch
	size := 0
	for _, row := range rows {
		rec, ok := records[key{row.Source, row.Seq}]
		if !ok {
			pruned = append(pruned, row.ID)
			continue
		}
		// Only a batch not yet sent is trimmed to the byte budget; a retried
		// one keeps exactly the rows it had.
		if h.Batch == nil && len(kept) > 0 && size+len(rec.Fields)+200 > config.LogStreamBatchBytes {
			break
		}
		size += len(rec.Fields) + 200
		kept = append(kept, row)
		batch.Records = append(batch.Records, rec)
	}
	if len(pruned) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE log_stream_deliveries SET status = 'failed', finished_at = now(), last_error = $2
			WHERE stream_id = $1 AND id = ANY($3)`, h.Stream, logstream.RecordPruned, pq.Array(pruned)); err != nil {
			return logstream.Batch{}, false, failure(err)
		}
	}
	if len(kept) == 0 {
		return logstream.Batch{}, false, nil
	}
	ids := make([]int64, len(kept))
	for i, k := range kept {
		ids[i] = k.ID
	}
	var attempts int
	var first time.Time
	if err := tx.QueryRowxContext(ctx, `WITH u AS (
		UPDATE log_stream_deliveries SET batch = COALESCE(batch, $3), attempts = attempts + 1,
			next_attempt_at = now() + make_interval(secs => $4), first_attempt_at = COALESCE(first_attempt_at, now())
		WHERE stream_id = $1 AND id = ANY($2) RETURNING id, attempts, first_attempt_at)
		SELECT max(attempts), min(first_attempt_at) FROM u`, h.Stream, pq.Array(ids), kept[0].ID, lease.Seconds()).Scan(&attempts, &first); err != nil {
		return logstream.Batch{}, false, failure(err)
	}
	batchID := kept[0].ID
	if h.Batch != nil {
		batchID = *h.Batch
	}
	batch.Stream, batch.Environment, batch.Destination = h.Stream, h.Environment, h.Destination
	if err := json.Unmarshal(h.Config, &batch.Config); err != nil {
		return logstream.Batch{}, false, failure(err)
	}
	batch.Sealed = []string(h.Secrets)
	batch.ID, batch.Rows, batch.Attempts, batch.FirstAttempt = batchID, ids, attempts, first
	batch.At = batch.Records[0].At
	return batch, true, nil
}

type key struct {
	source string
	seq    int64
}

// loadRecords reads the records of the rows from the stream's environment.
func loadRecords(ctx context.Context, tx *sqlx.Tx, environment identity.EnvironmentID, rows []claimedRow) (map[key]logstream.Record, error) {
	var events, audits []int64
	for _, row := range rows {
		if row.Source == logstream.SourceEvents {
			events = append(events, row.Seq)
		} else {
			audits = append(audits, row.Seq)
		}
	}
	out := make(map[key]logstream.Record, len(rows))
	if len(events) > 0 {
		var rs []struct {
			ID           int64                    `db:"id"`
			Type         string                   `db:"type"`
			ActorKind    string                   `db:"actor_kind"`
			ActorID      string                   `db:"actor_id"`
			SubjectKind  string                   `db:"subject_kind"`
			SubjectID    string                   `db:"subject_id"`
			Organization *identity.OrganizationID `db:"organization_id"`
			Data         []byte                   `db:"data"`
			CreatedAt    time.Time                `db:"created_at"`
		}
		if err := tx.SelectContext(ctx, &rs, `SELECT id, type, actor_kind, actor_id, subject_kind, subject_id, organization_id, data, created_at
			FROM events WHERE environment_id = $1 AND id = ANY($2)`, environment, pq.Array(events)); err != nil {
			return nil, failure(err)
		}
		for _, e := range rs {
			fields, err := json.Marshal(struct {
				ID           int64                    `json:"id"`
				Type         string                   `json:"type"`
				Actor        map[string]string        `json:"actor"`
				Subject      map[string]string        `json:"subject"`
				Organization *identity.OrganizationID `json:"organization_id,omitempty"`
				Data         json.RawMessage          `json:"data"`
			}{e.ID, e.Type, compact("kind", e.ActorKind, "id", e.ActorID), compact("kind", e.SubjectKind, "id", e.SubjectID), e.Organization, e.Data})
			if err != nil {
				return nil, failure(err)
			}
			out[key{logstream.SourceEvents, e.ID}] = logstream.Record{Source: logstream.SourceEvents, Seq: e.ID, At: e.CreatedAt, Fields: fields}
		}
	}
	if len(audits) > 0 {
		var rs []struct {
			Seq          int64                   `db:"seq"`
			ID           uuid.UUID               `db:"id"`
			Organization identity.OrganizationID `db:"organization_id"`
			Action       string                  `db:"action"`
			Version      int                     `db:"version"`
			OccurredAt   time.Time               `db:"occurred_at"`
			Actor        []byte                  `db:"actor"`
			Targets      []byte                  `db:"targets"`
			Context      []byte                  `db:"context"`
			Metadata     []byte                  `db:"metadata"`
		}
		if err := tx.SelectContext(ctx, &rs, `SELECT seq, id, organization_id, action, version, occurred_at, actor, targets, context, metadata
			FROM audit_log_events WHERE environment_id = $1 AND seq = ANY($2)`, environment, pq.Array(audits)); err != nil {
			return nil, failure(err)
		}
		for _, a := range rs {
			fields, err := json.Marshal(struct {
				ID           string          `json:"id"`
				Organization string          `json:"organization_id"`
				Action       string          `json:"action"`
				Version      int             `json:"version"`
				Actor        json.RawMessage `json:"actor"`
				Targets      json.RawMessage `json:"targets"`
				Context      json.RawMessage `json:"context"`
				Metadata     json.RawMessage `json:"metadata"`
			}{a.ID.String(), a.Organization.String(), a.Action, a.Version, a.Actor, a.Targets, a.Context, a.Metadata})
			if err != nil {
				return nil, failure(err)
			}
			out[key{logstream.SourceAuditLogs, a.Seq}] = logstream.Record{Source: logstream.SourceAuditLogs, Seq: a.Seq, At: a.OccurredAt, Fields: fields}
		}
	}
	return out, nil
}

// compact is a map of the non-empty pairs (k1 → v1, k2 → v2).
func compact(k1, v1, k2, v2 string) map[string]string {
	m := map[string]string{}
	if v1 != "" {
		m[k1] = v1
	}
	if v2 != "" {
		m[k2] = v2
	}
	return m
}
