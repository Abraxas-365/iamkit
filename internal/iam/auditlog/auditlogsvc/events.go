package auditlogsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// pruneBatch bounds one pruning transaction.
const pruneBatch = 5000

// Events emits, reads and prunes the events.
type Events struct {
	repository auditlog.EventRepository
	actions    auditlog.ActionRepository
	schemas    auditlog.SchemaValidator
	retention  time.Duration
	usage      auditlog.Usage
	now        func() time.Time
}

// New keeps events for retention (IAMKIT_AUDIT_LOG_RETENTION).
func New(repository auditlog.EventRepository, actions auditlog.ActionRepository, schemas auditlog.SchemaValidator, retention time.Duration) *Events {
	return &Events{repository: repository, actions: actions, schemas: schemas, retention: retention, now: time.Now}
}

// SetUsage limits and counts ingest per environment (nil: none).
func (s *Events) SetUsage(u auditlog.Usage) { s.usage = u }

var (
	_ auditlog.EventCommands = (*Events)(nil)
	_ auditlog.EventQueries  = (*Events)(nil)
)

// object returns raw as a metadata object ({} when absent).
func object(raw json.RawMessage) json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return json.RawMessage(`{}`)
	}
	return raw
}

// stored returns the party as it is kept: metadata only when it has keys.
func stored(p auditlog.Party) auditlog.Party {
	if m := compact(object(p.Metadata)); string(m) != "{}" {
		p.Metadata = m
	} else {
		p.Metadata = nil
	}
	return p
}

func compact(raw json.RawMessage) json.RawMessage {
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return raw
	}
	return out.Bytes()
}

// violation turns a validator error into the audit log's 422. The shared
// validator words its refusals for user profiles; only the detail after
// the first colon is kept.
func violation(field string, err error) error {
	var e *errx.Error
	if !errors.As(err, &e) || e.Code != "PROFILE_SCHEMA" {
		return err
	}
	_, detail, _ := strings.Cut(e.Message, ": ")
	return auditlog.ErrSchema(field, detail)
}

func (s *Events) validate(schema json.RawMessage, field string, document json.RawMessage) error {
	if len(schema) == 0 {
		return nil
	}
	return violation(field, s.schemas.Validate(schema, object(document)))
}

func (s *Events) Emit(ctx context.Context, environment identity.EnvironmentID, input auditlog.Input, key string) (auditlog.Receipt, error) {
	if environment.IsZero() {
		return auditlog.Receipt{}, errx.Validation("environment_id is required")
	}
	now := s.now()
	if err := input.Validate(now, config.AuditLogFutureSkew, s.retention); err != nil {
		return auditlog.Receipt{}, err
	}
	var idem *auditlog.Idempotency
	if key != "" {
		if err := auditlog.ValidateIdempotencyKey(key); err != nil {
			return auditlog.Receipt{}, err
		}
		hash, err := input.Hash()
		if err != nil {
			return auditlog.Receipt{}, err
		}
		idem = &auditlog.Idempotency{Key: key, Hash: hash}
		// A replay answers before anything else: it costs no quota and
		// needs neither the action nor the organization to still exist.
		prior, found, err := s.repository.FindKey(ctx, environment, key)
		if err != nil {
			return auditlog.Receipt{}, err
		}
		if found {
			return replay(prior, hash)
		}
	}
	if s.usage != nil {
		if err := s.usage.Admit(ctx, environment, usage.LimitAuditEvents); err != nil {
			return auditlog.Receipt{}, err
		}
	}
	action, err := s.actions.FindActionByName(ctx, environment, input.Action)
	if err != nil {
		var e *errx.Error
		if errors.As(err, &e) && e.Type == errx.TypeNotFound {
			return auditlog.Receipt{}, auditlog.ErrUnknownAction(input.Action)
		}
		return auditlog.Receipt{}, err
	}
	if input.Version != nil && *input.Version != action.Version {
		return auditlog.Receipt{}, auditlog.ErrVersion(action.Version)
	}
	if err = s.check(action, input); err != nil {
		return auditlog.Receipt{}, err
	}
	exists, err := s.repository.OrganizationExists(ctx, environment, input.Organization)
	if err != nil {
		return auditlog.Receipt{}, err
	}
	if !exists {
		return auditlog.Receipt{}, auditlog.ErrUnknownOrganization()
	}
	event := auditlog.Event{ID: identity.NewAuditEventID(), Environment: environment, Organization: input.Organization,
		Action: action.Name, Version: action.Version, OccurredAt: input.OccurredAt.UTC(),
		Actor: stored(input.Actor), Targets: []auditlog.Party{}, Context: input.Context, Metadata: compact(object(input.Metadata))}
	for _, t := range input.Targets {
		event.Targets = append(event.Targets, stored(t))
	}
	inserted, err := s.repository.Insert(ctx, event, idem)
	if err != nil {
		return auditlog.Receipt{}, err
	}
	if inserted.Replayed {
		// Lost the race on the key: the winner's request decides.
		return replay(inserted, idem.Hash)
	}
	if s.usage != nil {
		s.usage.Count(ctx, environment, usage.MetricAuditEvents, 1)
	}
	return inserted.Receipt, nil
}

func replay(prior auditlog.Inserted, hash []byte) (auditlog.Receipt, error) {
	if !bytes.Equal(prior.Hash, hash) {
		return auditlog.Receipt{}, auditlog.ErrKeyReused()
	}
	return prior.Receipt, nil
}

// check applies the action's rules: target types and JSON Schemas.
func (s *Events) check(action auditlog.Action, input auditlog.Input) error {
	for n, t := range input.Targets {
		field := "targets[" + itoa(n) + "]"
		if !has(action.TargetTypes, t.Type) {
			return auditlog.ErrTargetType(field, t.Type)
		}
	}
	if err := s.validate(action.Schema.Metadata, "metadata", input.Metadata); err != nil {
		return err
	}
	if err := s.validate(action.Schema.Actor, "actor.metadata", input.Actor.Metadata); err != nil {
		return err
	}
	for n, t := range input.Targets {
		if err := s.validate(action.Schema.Targets[t.Type], "targets["+itoa(n)+"].metadata", t.Metadata); err != nil {
			return err
		}
	}
	return nil
}

func has(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	raw, _ := json.Marshal(n)
	return string(raw)
}

func (s *Events) List(ctx context.Context, environment identity.EnvironmentID, filter auditlog.Filter, limit int) (auditlog.Page, error) {
	if err := filter.Validate(); err != nil {
		return auditlog.Page{}, err
	}
	limit = auditlog.Limit(limit)
	items, err := s.repository.List(ctx, environment, filter, limit)
	if err != nil {
		return auditlog.Page{}, err
	}
	page := auditlog.Page{Items: items}
	switch {
	case filter.After != nil:
		page.Next = *filter.After
		if len(items) > 0 {
			page.Next = items[len(items)-1].Seq
		}
	case len(items) == limit:
		page.Next = items[len(items)-1].Seq
	}
	return page, nil
}

func (s *Events) Find(ctx context.Context, environment identity.EnvironmentID, id identity.AuditEventID) (auditlog.Event, error) {
	return s.repository.Find(ctx, environment, id)
}

func (s *Events) Export(ctx context.Context, environment identity.EnvironmentID, filter auditlog.Filter, write func(auditlog.Event) error) error {
	if filter.Before != 0 {
		return errx.Validation("export reads forward: use after, not before")
	}
	after := int64(0)
	if filter.After != nil {
		after = *filter.After
	}
	filter.After = &after
	if err := filter.Validate(); err != nil {
		return err
	}
	for {
		items, err := s.repository.List(ctx, environment, filter, auditlog.ExportBatch)
		if err != nil {
			return err
		}
		for _, e := range items {
			if err := write(e); err != nil {
				return err
			}
		}
		if len(items) < auditlog.ExportBatch {
			return nil
		}
		after = items[len(items)-1].Seq
	}
}

func (s *Events) Prune(ctx context.Context) (bool, error) {
	n, err := s.repository.Prune(ctx, s.now().Add(-s.retention), pruneBatch)
	return n == pruneBatch, err
}
