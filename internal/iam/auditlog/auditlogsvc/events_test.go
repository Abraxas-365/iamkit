package auditlogsvc_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog/auditlogsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userschema"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type fakeActions struct {
	byName map[string]auditlog.Action
}

func (f *fakeActions) CreateAction(context.Context, auditlog.Mutation, auditlog.Action) error {
	return nil
}
func (f *fakeActions) UpdateAction(context.Context, auditlog.Mutation, auditlog.Action, bool) error {
	return nil
}
func (f *fakeActions) DeleteAction(context.Context, auditlog.Mutation, identity.AuditActionID) error {
	return nil
}
func (f *fakeActions) FindAction(context.Context, identity.EnvironmentID, identity.AuditActionID) (auditlog.Action, error) {
	return auditlog.Action{}, auditlog.ErrActionNotFound()
}
func (f *fakeActions) FindActionByName(_ context.Context, _ identity.EnvironmentID, name string) (auditlog.Action, error) {
	if a, ok := f.byName[name]; ok {
		return a, nil
	}
	return auditlog.Action{}, auditlog.ErrActionNotFound()
}
func (f *fakeActions) ListActions(context.Context, identity.EnvironmentID) ([]auditlog.Action, error) {
	return nil, nil
}
func (f *fakeActions) CountActions(context.Context, identity.EnvironmentID) (int, error) {
	return 0, nil
}

type fakeEvents struct {
	orgs    map[identity.OrganizationID]bool
	stored  []auditlog.Event
	keys    map[string]auditlog.Inserted
	pruned  int
	listed  []auditlog.Event
	filters []auditlog.Filter
}

func (f *fakeEvents) OrganizationExists(_ context.Context, _ identity.EnvironmentID, o identity.OrganizationID) (bool, error) {
	return f.orgs[o], nil
}
func (f *fakeEvents) Insert(_ context.Context, e auditlog.Event, idem *auditlog.Idempotency) (auditlog.Inserted, error) {
	if idem != nil {
		if prior, ok := f.keys[idem.Key]; ok {
			return prior, nil
		}
	}
	e.Seq = int64(len(f.stored) + 1)
	f.stored = append(f.stored, e)
	out := auditlog.Inserted{Receipt: auditlog.Receipt{ID: e.ID, CreatedAt: time.Now()}}
	if idem != nil {
		f.keys[idem.Key] = auditlog.Inserted{Receipt: out.Receipt, Replayed: true, Hash: idem.Hash}
	}
	return out, nil
}
func (f *fakeEvents) FindKey(_ context.Context, _ identity.EnvironmentID, key string) (auditlog.Inserted, bool, error) {
	v, ok := f.keys[key]
	return v, ok, nil
}
func (f *fakeEvents) Find(context.Context, identity.EnvironmentID, identity.AuditEventID) (auditlog.Event, error) {
	return auditlog.Event{}, auditlog.ErrEventNotFound()
}
func (f *fakeEvents) List(_ context.Context, _ identity.EnvironmentID, filter auditlog.Filter, limit int) ([]auditlog.Event, error) {
	f.filters = append(f.filters, filter)
	if len(f.listed) > limit {
		return f.listed[:limit], nil
	}
	return f.listed, nil
}
func (f *fakeEvents) Prune(_ context.Context, _ time.Time, batch int) (int, error) {
	return f.pruned, nil
}

type fakeUsage struct {
	err     error
	admits  int
	counted int64
}

func (u *fakeUsage) Admit(_ context.Context, _ identity.EnvironmentID, limit string) error {
	if limit != usage.LimitAuditEvents {
		panic("wrong limit " + limit)
	}
	u.admits++
	return u.err
}
func (u *fakeUsage) Count(_ context.Context, _ identity.EnvironmentID, metric string, n int64) {
	if metric != usage.MetricAuditEvents {
		panic("wrong metric " + metric)
	}
	u.counted += n
}

type fixture struct {
	svc     *auditlogsvc.Events
	events  *fakeEvents
	usage   *fakeUsage
	env     identity.EnvironmentID
	org     identity.OrganizationID
	version int
}

func newFixture() *fixture {
	org := identity.NewOrganizationID()
	f := &fixture{events: &fakeEvents{orgs: map[identity.OrganizationID]bool{org: true}, keys: map[string]auditlog.Inserted{}},
		usage: &fakeUsage{}, env: identity.NewEnvironmentID(), org: org}
	actions := &fakeActions{byName: map[string]auditlog.Action{"invoice.paid": {Name: "invoice.paid", Version: 3, TargetTypes: []string{"invoice"},
		Schema: auditlog.Schema{
			Metadata: json.RawMessage(`{"type":"object","required":["amount"],"properties":{"amount":{"type":"number"}}}`),
			Actor:    json.RawMessage(`{"type":"object","required":["role"]}`),
			Targets:  map[string]json.RawMessage{"invoice": json.RawMessage(`{"type":"object","required":["number"]}`)},
		}}}}
	f.svc = auditlogsvc.New(f.events, actions, userschema.Validator{}, 24*time.Hour*30)
	f.svc.SetUsage(f.usage)
	return f
}

func (f *fixture) input() auditlog.Input {
	return auditlog.Input{Organization: f.org, Action: "invoice.paid", OccurredAt: time.Now().Add(-time.Minute),
		Actor:    auditlog.Party{Type: "user", ID: "u1", Metadata: json.RawMessage(`{"role":"admin"}`)},
		Targets:  []auditlog.Party{{Type: "invoice", ID: "i1", Metadata: json.RawMessage(`{"number":"F-1"}`)}},
		Metadata: json.RawMessage(`{"amount": 5}`)}
}

func code(t *testing.T, err error) string {
	t.Helper()
	var e *errx.Error
	if !errors.As(err, &e) {
		t.Fatalf("not an errx error: %v", err)
	}
	return e.Code
}

func TestEmitStoresWithCurrentVersion(t *testing.T) {
	f := newFixture()
	if _, err := f.svc.Emit(context.Background(), f.env, f.input(), ""); err != nil {
		t.Fatal(err)
	}
	if len(f.events.stored) != 1 || f.events.stored[0].Version != 3 || f.usage.counted != 1 || f.usage.admits != 1 {
		t.Fatalf("stored %+v usage %+v", f.events.stored, f.usage)
	}
	v := 3
	in := f.input()
	in.Version = &v
	if _, err := f.svc.Emit(context.Background(), f.env, in, ""); err != nil {
		t.Fatal(err)
	}
	v = 2
	_, err := f.svc.Emit(context.Background(), f.env, in, "")
	if code(t, err) != "AUDIT_ACTION_VERSION" {
		t.Fatalf("stale version: %v", err)
	}
}

func TestEmitRefusals(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	cases := map[string]struct {
		mutate func(*auditlog.Input)
		code   string
	}{
		"unknown action":  {func(i *auditlog.Input) { i.Action = "invoice.sent" }, "UNKNOWN_AUDIT_ACTION"},
		"unknown org":     {func(i *auditlog.Input) { i.Organization = identity.NewOrganizationID() }, "UNKNOWN_ORGANIZATION"},
		"target type":     {func(i *auditlog.Input) { i.Targets[0].Type = "order" }, "AUDIT_TARGET_TYPE"},
		"metadata schema": {func(i *auditlog.Input) { i.Metadata = json.RawMessage(`{"amount":"x"}`) }, "AUDIT_SCHEMA_VIOLATION"},
		"missing meta":    {func(i *auditlog.Input) { i.Metadata = nil }, "AUDIT_SCHEMA_VIOLATION"},
		"actor schema":    {func(i *auditlog.Input) { i.Actor.Metadata = nil }, "AUDIT_SCHEMA_VIOLATION"},
		"target schema":   {func(i *auditlog.Input) { i.Targets[0].Metadata = nil }, "AUDIT_SCHEMA_VIOLATION"},
		"future":          {func(i *auditlog.Input) { i.OccurredAt = time.Now().Add(time.Hour) }, "VALIDATION"},
		"too old":         {func(i *auditlog.Input) { i.OccurredAt = time.Now().Add(-365 * 24 * time.Hour) }, "VALIDATION"},
	}
	for name, tc := range cases {
		in := f.input()
		tc.mutate(&in)
		_, err := f.svc.Emit(ctx, f.env, in, "")
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if got := code(t, err); got != tc.code {
			t.Errorf("%s: code %s want %s (%v)", name, got, tc.code, err)
		}
	}
	if len(f.events.stored) != 0 || f.usage.counted != 0 {
		t.Fatal("a refused event was stored or counted")
	}
}

func TestEmitIdempotency(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	first, err := f.svc.Emit(ctx, f.env, f.input(), "key-1")
	if err != nil {
		t.Fatal(err)
	}
	// The same request again (a replay costs no quota and stores nothing).
	in := f.input()
	in.OccurredAt = f.events.stored[0].OccurredAt
	again, err := f.svc.Emit(ctx, f.env, in, "key-1")
	if err != nil || again.ID != first.ID || len(f.events.stored) != 1 || f.usage.counted != 1 || f.usage.admits != 1 {
		t.Fatalf("replay: %v %+v stored=%d usage=%+v", err, again, len(f.events.stored), f.usage)
	}
	// Another request under the same key.
	other := in
	other.Metadata = json.RawMessage(`{"amount": 6}`)
	if _, err = f.svc.Emit(ctx, f.env, other, "key-1"); code(t, err) != "IDEMPOTENCY_KEY_REUSED" {
		t.Fatalf("reuse: %v", err)
	}
	// Racing: the key appears between the lookup and the insert.
	racy := newFixture()
	hash, _ := in.Hash()
	racy.events.keys["race"] = auditlog.Inserted{Receipt: auditlog.Receipt{ID: identity.NewAuditEventID()}, Replayed: true, Hash: hash}
	got, err := racy.svc.Emit(ctx, racy.env, in, "race")
	if err != nil || got.ID != racy.events.keys["race"].ID {
		t.Fatalf("race: %v", err)
	}
	if _, err = f.svc.Emit(ctx, f.env, in, string(make([]byte, 256))); err == nil {
		t.Fatal("long key accepted")
	}
}

func TestEmitUsageLimit(t *testing.T) {
	f := newFixture()
	f.usage.err = usage.ErrExceeded(usage.Limit{Name: usage.LimitAuditEvents, Kind: usage.KindPerMinute}, 1)
	_, err := f.svc.Emit(context.Background(), f.env, f.input(), "")
	if err == nil || len(f.events.stored) != 0 || f.usage.counted != 0 {
		t.Fatalf("limit: %v", err)
	}
}

func TestListCursors(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	for _, seq := range []int64{9, 8, 7} {
		f.events.listed = append(f.events.listed, auditlog.Event{Seq: seq})
	}
	page, err := f.svc.List(ctx, f.env, auditlog.Filter{}, 3)
	if err != nil || page.Next != 7 {
		t.Fatalf("full newest-first page: %v %+v", err, page)
	}
	page, _ = f.svc.List(ctx, f.env, auditlog.Filter{}, 10)
	if page.Next != 0 {
		t.Fatalf("exhausted page next = %d", page.Next)
	}
	after := int64(4)
	page, _ = f.svc.List(ctx, f.env, auditlog.Filter{After: &after}, 10)
	if page.Next != 7 {
		t.Fatalf("feed next = %d", page.Next)
	}
	f.events.listed = nil
	page, _ = f.svc.List(ctx, f.env, auditlog.Filter{After: &after}, 10)
	if page.Next != 4 {
		t.Fatalf("empty feed next = %d", page.Next)
	}
	if _, err = f.svc.List(ctx, f.env, auditlog.Filter{Before: 3, After: &after}, 10); err == nil {
		t.Fatal("after+before accepted")
	}
}

func TestExportBatches(t *testing.T) {
	f := newFixture()
	for n := range 3 {
		f.events.listed = append(f.events.listed, auditlog.Event{Seq: int64(n + 1)})
	}
	var seen int
	if err := f.svc.Export(context.Background(), f.env, auditlog.Filter{}, func(auditlog.Event) error { seen++; return nil }); err != nil || seen != 3 {
		t.Fatalf("export: %v %d", err, seen)
	}
	if after := f.events.filters[0].After; after == nil || *after != 0 {
		t.Fatal("export did not start at the beginning")
	}
	if err := f.svc.Export(context.Background(), f.env, auditlog.Filter{Before: 4}, func(auditlog.Event) error { return nil }); err == nil {
		t.Fatal("export with before accepted")
	}
	stop := errors.New("stop")
	if err := f.svc.Export(context.Background(), f.env, auditlog.Filter{}, func(auditlog.Event) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("write error lost: %v", err)
	}
}

func TestPruneMore(t *testing.T) {
	f := newFixture()
	f.events.pruned = 5000
	if more, err := f.svc.Prune(context.Background()); err != nil || !more {
		t.Fatalf("prune: %v %v", more, err)
	}
	f.events.pruned = 10
	if more, _ := f.svc.Prune(context.Background()); more {
		t.Fatal("small round asked for more")
	}
}
