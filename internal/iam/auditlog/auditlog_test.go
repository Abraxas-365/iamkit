package auditlog_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

var now = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

func input() auditlog.Input {
	return auditlog.Input{Organization: identity.NewOrganizationID(), Action: "invoice.paid", OccurredAt: now.Add(-time.Minute),
		Actor:    auditlog.Party{Type: "user", ID: "u1", Name: "Ana"},
		Targets:  []auditlog.Party{{Type: "invoice", ID: "inv_1"}},
		Metadata: json.RawMessage(`{"amount": 10, "paid": true}`)}
}

func TestInputValidate(t *testing.T) {
	if err := input().Validate(now, 5*time.Minute, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*auditlog.Input){
		"organization":   func(i *auditlog.Input) { i.Organization = identity.OrganizationID{} },
		"action":         func(i *auditlog.Input) { i.Action = "Invoice" },
		"occurred_at":    func(i *auditlog.Input) { i.OccurredAt = time.Time{} },
		"future":         func(i *auditlog.Input) { i.OccurredAt = now.Add(10 * time.Minute) },
		"retention":      func(i *auditlog.Input) { i.OccurredAt = now.Add(-48 * time.Hour) },
		"version":        func(i *auditlog.Input) { v := 0; i.Version = &v },
		"actor type":     func(i *auditlog.Input) { i.Actor.Type = "" },
		"actor id":       func(i *auditlog.Input) { i.Actor.ID = strings.Repeat("x", 256) },
		"control":        func(i *auditlog.Input) { i.Actor.Name = "a\nb" },
		"target id":      func(i *auditlog.Input) { i.Targets[0].ID = "" },
		"too many":       func(i *auditlog.Input) { i.Targets = make([]auditlog.Party, 51) },
		"user agent":     func(i *auditlog.Input) { i.Context.UserAgent = strings.Repeat("x", 1025) },
		"metadata array": func(i *auditlog.Input) { i.Metadata = json.RawMessage(`[1]`) },
		"metadata nest":  func(i *auditlog.Input) { i.Metadata = json.RawMessage(`{"a": {"b": 1}}`) },
		"metadata long":  func(i *auditlog.Input) { i.Metadata = json.RawMessage(`{"a": "` + strings.Repeat("x", 501) + `"}`) },
		"metadata key":   func(i *auditlog.Input) { i.Metadata = json.RawMessage(`{"` + strings.Repeat("k", 41) + `": 1}`) },
		"metadata nul":   func(i *auditlog.Input) { i.Metadata = json.RawMessage(`{"a": "x\u0000"}`) },
		"metadata huge":  func(i *auditlog.Input) { i.Metadata = json.RawMessage(`{"a": 1e999999}`) },
		"metadata big":   func(i *auditlog.Input) { i.Metadata = json.RawMessage(`{"a": 10000000000000000}`) },
	}
	for name, mutate := range cases {
		i := input()
		mutate(&i)
		if err := i.Validate(now, 5*time.Minute, 24*time.Hour); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	many := map[string]int{}
	for k := range 51 {
		many[string(rune('a'+k%26))+string(rune('a'+k/26))] = k
	}
	raw, _ := json.Marshal(many)
	if err := auditlog.ValidateMetadata("metadata", raw); err == nil {
		t.Error("51 keys accepted")
	}
}

func TestCanonicalHash(t *testing.T) {
	a := input()
	b := a
	b.Metadata = json.RawMessage("{\n  \"paid\": true,   \"amount\": 10 }")
	b.OccurredAt = a.OccurredAt.In(time.FixedZone("x", 3600))
	ha, _ := a.Hash()
	hb, _ := b.Hash()
	if !bytes.Equal(ha, hb) {
		t.Fatal("equivalent requests hash differently")
	}
	// Absent, null and empty metadata alike.
	c, d := a, a
	c.Metadata, d.Metadata = nil, json.RawMessage(`{}`)
	hc, _ := c.Hash()
	hd, _ := d.Hash()
	if !bytes.Equal(hc, hd) {
		t.Fatal("empty metadata differs")
	}
	for name, mutate := range map[string]func(*auditlog.Input){
		"action":   func(i *auditlog.Input) { i.Action = "invoice.sent" },
		"actor":    func(i *auditlog.Input) { i.Actor.ID = "u2" },
		"target":   func(i *auditlog.Input) { i.Targets[0].ID = "inv_2" },
		"metadata": func(i *auditlog.Input) { i.Metadata = json.RawMessage(`{"amount": 11}`) },
		"version":  func(i *auditlog.Input) { v := 1; i.Version = &v },
		"context":  func(i *auditlog.Input) { i.Context.Location = "PE" },
		"time":     func(i *auditlog.Input) { i.OccurredAt = i.OccurredAt.Add(time.Second) },
	} {
		x := input()
		x.Organization, x.OccurredAt = a.Organization, a.OccurredAt
		x.Targets = []auditlog.Party{{Type: "invoice", ID: "inv_1"}}
		mutate(&x)
		hx, _ := x.Hash()
		if bytes.Equal(ha, hx) {
			t.Errorf("%s change keeps the hash", name)
		}
	}
	if len(ha) != 32 {
		t.Fatalf("hash length %d", len(ha))
	}
}

func TestActionInput(t *testing.T) {
	ok := auditlog.ActionInput{Name: "invoice.paid", TargetTypes: []string{"invoice"},
		Schema: auditlog.Schema{Metadata: json.RawMessage(`{"type":"object"}`), Targets: map[string]json.RawMessage{"invoice": json.RawMessage(`{"type":"object"}`)}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []auditlog.ActionInput{
		{Name: "invoice"},
		{Name: "Invoice.Paid"},
		{Name: "invoice.paid", TargetTypes: []string{"Bad"}},
		{Name: "invoice.paid", TargetTypes: []string{"a", "a"}},
		{Name: "invoice.paid", Description: strings.Repeat("x", 501)},
		{Name: "invoice.paid", Schema: auditlog.Schema{Metadata: json.RawMessage(`[]`)}},
		{Name: "invoice.paid", Schema: auditlog.Schema{Targets: map[string]json.RawMessage{"order": json.RawMessage(`{}`)}}},
	}
	for n, in := range bad {
		if err := in.Validate(); err == nil {
			t.Errorf("case %d accepted", n)
		}
	}
}

func TestActionUpdateBumps(t *testing.T) {
	current := auditlog.Action{Name: "invoice.paid", TargetTypes: []string{"invoice"}, Version: 1,
		Schema: auditlog.Schema{Metadata: json.RawMessage(`{"type":"object"}`)}}
	text := "new"
	next, rules, err := auditlog.ActionUpdate{Description: &text}.Apply(current)
	if err != nil || rules || next.Description != "new" {
		t.Fatalf("description: %v %v %+v", err, rules, next)
	}
	same := auditlog.Schema{Metadata: json.RawMessage(`{ "type" : "object" }`)}
	if _, rules, _ = (auditlog.ActionUpdate{Schema: &same}).Apply(current); rules {
		t.Fatal("reformatted schema bumps")
	}
	changed := auditlog.Schema{Metadata: json.RawMessage(`{"type":"object","required":["a"]}`)}
	if _, rules, _ = (auditlog.ActionUpdate{Schema: &changed}).Apply(current); !rules {
		t.Fatal("schema change does not bump")
	}
	types := []string{"invoice", "order"}
	if _, rules, _ = (auditlog.ActionUpdate{TargetTypes: &types}).Apply(current); !rules {
		t.Fatal("target type change does not bump")
	}
	orphan := []string{}
	withTarget := current
	withTarget.Schema.Targets = map[string]json.RawMessage{"invoice": json.RawMessage(`{}`)}
	if _, _, err = (auditlog.ActionUpdate{TargetTypes: &orphan}).Apply(withTarget); err == nil {
		t.Fatal("schema for a removed target type accepted")
	}
}

func TestFilterAndLimit(t *testing.T) {
	one, two := int64(1), int64(2)
	for name, f := range map[string]auditlog.Filter{
		"both cursors": {After: &one, Before: 5},
		"negative":     {After: func() *int64 { n := int64(-1); return &n }()},
		"bad action":   {Actions: []string{"nope"}},
		"range":        {OccurredAfter: &now, OccurredBefore: func() *time.Time { t := now.Add(-time.Hour); return &t }()},
	} {
		if f.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := (auditlog.Filter{After: &two, Actions: []string{"a.b"}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if auditlog.Limit(0) != 50 || auditlog.Limit(1000) != 200 || auditlog.Limit(7) != 7 {
		t.Fatal("limit")
	}
}

func TestErrors(t *testing.T) {
	if got := auditlog.ErrUnknownAction("a.b").Error(); !strings.Contains(got, "UNKNOWN_AUDIT_ACTION") {
		t.Fatal(got)
	}
	if got := auditlog.ErrKeyReused().Error(); !strings.Contains(got, "IDEMPOTENCY_KEY_REUSED") {
		t.Fatal(got)
	}
}
