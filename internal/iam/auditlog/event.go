package auditlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Limits of one emitted event (see Input.Validate).
const (
	MaxTargets         = 50
	MaxFieldLength     = 255
	MaxLocationLength  = 255
	MaxUserAgentLength = 1024
	MaxMetadataKeys    = 50
	MaxMetadataKey     = 40
	MaxMetadataValue   = 500
	MaxMetadataNumber  = 32
	MaxIdempotencyKey  = 255
)

// Party is the actor or a target of an event: who did it, or what it was
// done to.
type Party struct {
	Type     string          `json:"type"`
	ID       string          `json:"id"`
	Name     string          `json:"name,omitempty"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// Context is where the action came from.
type Context struct {
	Location  string `json:"location,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// Input is an event as an application emits it.
type Input struct {
	Organization identity.OrganizationID `json:"organization_id"`
	Action       string                  `json:"action"`
	OccurredAt   time.Time               `json:"occurred_at"`
	// Version is optional; when given it must be the action's current one.
	Version  *int            `json:"version,omitempty"`
	Actor    Party           `json:"actor"`
	Targets  []Party         `json:"targets"`
	Context  Context         `json:"context"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// Event is a stored event. Seq orders the log and is the paging cursor;
// ID is the public identifier. Action is the name the event was emitted
// with: it stays when the action is deleted.
type Event struct {
	Seq          int64                   `json:"seq"`
	ID           identity.AuditEventID   `json:"id"`
	Environment  identity.EnvironmentID  `json:"environment_id"`
	Organization identity.OrganizationID `json:"organization_id"`
	Action       string                  `json:"action"`
	Version      int                     `json:"version"`
	OccurredAt   time.Time               `json:"occurred_at"`
	Actor        Party                   `json:"actor"`
	Targets      []Party                 `json:"targets"`
	Context      Context                 `json:"context"`
	Metadata     json.RawMessage         `json:"metadata"`
	CreatedAt    time.Time               `json:"created_at"`
}

// Receipt is the answer to an accepted event; a replay of an idempotent
// request answers the same receipt.
type Receipt struct {
	ID        identity.AuditEventID `json:"id"`
	CreatedAt time.Time             `json:"created_at"`
}

// Idempotency identifies a request by its Idempotency-Key and the SHA-256
// of its canonical form.
type Idempotency struct {
	Key  string
	Hash []byte
}

// Inserted is what the repository reports for an insert or a key lookup.
// Replayed means the key was already used; Hash is the one it was used
// with (the caller compares it with its own).
type Inserted struct {
	Receipt
	Replayed bool
	Hash     []byte
}

func plainText(field, value string, max int, required bool) error {
	if required && value == "" {
		return errx.Validation(field + " is required")
	}
	if utf8.RuneCountInString(value) > max {
		return errx.Validation(field + " must be at most " + itoa(max) + " characters")
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == utf8.RuneError || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069' {
			return errx.Validation(field + " must not contain control characters")
		}
	}
	return nil
}

func itoa(n int) string {
	raw, _ := json.Marshal(n)
	return string(raw)
}

// Validate checks the party; label names it in errors (actor, targets[0]).
func (p Party) Validate(label string) error {
	if err := plainText(label+".type", p.Type, MaxFieldLength, true); err != nil {
		return err
	}
	if err := plainText(label+".id", p.ID, MaxFieldLength, true); err != nil {
		return err
	}
	if err := plainText(label+".name", p.Name, MaxFieldLength, false); err != nil {
		return err
	}
	return ValidateMetadata(label+".metadata", p.Metadata)
}

func (c Context) Validate() error {
	if err := plainText("context.location", c.Location, MaxLocationLength, false); err != nil {
		return err
	}
	return plainText("context.user_agent", c.UserAgent, MaxUserAgentLength, false)
}

// ValidateMetadata checks a metadata object: absent, null or an object of
// at most 50 keys (each at most 40 characters) with scalar values (strings
// of at most 500 characters, numbers, booleans). NUL is refused (jsonb
// cannot hold it).
func ValidateMetadata(field string, raw json.RawMessage) error {
	object, err := metadataObject(field, raw)
	if err != nil {
		return err
	}
	if len(object) > MaxMetadataKeys {
		return errx.Validation(field + " must have at most 50 keys")
	}
	for key, value := range object {
		if key == "" || utf8.RuneCountInString(key) > MaxMetadataKey {
			return errx.Validation(field + " keys must be 1 to 40 characters")
		}
		if err := plainText(field+" key "+key, key, MaxMetadataKey, true); err != nil {
			return err
		}
		switch v := value.(type) {
		case string:
			if utf8.RuneCountInString(v) > MaxMetadataValue {
				return errx.Validation(field + "." + key + " must be at most 500 characters")
			}
			if strings.ContainsRune(v, 0) || !utf8.ValidString(v) {
				return errx.Validation(field + "." + key + " must not contain the NUL character")
			}
		case json.Number:
			// Bounded so schema keywords (minimum, multipleOf) never do
			// big-number work and the value fits a jsonb numeric.
			f, err := v.Float64()
			if err != nil || len(v) > MaxMetadataNumber || math.IsInf(f, 0) || math.Abs(f) > 1e15 {
				return errx.Validation(field + "." + key + " must be a number of at most 15 digits")
			}
		case bool:
		default:
			return errx.Validation(field + "." + key + " must be a string, number or boolean")
		}
	}
	return nil
}

// metadataObject decodes raw (nil and null are an empty object).
func metadataObject(field string, raw json.RawMessage) (map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return map[string]any{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var object map[string]any
	if err := dec.Decode(&object); err != nil || object == nil || dec.More() {
		return nil, errx.Validation(field + " must be a JSON object")
	}
	return object, nil
}

// Validate checks everything that does not depend on the registered
// action: the shape and limits of the fields, and occurred_at within
// FutureSkew ahead of now and retention behind it.
func (i Input) Validate(now time.Time, futureSkew, retention time.Duration) error {
	if i.Organization.IsZero() {
		return errx.Validation("organization_id is required")
	}
	if !ValidName(i.Action) {
		return errx.Validation("action must be lowercase words separated by dots, such as invoice.paid")
	}
	if i.OccurredAt.IsZero() {
		return errx.Validation("occurred_at is required")
	}
	if i.OccurredAt.After(now.Add(futureSkew)) {
		return errx.Validation("occurred_at must not be more than " + futureSkew.String() + " in the future")
	}
	if i.OccurredAt.Before(now.Add(-retention)) {
		return errx.Validation("occurred_at must be within the retention period")
	}
	if i.Version != nil && *i.Version < 1 {
		return errx.Validation("version must be a positive integer")
	}
	if err := i.Actor.Validate("actor"); err != nil {
		return err
	}
	if len(i.Targets) > MaxTargets {
		return errx.Validation("targets must have at most 50 entries")
	}
	for n, t := range i.Targets {
		if err := t.Validate("targets[" + itoa(n) + "]"); err != nil {
			return err
		}
	}
	if err := i.Context.Validate(); err != nil {
		return err
	}
	return ValidateMetadata("metadata", i.Metadata)
}

// ValidateIdempotencyKey checks an Idempotency-Key header value.
func ValidateIdempotencyKey(key string) error {
	return plainText("Idempotency-Key", key, MaxIdempotencyKey, true)
}

type canonicalParty struct {
	Type     string         `json:"type"`
	ID       string         `json:"id"`
	Name     string         `json:"name,omitempty"`
	Metadata map[string]any `json:"metadata"`
}

type canonicalInput struct {
	Organization string           `json:"organization_id"`
	Action       string           `json:"action"`
	OccurredAt   string           `json:"occurred_at"`
	Version      *int             `json:"version,omitempty"`
	Actor        canonicalParty   `json:"actor"`
	Targets      []canonicalParty `json:"targets"`
	Context      Context          `json:"context"`
	Metadata     map[string]any   `json:"metadata"`
}

func canonicalParties(label string, p Party) (canonicalParty, error) {
	metadata, err := metadataObject(label+".metadata", p.Metadata)
	return canonicalParty{Type: p.Type, ID: p.ID, Name: p.Name, Metadata: metadata}, err
}

// Canonical is the request in one stable form: members in fixed order,
// object keys sorted, no insignificant whitespace, absent and empty
// metadata alike, occurred_at in UTC. Two requests that say the same thing
// have the same canonical form.
func (i Input) Canonical() ([]byte, error) {
	out := canonicalInput{Organization: i.Organization.String(), Action: i.Action,
		OccurredAt: i.OccurredAt.UTC().Format(time.RFC3339Nano), Version: i.Version, Context: i.Context,
		Targets: []canonicalParty{}}
	var err error
	if out.Actor, err = canonicalParties("actor", i.Actor); err != nil {
		return nil, err
	}
	for n, t := range i.Targets {
		c, err := canonicalParties("targets["+itoa(n)+"]", t)
		if err != nil {
			return nil, err
		}
		out.Targets = append(out.Targets, c)
	}
	if out.Metadata, err = metadataObject("metadata", i.Metadata); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

// Hash is the SHA-256 of the canonical form: what an Idempotency-Key is
// bound to.
func (i Input) Hash() ([]byte, error) {
	raw, err := i.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return sum[:], nil
}

// Filter narrows the log. With After (0 = the beginning) the log is read
// oldest first from that seq, a feed cursor; otherwise newest first, below
// Before when set.
type Filter struct {
	Organization identity.OrganizationID
	// Actions are exact action names.
	Actions    []string
	ActorID    string
	ActorType  string
	TargetID   string
	TargetType string
	// OccurredAfter / OccurredBefore bound occurred_at (inclusive).
	OccurredAfter  *time.Time
	OccurredBefore *time.Time
	After          *int64
	Before         int64
}

// MaxFilterActions caps the actions one filter may name.
const MaxFilterActions = 20

// ExportBatch is how many events one export query reads.
const ExportBatch = 1000

// Page limits.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Limit clamps a requested page size.
func Limit(n int) int {
	if n <= 0 {
		return DefaultLimit
	}
	return min(n, MaxLimit)
}

func (f Filter) Validate() error {
	if len(f.Actions) > MaxFilterActions {
		return errx.Validation("action may name at most 20 actions")
	}
	for _, a := range f.Actions {
		if !ValidName(a) {
			return errx.Validation("action must be action names such as invoice.paid")
		}
	}
	for field, value := range map[string]string{"actor_id": f.ActorID, "actor_type": f.ActorType, "target_id": f.TargetID, "target_type": f.TargetType} {
		if err := plainText(field, value, MaxFieldLength, false); err != nil {
			return err
		}
	}
	if (f.After != nil && *f.After < 0) || f.Before < 0 {
		return errx.Validation("after and before must be event seq cursors")
	}
	if f.After != nil && f.Before != 0 {
		return errx.Validation("after and before cannot be combined")
	}
	if f.OccurredAfter != nil && f.OccurredBefore != nil && f.OccurredBefore.Before(*f.OccurredAfter) {
		return errx.Validation("occurred_before must not be earlier than occurred_after")
	}
	return nil
}

// Page is one page of the log. Next is the cursor for the following page:
// with After, pass it as after (the newest seq returned, or the cursor
// itself when nothing new arrived); without After, pass it as before (the
// oldest seq returned, 0 when the log is exhausted).
type Page struct {
	Items []Event `json:"items"`
	Next  int64   `json:"next"`
}
