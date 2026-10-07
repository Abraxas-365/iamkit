package iamclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/internal/transport"
)

// Event is one entry of an environment's typed event log.
type Event struct {
	ID             int64           `json:"id"`
	EnvironmentID  string          `json:"environment_id"`
	Type           string          `json:"type"`
	Actor          EventParty      `json:"actor"`
	Subject        EventParty      `json:"subject"`
	OrganizationID string          `json:"organization_id,omitempty"`
	Data           json.RawMessage `json:"data,omitempty"`
	OccurredAt     time.Time       `json:"occurred_at"`
}

// EventParty is an event's actor or subject. Actor kinds are "operator",
// "user", "service_account", "directory" and "system" (empty ID).
type EventParty struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
}

// EventFilter narrows Events. Types are exact ("user.created") or families
// ("user.*"). Set After (0 = the beginning) to read oldest first as a feed;
// otherwise events come newest first below Before (0 = the newest).
type EventFilter struct {
	Types          []string
	Subject        string
	OrganizationID string
	After          *int64
	Before         int64
	// Limit is the page size of Events and History (export ignores it).
	Limit int
}

// EventPage is one page of events. With EventFilter.After, pass Next as the
// next After (it stays put when nothing new arrived); otherwise pass it as
// Before, 0 meaning no older events.
type EventPage struct {
	Items []Event `json:"items"`
	Next  int64   `json:"next"`
}

// Events reads the environment's event log.
func (e Environment) Events(ctx context.Context, filter EventFilter) (EventPage, error) {
	var out EventPage
	err := e.client.do(ctx, "GET", e.path("events"), filter.Query(), nil, &out)
	if out.Items == nil {
		out.Items = []Event{}
	}
	return out, err
}

// Query encodes the filter as query parameters.
func (f EventFilter) Query() url.Values {
	q := url.Values{}
	if len(f.Types) > 0 {
		q["type"] = f.Types
	}
	set := func(key, value string) {
		if value != "" {
			q[key] = []string{value}
		}
	}
	set("subject", f.Subject)
	set("organization_id", f.OrganizationID)
	if f.After != nil {
		set("after", strconv.FormatInt(*f.After, 10))
	}
	if f.Before > 0 {
		set("before", strconv.FormatInt(f.Before, 10))
	}
	if f.Limit > 0 {
		set("limit", strconv.Itoa(f.Limit))
	}
	return q
}

// History reads one entity's events newest first: collection is "users",
// "organizations", "applications", "oauth-clients", "roles" or
// "resources". Updates carry data.changes {"field": [old, new]}; page back
// with filter.Before (filter.After and Subject are not allowed).
func (e Environment) History(ctx context.Context, collection, id string, filter EventFilter) (EventPage, error) {
	var out EventPage
	if err := safeSegment(collection); err != nil {
		return out, err
	}
	if err := safeSegment(id); err != nil {
		return out, err
	}
	err := e.client.do(ctx, "GET", e.path(collection+"/"+id+"/history"), filter.Query(), nil, &out)
	if out.Items == nil {
		out.Items = []Event{}
	}
	return out, err
}

// ExportEvents streams the matching events oldest first (from
// filter.After, default the beginning; Before is not allowed) and calls
// fn for each until the log ends or fn returns an error.
func (e Environment) ExportEvents(ctx context.Context, filter EventFilter, fn func(Event) error) error {
	path := "/management/v1" + e.path("events/export")
	// The export streams to the end of the log: no page size.
	filter.Limit = 0
	if q := filter.Query(); len(q) > 0 {
		path += "?" + q.Encode()
	}
	if !strings.HasPrefix(e.client.key, "ik_mgmt_") {
		return fmt.Errorf("management credential required")
	}
	body, err := transport.Stream(e.client.http, ctx, e.client.baseURL+path, []transport.Header{{Key: "X-API-Key", Value: e.client.key}})
	if err != nil {
		return err
	}
	defer body.Close()
	return decodeEvents(body, fn)
}

// decodeEvents reads NDJSON events.
func decodeEvents(r io.Reader, fn func(Event) error) error {
	dec := json.NewDecoder(r)
	for {
		var ev Event
		if err := dec.Decode(&ev); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
}
