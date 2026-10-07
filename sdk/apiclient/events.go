package apiclient

import (
	"context"
	"encoding/json"
	"io"
	"net/url"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/Abraxas-365/iamkit/sdk/internal/transport"
)

// Events reads the environment's event log (needs iam:events:read).
func (e Environment) Events(ctx context.Context, filter EventFilter) (EventPage, error) {
	var out EventPage
	err := e.client.do(ctx, "GET", e.path("events"), filter.Query(), nil, &out)
	if out.Items == nil {
		out.Items = []Event{}
	}
	return out, err
}

// History reads one entity's events newest first (collection "users",
// "organizations", "applications", "roles" or "resources"; needs the
// collection's read permission and iam:events:read). Updates carry
// data.changes {"field": [old, new]}.
func (e Environment) History(ctx context.Context, collection, id string, filter EventFilter) (EventPage, error) {
	var out EventPage
	err := e.client.do(ctx, "GET", e.path(url.PathEscape(collection), url.PathEscape(id), "history"), filter.Query(), nil, &out)
	if out.Items == nil {
		out.Items = []Event{}
	}
	return out, err
}

// ExportEvents streams the matching events oldest first (iam:events:read)
// and calls fn for each until the log ends or fn returns an error.
func (e Environment) ExportEvents(ctx context.Context, filter EventFilter, fn func(Event) error) error {
	if e.client.token == "" {
		return &apierror.Error{Code: "UNAUTHORIZED", Message: "bearer token required", HTTPStatus: 401}
	}
	path := "/api/v1" + e.path("events", "export")
	// The export streams to the end of the log: no page size.
	filter.Limit = 0
	if q := filter.Query(); len(q) > 0 {
		path += "?" + q.Encode()
	}
	body, err := transport.Stream(e.client.http, ctx, e.client.baseURL+path, []transport.Header{{Key: "Authorization", Value: "Bearer " + e.client.token}})
	if err != nil {
		return err
	}
	defer body.Close()
	dec := json.NewDecoder(body)
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
