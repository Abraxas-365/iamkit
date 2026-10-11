package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSessionEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Authorization"))
		switch {
		case r.Method == "GET":
			w.Write([]byte(`{"items":[{"id":"s1","current":true,"organization":{"id":"o","name":"Acme"},"application":{"id":"a","name":"web"},"ip_address":"203.0.113.7","user_agent":"curl","amr":["pwd"]}],"page":{"total":1,"limit":20,"offset":0}}`))
		case r.Method == "POST":
			w.Write([]byte(`{"count":2}`))
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()
	page, err := c.ListSessions(ctx, "tok", "env", "https://a.example", 5, 0)
	if err != nil || len(page.Items) != 1 || !page.Items[0].Current || page.Items[0].Organization.Name != "Acme" || *page.Items[0].IPAddress != "203.0.113.7" || page.Page.Total != 1 {
		t.Fatalf("sessions = %+v %v", page, err)
	}
	if err := c.RevokeSession(ctx, "tok", "env", "https://a.example", "s1"); err != nil {
		t.Fatal(err)
	}
	if n, err := c.RevokeOtherSessions(ctx, "tok", "env", "https://a.example"); err != nil || n != 2 {
		t.Fatalf("revoke others = %d %v", n, err)
	}
	want := []string{
		"GET /identity/v1/me/sessions?environment_id=env&audience=https%3A%2F%2Fa.example&limit=5 Bearer tok",
		"DELETE /identity/v1/me/sessions/s1?environment_id=env&audience=https%3A%2F%2Fa.example Bearer tok",
		"POST /identity/v1/me/sessions/revoke-others?environment_id=env&audience=https%3A%2F%2Fa.example Bearer tok",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %v", calls)
	}
}
