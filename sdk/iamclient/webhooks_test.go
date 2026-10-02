package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhooks(t *testing.T) {
	var seen []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /management/v1/environments/env/webhooks":
			var in map[string]any
			json.NewDecoder(r.Body).Decode(&in)
			if in["name"] != "CRM" || len(in["types"].([]any)) != 1 {
				t.Errorf("create body = %v", in)
			}
			w.Write([]byte(`{"id":"w1","secret":"whsec_abc"}`))
		case "GET /management/v1/environments/env/webhooks/w1/deliveries":
			w.Write([]byte(`{"items":[{"id":3,"event_id":9,"event_type":"user.created","status":"failed","attempts":2}],"page":{"total":1}}`))
		case "POST /management/v1/environments/env/webhooks/w1/replay":
			w.Write([]byte(`{"queued":4}`))
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer remote.Close()
	env := New(remote.URL, "ik_mgmt_test").Environment("env")
	ctx := context.Background()
	name, url := "CRM", "https://crm.example/hook"
	secret, err := env.CreateWebhook(ctx, WebhookInput{Name: &name, URL: &url, Types: []string{"user.*"}})
	if err != nil || secret.Secret != "whsec_abc" {
		t.Fatalf("create = %+v %v", secret, err)
	}
	deliveries, err := env.WebhookDeliveries(ctx, "w1", "failed")
	if err != nil || len(deliveries) != 1 || deliveries[0].EventID != 9 {
		t.Fatalf("deliveries = %+v %v", deliveries, err)
	}
	if n, err := env.ReplayWebhook(ctx, "w1", 5); err != nil || n != 4 {
		t.Fatalf("replay = %d %v", n, err)
	}
	if err := env.RetryWebhookDelivery(ctx, "w1", 3); err != nil {
		t.Fatal(err)
	}
	if seen[1] != "GET /management/v1/environments/env/webhooks/w1/deliveries?status=failed" || seen[3] != "POST /management/v1/environments/env/webhooks/w1/deliveries/3/retry" {
		t.Fatalf("requests = %v", seen)
	}
	if _, err := env.Webhook(ctx, "../x"); err == nil {
		t.Fatal("unsafe id accepted")
	}
}
