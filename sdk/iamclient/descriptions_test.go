package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPermissionDescriptions(t *testing.T) {
	var calls []string
	var put map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "PUT" {
			_ = json.NewDecoder(r.Body).Decode(&put)
			w.WriteHeader(204)
			return
		}
		w.Write([]byte(`{"items":[{"permission":"orders:read","locale":"es","display_name":"Leer pedidos","description":"Ver pedidos."}]}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	got, err := env.PermissionDescriptions(ctx, "r1")
	if err != nil || len(got) != 1 || got[0].Locale != "es" || got[0].DisplayName != "Leer pedidos" {
		t.Fatalf("get = %+v %v", got, err)
	}
	if err := env.SetPermissionDescriptions(ctx, "r1", nil); err != nil {
		t.Fatal(err)
	}
	if items, ok := put["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("clearing must send an empty list: %v", put)
	}
	if err := env.SetPermissionDescriptions(ctx, "r1", got); err != nil {
		t.Fatal(err)
	}
	if items, _ := put["items"].([]any); len(items) != 1 || items[0].(map[string]any)["display_name"] != "Leer pedidos" {
		t.Fatalf("put = %v", put)
	}
	want := "/management/v1/environments/env-1/resources/r1/permission-descriptions"
	for i, call := range calls {
		method := []string{"GET", "PUT", "PUT"}[i]
		if call != method+" "+want {
			t.Fatalf("call %d = %s", i, call)
		}
	}
}
