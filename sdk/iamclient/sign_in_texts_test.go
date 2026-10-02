package iamclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSignInTextsEndpoints(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(b)))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "DELETE":
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/catalog"):
			w.Write([]byte(`{"locale":"es","items":[{"key":"hosted.notice.code_sent","default":"Enviamos a %s.","placeholders":["%s"],"max_length":120}]}`))
		case strings.HasSuffix(r.URL.Path, "/texts"):
			w.Write([]byte(`{"items":[{"locale":"en","texts":{"hosted.form.continue":"Next"}}],"page":{"total":1,"limit":50,"offset":0}}`))
		default:
			w.Write([]byte(`{"environment_id":"env-1","client_id":"c1","locale":"en","texts":{"hosted.form.continue":"Next"},"updated_at":"2026-01-01T00:00:00Z"}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	catalog, err := env.SignInTextCatalog(ctx, "es")
	if err != nil || len(catalog) != 1 || catalog[0].Placeholders[0] != "%s" || catalog[0].MaxLength != 120 {
		t.Fatalf("catalog = %+v %v", catalog, err)
	}
	sets, err := env.SignInTextSets(ctx)
	if err != nil || len(sets) != 1 || sets[0].Texts["hosted.form.continue"] != "Next" {
		t.Fatalf("sets = %+v %v", sets, err)
	}
	got, err := env.SignInTexts(ctx, TextScope{ClientID: "c1"}, "en")
	if err != nil || got.ClientID != "c1" || got.Texts["hosted.form.continue"] != "Next" {
		t.Fatalf("texts = %+v %v", got, err)
	}
	if _, err := env.SetSignInTexts(ctx, TextScope{OrganizationID: "o1"}, "es", map[string]string{"hosted.form.continue": "Seguir"}); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteSignInTexts(ctx, TextScope{}, "en"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.SignInTexts(ctx, TextScope{ClientID: "../x"}, "en"); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	base := "/management/v1/environments/env-1/login-settings"
	want := []string{
		"GET " + base + "/texts/catalog?locale=es",
		"GET " + base + "/texts",
		"GET " + base + "/clients/c1/texts/en",
		"PUT " + base + "/organizations/o1/texts/es",
		"DELETE " + base + "/texts/en",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	if bodies[3] != `{"texts":{"hosted.form.continue":"Seguir"}}` {
		t.Fatalf("body = %s", bodies[3])
	}
}
