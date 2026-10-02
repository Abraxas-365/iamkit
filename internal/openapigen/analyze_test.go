package openapigen

import (
	"path/filepath"
	"testing"
)

// The analyser is exercised end to end by cmd/openapi (freshness) and the
// e2e contract checks; these pin the patterns it must keep recognizing.
func TestAnalyze(t *testing.T) {
	if testing.Short() {
		t.Skip("loads every package")
	}
	a, err := Load(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const mod = "github.com/Abraxas-365/iamkit/internal/"
	analyze := func(name string) Operation {
		t.Helper()
		src := a.funcs[mod+name]
		if src == nil {
			t.Fatalf("%s not found", name)
		}
		return a.Analyze(src)
	}
	status := func(op Operation, code int) *Response {
		for i := range op.Responses {
			if op.Responses[i].Status == code {
				return &op.Responses[i]
			}
		}
		return nil
	}

	// A paginated list: pagination query parameters, a typed 200.
	list := analyze("iam/application/adapters/apphttp.(*Handler).List")
	if list.Query["limit"] != "integer" || list.Query["search"] != "string" {
		t.Errorf("list query = %v", list.Query)
	}
	if r := status(list, 200); r == nil || r.Schema["$ref"] != "#/components/schemas/PaginatedApplication" {
		t.Errorf("list 200 = %+v", r)
	}

	// A create: BodyParser target, Status(201).JSON.
	create := analyze("iam/application/adapters/apphttp.(*Handler).Create")
	if create.Body == nil {
		t.Error("create has no request body")
	}
	if status(create, 201) == nil {
		t.Errorf("create responses = %+v", create.Responses)
	}

	// Through a function-typed field wired in bootstrap (Bindings).
	login := analyze("iam/authentication/adapters/authhttp.(*Handler).Login")
	if status(login, 200) == nil {
		t.Errorf("login responses = %+v", login.Responses)
	}

	// OAuth endpoints answer {"error": code} with explicit statuses.
	revoke := analyze("iam/oauth/adapters/oauthhttp.(*Handler).revoke")
	if r := status(revoke, 400); r == nil || r.Schema == nil {
		t.Errorf("revoke 400 = %+v", r)
	}
}
