package e2e_test

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

// importResults returns the per-row results of an import response.
func importResults(t *testing.T, res Response) []map[string]any {
	t.Helper()
	raw, _ := res.JSON["results"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

func rowCode(row map[string]any) string {
	e, _ := row["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

// TestUserImport: POST …/users/import creates up to 100 users, each row on
// its own; password_hash keeps an existing bcrypt password (no policy), the
// user signs in with the old password, email_verified and metadata are
// stored, events say origin import, machine rows and org admins cannot use
// the hash, and /api/v1 needs iam:users:write.
func TestUserImport(t *testing.T) {
	e := newEnv(t)
	url := e.Base + "/users/import"
	hash, err := bcrypt.GenerateFromPassword([]byte("old pw"), 10) // shorter than the password policy allows
	if err != nil {
		t.Fatal(err)
	}

	// Bounds and malformed bodies.
	e.Must("POST", url, e.Owner, fiber.Map{"users": []any{}}, 400)
	e.Must("POST", url, e.Owner, fiber.Map{}, 400)
	e.Must("POST", url, e.Owner, "nope", 400)
	rows := make([]fiber.Map, 101)
	for i := range rows {
		rows[i] = fiber.Map{"email": "x@example.com", "name": "X"}
	}
	e.Must("POST", url, e.Owner, fiber.Map{"users": rows}, 400)
	e.Must("POST", url, "", fiber.Map{"users": rows[:1]}, 401)

	// A mix of successes and failures answers 200.
	res := e.Must("POST", url, e.Owner, fiber.Map{"users": []fiber.Map{
		{"email": "Ivy@Example.com", "name": "Ivy", "password_hash": " " + string(hash) + " ", "email_verified": true, "external_id": "legacy-1",
			"metadata": fiber.Map{"plan": "pro", "seats": 3}},
		{"email": e.AliceEmail, "name": "Alice again"},                                                // conflict
		{"email": "no-name@example.com"},                                                              // validation
		{"email": "both@example.com", "name": "B", "password": e.Pass, "password_hash": string(hash)}, // exclusive
		{"email": "weird@example.com", "name": "W", "password_hash": "{SSHA}abcdef"},                  // unsupported
		{"kind": "machine", "name": "bot", "password_hash": string(hash)},                             // machine
		{"kind": "machine", "name": "bot2", "email_verified": true},                                   // machine
		{"email": "jon@example.com", "name": "Jon", "metadata": []int{1}},                             // metadata not an object
		{"email": "kim@example.com", "name": "Kim", "password": e.Pass},                               // plain password, policy applies
		{"email": "short@example.com", "name": "Short", "password": "short"},                          // policy
		{"email": "ivy@example.com", "name": "Dup in batch"},                                          // conflict with row 0
		{"email": "uname@example.com", "name": "U", "username": "ivy-2"},
		{"email": "uname2@example.com", "name": "U2", "username": "ivy-2"}, // username conflict
	}}, 200)
	results := importResults(t, res)
	want := []string{"", "CONFLICT", "VALIDATION", "VALIDATION", "VALIDATION", "VALIDATION", "VALIDATION", "VALIDATION", "", "PASSWORD_POLICY", "CONFLICT", "", "CONFLICT"}
	if len(results) != len(want) {
		t.Fatalf("results = %s", res.Body)
	}
	created := 0
	for i, row := range results {
		if row["index"] != float64(i) {
			t.Fatalf("row %d index = %v", i, row["index"])
		}
		if want[i] == "" {
			created++
			if id, _ := row["id"].(string); id == "" || row["error"] != nil {
				t.Fatalf("row %d = %v", i, row)
			}
		} else if rowCode(row) != want[i] || row["id"] != nil {
			t.Fatalf("row %d = %v, want %s", i, row, want[i])
		}
	}
	if res.JSON["created"] != float64(created) || res.JSON["failed"] != float64(len(want)-created) {
		t.Fatalf("counts = %v/%v", res.JSON["created"], res.JSON["failed"])
	}
	if strings.Contains(res.Body, string(hash)) {
		t.Fatal("the result echoes the hash")
	}
	if msg := results[1]["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "email") {
		t.Fatalf("conflict message = %q", msg)
	}

	// Stored: email_verified, metadata, external ID, the hash as sent (trimmed).
	ivy := results[0]["id"].(string)
	got := e.Must("GET", e.Base+"/users/"+ivy, e.Owner, nil, 200).JSON
	meta, _ := got["metadata"].(map[string]any)
	if got["email"] != "ivy@example.com" || got["email_verified"] != true || got["external_id"] != "legacy-1" || meta["plan"] != "pro" || meta["seats"] != float64(3) {
		t.Fatalf("imported user = %v", got)
	}
	var stored string
	if err := e.DB.Get(&stored, `SELECT password_hash FROM users WHERE id=$1`, ivy); err != nil || stored != string(hash) {
		t.Fatalf("stored hash = %q %v", stored, err)
	}
	kim := results[8]["id"].(string)
	if err := e.DB.Get(&stored, `SELECT password_hash FROM users WHERE id=$1`, kim); err != nil || stored == e.Pass || bcrypt.CompareHashAndPassword([]byte(stored), []byte(e.Pass)) != nil {
		t.Fatalf("plain password row stored %q %v", stored, err)
	}
	if got := e.Must("GET", e.Base+"/users/"+kim, e.Owner, nil, 200).JSON["email_verified"]; got != false {
		t.Fatalf("email_verified defaults to %v", got)
	}

	// The imported user signs in with the old password, then it keeps working.
	e.Join(e.Org, ivy)
	e.Grant(e.Org, ivy, e.Res, "invoices:read")
	for range 2 {
		e.Must("POST", "/identity/v1/login", "", e.LoginBody("ivy@example.com", "old pw"), 200)
	}
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("ivy@example.com", "wrong"), 401)

	// Events: origin import for the batch, api for the regular create.
	events := e.Must("GET", e.Base+"/events?type=user.created&subject="+ivy, e.Owner, nil, 200)
	items := events.JSON["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["data"].(map[string]any)["origin"] != "import" {
		t.Fatalf("import event = %s", events.Body)
	}
	if strings.Contains(events.Body, string(hash)) {
		t.Fatal("hash in the event")
	}
	single := e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "solo@example.com", "name": "Solo", "password_hash": string(hash), "email_verified": true, "metadata": fiber.Map{"k": "v"}}, 201).JSON["id"].(string)
	events = e.Must("GET", e.Base+"/events?type=user.created&subject="+single, e.Owner, nil, 200)
	if items = events.JSON["items"].([]any); len(items) != 1 || items[0].(map[string]any)["data"].(map[string]any)["origin"] != "api" {
		t.Fatalf("api event = %s", events.Body)
	}
	if got := e.Must("GET", e.Base+"/users/"+single, e.Owner, nil, 200).JSON; got["email_verified"] != true || got["metadata"].(map[string]any)["k"] != "v" {
		t.Fatalf("regular create = %v", got)
	}
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "weird2@example.com", "name": "W", "password_hash": "plain"}, 400)
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "weird3@example.com", "name": "W", "password": e.Pass, "password_hash": string(hash)}, 400)
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"kind": "machine", "name": "bot3", "password_hash": string(hash)}, 400)
	e.Must("POST", e.Base+"/users", e.Owner, fiber.Map{"email": "weird4@example.com", "name": "W", "password_hash": "$2a$" + strings.Repeat("a", 1100)}, 400)

	// /api/v1: iam:users:write and iam:users:import.
	api := "/api/v1/environments/" + e.EnvID + "/users/import"
	body := fiber.Map{"users": []fiber.Map{{"email": "api1@example.com", "name": "Api", "password_hash": string(hash)}}}
	e.Must("POST", api, "", body, 401)
	e.Must("POST", api, e.scopedToken("iam:users:read"), body, 403)
	e.Must("POST", api, e.scopedToken("iam:orgs:write"), body, 403)
	writer := e.scopedToken("iam:users:write")
	e.Must("POST", api, writer, body, 403)
	e.Must("POST", api, e.scopedToken("iam:users:import"), body, 403)
	// Asserted fields on create need it too; metadata and a password do not.
	users := "/api/v1/environments/" + e.EnvID + "/users"
	e.Must("POST", users, writer, fiber.Map{"email": "api2@example.com", "name": "Api", "password_hash": string(hash)}, 403)
	e.Must("POST", users, writer, fiber.Map{"email": "api3@example.com", "name": "Api", "email_verified": true}, 403)
	e.Must("POST", users, writer, fiber.Map{"email": "api4@example.com", "name": "Api", "password": e.Pass, "metadata": fiber.Map{"plan": "pro"}}, 201)
	importer := e.scopedToken("iam:users:write", "iam:users:import")
	e.Must("POST", users, importer, fiber.Map{"email": "api5@example.com", "name": "Api", "email_verified": true}, 201)
	ok := e.Must("POST", api, importer, body, 200)
	if ok.JSON["created"] != float64(1) || ok.JSON["failed"] != float64(0) {
		t.Fatalf("api import = %s", ok.Body)
	}
	if strings.Contains(ok.Body, string(hash)) {
		t.Fatal("api result echoes the hash")
	}
}

// TestUserImportQuota: each row is admitted against users_max on its own.
func TestUserImportQuota(t *testing.T) {
	e := newEnv(t)
	e.Must("PUT", e.Base+"/limits", e.Owner, fiber.Map{"users_max": 3}, 200) // Alice + two more
	res := e.Must("POST", e.Base+"/users/import", e.Owner, fiber.Map{"users": []fiber.Map{
		{"email": "q1@example.com", "name": "Q1"},
		{"email": "q2@example.com", "name": "Q2"},
		{"email": "q3@example.com", "name": "Q3"},
		{"email": "q4@example.com", "name": "Q4"},
	}}, 200)
	results := importResults(t, res)
	if res.JSON["created"] != float64(2) || res.JSON["failed"] != float64(2) {
		t.Fatalf("counts = %s", res.Body)
	}
	if results[0]["id"] == nil || results[1]["id"] == nil || rowCode(results[2]) != "QUOTA_EXCEEDED" || rowCode(results[3]) != "QUOTA_EXCEEDED" {
		t.Fatalf("results = %s", res.Body)
	}
}

// TestUserImportOrgAdminCannotSetHash: an organization's administrators
// create users without password_hash or email_verified, whatever they send.
func TestUserImportOrgAdminCannotSetHash(t *testing.T) {
	e := newEnv(t)
	iam := e.IAMResource()
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": iam}, 201)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": e.systemRole("org_owner")}, 204)
	token := e.orgAdminToken(e.Org, e.AliceEmail)
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	hash, err := bcrypt.GenerateFromPassword([]byte("old pw"), 10)
	if err != nil {
		t.Fatal(err)
	}

	// Sent next to a password: the extra fields are ignored.
	id := e.Must("POST", admin+"/users", token, fiber.Map{"email": "nina@example.com", "name": "Nina", "password": e.Pass, "password_hash": string(hash), "email_verified": true, "metadata": fiber.Map{"a": 1}}, 201).JSON["id"].(string)
	var row struct {
		Hash     string `db:"password_hash"`
		Verified bool   `db:"email_verified"`
		Metadata string `db:"metadata"`
	}
	if err := e.DB.Get(&row, `SELECT password_hash, email_verified, metadata::text AS metadata FROM users WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if row.Verified || row.Hash == string(hash) || bcrypt.CompareHashAndPassword([]byte(row.Hash), []byte(e.Pass)) != nil || row.Metadata != "{}" {
		t.Fatalf("org admin create stored %+v", row)
	}

	// Without a password the hash alone gives the user none.
	id = e.Must("POST", admin+"/users", token, fiber.Map{"email": "omar@example.com", "name": "Omar", "password_hash": string(hash), "email_verified": true}, 201).JSON["id"].(string)
	if err := e.DB.Get(&row, `SELECT password_hash, email_verified, metadata::text AS metadata FROM users WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if row.Verified || row.Hash != "" {
		t.Fatalf("org admin create stored %+v", row)
	}

	// The import route needs iam:users:write + iam:users:import, which org
	// admins do not hold.
	e.Must("POST", "/api/v1/environments/"+e.EnvID+"/users/import", token, fiber.Map{"users": []fiber.Map{{"email": "z@example.com", "name": "Z"}}}, 403)
}

// TestUserImportEveryFormat: each supported hash format goes through the
// import route, signs in with the original password and is rehashed to
// bcrypt; an over-cap hash is refused at import.
func TestUserImportEveryFormat(t *testing.T) {
	e := newEnv(t)
	hashes := importedHashes(t, "legacy password")
	rows := []fiber.Map{}
	names := []string{}
	for name, hash := range hashes {
		names = append(names, name)
		rows = append(rows, fiber.Map{"email": "fmt-" + name + "@example.com", "name": name, "password_hash": hash})
	}
	rows = append(rows, fiber.Map{"email": "overcap@example.com", "name": "Over", "password_hash": "$argon2id$v=19$m=4194304,t=1,p=1$c2FsdHNhbHQ$c2FsdHNhbHRzYWx0c2FsdA"})
	res := e.Must("POST", e.Base+"/users/import", e.Owner, fiber.Map{"users": rows}, 200)
	results := importResults(t, res)
	if last := results[len(results)-1]; rowCode(last) != "VALIDATION" {
		t.Fatalf("over-cap row = %v", last)
	}
	for i, name := range names {
		id, _ := results[i]["id"].(string)
		if id == "" {
			t.Fatalf("%s import = %v", name, results[i])
		}
		e.Join(e.Org, id)
		e.Grant(e.Org, id, e.Res, "invoices:read")
		e.Must("POST", "/identity/v1/login", "", e.LoginBody("fmt-"+name+"@example.com", "legacy password"), 200)
		var stored string
		if err := e.DB.Get(&stored, `SELECT password_hash FROM users WHERE id=$1`, id); err != nil || bcrypt.CompareHashAndPassword([]byte(stored), []byte("legacy password")) != nil {
			t.Fatalf("%s not rehashed: %q %v", name, stored, err)
		}
	}
}
