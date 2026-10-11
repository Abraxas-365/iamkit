package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	fakeBcrypt = "$2a$10$fakefakefakefakefakefuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
	fakeArgon  = "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$ZmFrZWhhc2hmYWtlaGFzaA"
	fakeDjango = "pbkdf2_sha256$100000$fakesalt$ZmFrZQ=="
)

func byEmail(items []importItem) map[string]importItem {
	m := map[string]importItem{}
	for _, it := range items {
		m[it.User.Email] = it
	}
	return m
}

func TestConvertIAMKit(t *testing.T) {
	cases := []struct {
		name, in string
		rows     int
		wantRow  map[int]string // row → code ("" = ok)
		wantErr  string
	}{
		{"array", `[{"email":"a@x.io","name":"A"},{"email":"b@x.io","name":"B","email_verified":true}]`, 2, map[int]string{1: "", 2: ""}, ""},
		{"jsonl numbers lines", "{\"email\":\"a@x.io\",\"name\":\"A\"}\n\n{\"email\":\"b@x.io\",\"name\":\"B\"}\n", 2, map[int]string{1: "", 3: ""}, ""},
		{"unknown field", `{"email":"a@x.io","name":"A","role":"admin"}`, 1, map[int]string{1: codeInvalid}, ""},
		{"metadata not object", `{"email":"a@x.io","name":"A","metadata":"x"}`, 1, map[int]string{1: codeInvalid}, ""},
		{"broken line", "{\"email\":\"a@x.io\",\"name\":\"A\"}\n{nope\n", 2, map[int]string{1: "", 2: codeInvalid}, ""},
		{"empty", "", 0, nil, "no users"},
		{"broken array", `[{"email"`, 0, nil, "JSON array"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			items, err := convertImport([]byte(c.in), importOptions{})
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil || len(items) != c.rows {
				t.Fatalf("items = %d, err = %v", len(items), err)
			}
			for _, it := range items {
				if want, ok := c.wantRow[it.Row]; !ok || it.Code != want {
					t.Errorf("row %d code = %q (%s), want %q", it.Row, it.Code, it.Message, want)
				}
			}
		})
	}
}

func TestConvertAuth0(t *testing.T) {
	in := strings.Join([]string{
		fmt.Sprintf(`{"user_id":"auth0|1","email":"ann@x.io","email_verified":true,"name":"Ann A","username":"ann","passwordHash":%q,"user_metadata":{"a":1},"app_metadata":{"b":2}}`, fakeBcrypt),
		`{"user_id":"auth0|2","email":"bob@x.io","given_name":"Bob","family_name":"B"}`,
		`{"user_id":"auth0|3","email":"cy@x.io","nickname":"cyn"}`,
		`{"user_id":"auth0|4","email":"di@x.io"}`,
		`{"user_id":"auth0|5","name":"No Mail"}`,
		fmt.Sprintf(`{"user_id":"auth0|6","email":"ed@x.io","custom_password_hash":{"algorithm":"argon2","hash":{"value":%q}}}`, fakeArgon),
		`{"user_id":"auth0|7","email":"flo@x.io","custom_password_hash":{"algorithm":"md5","hash":{"value":"abcd"}}}`,
	}, "\n")

	got, err := convertImport([]byte(in), importOptions{From: "auth0", Metadata: true})
	if err != nil || len(got) != 7 {
		t.Fatalf("got %d, %v", len(got), err)
	}
	m := byEmail(got)
	ann := m["ann@x.io"].User
	if ann.ExternalID != "auth0|1" || !ann.EmailVerified || ann.Name != "Ann A" || ann.Username != "ann" || ann.PasswordHash != fakeBcrypt {
		t.Errorf("ann = %+v", ann)
	}
	if string(ann.Metadata) != `{"auth0_app_metadata":{"b":2},"auth0_user_metadata":{"a":1}}` {
		t.Errorf("metadata = %s", ann.Metadata)
	}
	for email, name := range map[string]string{"bob@x.io": "Bob B", "cy@x.io": "cyn", "di@x.io": "di"} {
		if m[email].User.Name != name {
			t.Errorf("%s name = %q, want %q", email, m[email].User.Name, name)
		}
	}
	if m["ed@x.io"].User.PasswordHash != fakeArgon {
		t.Error("custom argon2 hash not used")
	}
	if it := got[4]; it.Code != codeSkipped || it.Row != 5 || !strings.Contains(it.Message, "no email") {
		t.Errorf("no-email row = %+v", it)
	}
	if it := m["flo@x.io"]; it.Code != codeSkipped || strings.Contains(it.Message, "abcd") {
		t.Errorf("md5 row = %+v", it)
	}

	// Without --metadata none is kept; with --passwordless-unsupported the md5 row imports.
	got, _ = convertImport([]byte(in), importOptions{From: "auth0", PasswordlessUnsupported: true})
	m = byEmail(got)
	if len(m["ann@x.io"].User.Metadata) != 0 {
		t.Error("metadata kept without --metadata")
	}
	if it := m["flo@x.io"]; it.Code != "" || it.User.PasswordHash != "" {
		t.Errorf("passwordless row = %+v", it)
	}
}

func TestConvertFirebase(t *testing.T) {
	export := `{"users":[
	 {"localId":"u1","email":"ann@x.io","emailVerified":true,"displayName":"Ann","passwordHash":"aGFzaA==","salt":"c2FsdA=="},
	 {"localId":"u2","email":"bob@x.io","passwordHash":"aGFz-A","salt":"c2FsdA"},
	 {"localId":"u3","email":"cy@x.io"},
	 {"localId":"u4","displayName":"No Mail"},
	 {"localId":"u5","email":"di@x.io","passwordHash":"!!!","salt":"c2FsdA=="}
	]}`
	o := importOptions{From: "firebase", HashKey: "a2V5", SaltSeparator: "c2VwCg", Rounds: "8", MemCost: "14"}
	got, err := convertImport([]byte(export), o)
	if err != nil || len(got) != 5 {
		t.Fatalf("got %d, %v", len(got), err)
	}
	ann := got[0].User
	if want := "$firebase-scrypt$m=14,r=8$c2FsdA==$aGFzaA==$c2VwCg==$a2V5"; ann.PasswordHash != want {
		t.Errorf("hash = %q, want %q", ann.PasswordHash, want)
	}
	if ann.ExternalID != "u1" || !ann.EmailVerified || ann.Name != "Ann" {
		t.Errorf("ann = %+v", ann)
	}
	// URL-safe unpadded input is normalised to std padded.
	if want := "$firebase-scrypt$m=14,r=8$c2FsdA==$aGFz+A==$c2VwCg==$a2V5"; got[1].User.PasswordHash != want {
		t.Errorf("urlsafe hash = %q, want %q", got[1].User.PasswordHash, want)
	}
	if got[2].User.PasswordHash != "" || got[2].User.Name != "cy" || got[2].Code != "" {
		t.Errorf("passwordless = %+v", got[2])
	}
	if got[3].Code != codeSkipped {
		t.Errorf("no email = %+v", got[3])
	}
	if got[4].Code != codeInvalid {
		t.Errorf("bad base64 = %+v", got[4])
	}

	// Parameters are required only when a row has a password.
	if _, err := convertImport([]byte(export), importOptions{From: "firebase"}); err == nil || !strings.Contains(err.Error(), "--hash-key") {
		t.Errorf("missing flags err = %v", err)
	}
	if _, err := convertImport([]byte(`{"users":[{"localId":"u","email":"a@x.io"}]}`), importOptions{From: "firebase"}); err != nil {
		t.Errorf("passwordless export needs no flags: %v", err)
	}
	for _, bad := range []importOptions{
		{HashKey: "a2V5", SaltSeparator: "c2VwCg", Rounds: "8", MemCost: "99"},
		{HashKey: "a2V5", SaltSeparator: "c2VwCg", Rounds: "x", MemCost: "14"},
		{HashKey: "***", SaltSeparator: "c2VwCg", Rounds: "8", MemCost: "14"},
	} {
		bad.From = "firebase"
		if _, err := convertImport([]byte(export), bad); err == nil {
			t.Errorf("params %+v accepted", bad)
		}
	}
}

func TestConvertClerk(t *testing.T) {
	csv := strings.Join([]string{
		`ID,First_Name,Last_Name,Username,Primary_Email_Address,Password_Digest,Password_Hasher,Extra`,
		fmt.Sprintf(`user_1,Ann,A,ann,ann@x.io,%s,bcrypt,x`, fakeBcrypt),
		fmt.Sprintf(`user_2,Bob,,,bob@x.io,"%s",argon2id,x`, fakeArgon),
		fmt.Sprintf(`user_3,,,cy,cy@x.io,%s,pbkdf2_sha256,x`, fakeDjango),
		`user_4,Di,D,,di@x.io,whatever,md5,x`,
		`user_5,No,Mail,,,,,x`,
		`user_6,,,,ed@x.io,,,x`,
	}, "\n")
	got, err := convertImport([]byte(csv), importOptions{From: "clerk"})
	if err != nil || len(got) != 6 {
		t.Fatalf("got %d, %v", len(got), err)
	}
	m := byEmail(got)
	if u := m["ann@x.io"].User; u.PasswordHash != fakeBcrypt || u.Name != "Ann A" || u.ExternalID != "user_1" || u.Username != "ann" {
		t.Errorf("ann = %+v", u)
	}
	if m["bob@x.io"].User.PasswordHash != fakeArgon || m["bob@x.io"].User.Name != "Bob" {
		t.Errorf("bob = %+v", m["bob@x.io"])
	}
	if m["cy@x.io"].User.PasswordHash != fakeDjango || m["cy@x.io"].User.Name != "cy" {
		t.Errorf("cy = %+v", m["cy@x.io"])
	}
	if it := m["di@x.io"]; it.Code != codeSkipped || strings.Contains(it.Message, "whatever") || it.Row != 5 {
		t.Errorf("di = %+v", it)
	}
	if got[4].Code != codeSkipped || got[4].Row != 6 {
		t.Errorf("no email = %+v", got[4])
	}
	if it := m["ed@x.io"]; it.Code != "" || it.User.Name != "ed" || it.User.PasswordHash != "" {
		t.Errorf("ed = %+v", it)
	}
	// A hasher that does not match the digest's shape is not passed through.
	bad := "id,primary_email_address,password_digest,password_hasher\nu,a@x.io,$2a$10$xx,argon2id\n"
	got, _ = convertImport([]byte(bad), importOptions{From: "clerk"})
	if got[0].Code != codeSkipped {
		t.Errorf("mismatched hasher = %+v", got[0])
	}
	got, _ = convertImport([]byte(bad), importOptions{From: "clerk", PasswordlessUnsupported: true})
	if got[0].Code != "" || got[0].User.PasswordHash != "" {
		t.Errorf("passwordless = %+v", got[0])
	}
	if _, err := convertImport([]byte("id,email\n1,a@x.io\n"), importOptions{From: "clerk"}); err == nil {
		t.Error("CSV without primary_email_address accepted")
	}
}

func TestConvertCognito(t *testing.T) {
	in := `{"Users":[
	 {"Username":"ann","Attributes":[{"Name":"sub","Value":"sub-1"},{"Name":"email","Value":"ann@x.io"},{"Name":"email_verified","Value":"true"},{"Name":"name","Value":"Ann A"}]},
	 {"Username":"bob","Attributes":[{"Name":"email","Value":"bob@x.io"},{"Name":"email_verified","Value":"false"},{"Name":"given_name","Value":"Bob"},{"Name":"family_name","Value":"B"}]},
	 {"Username":"cy","Attributes":[{"Name":"phone_number","Value":"+1"}]},
	 {"Username":"di","Attributes":[{"Name":"email","Value":"di@x.io"}]}
	]}`
	got, err := convertImport([]byte(in), importOptions{From: "cognito"})
	if err != nil || len(got) != 4 {
		t.Fatalf("got %d, %v", len(got), err)
	}
	if u := got[0].User; u.ExternalID != "sub-1" || !u.EmailVerified || u.Name != "Ann A" {
		t.Errorf("ann = %+v", u)
	}
	if u := got[1].User; u.ExternalID != "bob" || u.EmailVerified || u.Name != "Bob B" {
		t.Errorf("bob = %+v", u)
	}
	if got[2].Code != codeSkipped || got[2].Row != 3 {
		t.Errorf("cy = %+v", got[2])
	}
	if got[3].User.Name != "di" {
		t.Errorf("di = %+v", got[3].User)
	}
	for _, u := range got {
		if u.User.PasswordHash != "" {
			t.Error("cognito rows carry no hash")
		}
	}
	if _, err := convertImport([]byte(`[1]`), importOptions{From: "cognito"}); err == nil {
		t.Error("non-export accepted")
	}
	if _, err := convertImport([]byte(`{}`), importOptions{From: "nope"}); err == nil {
		t.Error("unknown source accepted")
	}
}

func TestSplitBatches(t *testing.T) {
	mk := func(n int, pad int) []importItem {
		var items []importItem
		for i := 1; i <= n; i++ {
			items = append(items, importItem{Row: i, User: importUser{
				Email: fmt.Sprintf("u%d@x.io", i), Name: strings.Repeat("n", pad),
			}})
		}
		return items
	}
	t.Run("by count", func(t *testing.T) {
		b, big := splitBatches(mk(250, 5), importBatchRows, importBatchBytes)
		if len(big) != 0 || len(b) != 3 || len(b[0].items) != 100 || len(b[1].items) != 100 || len(b[2].items) != 50 {
			t.Fatalf("batches = %d, big = %d", len(b), len(big))
		}
	})
	t.Run("by size", func(t *testing.T) {
		b, big := splitBatches(mk(50, 2000), importBatchRows, importBatchBytes)
		if len(big) != 0 || len(b) < 2 {
			t.Fatalf("batches = %d", len(b))
		}
		total := 0
		for _, x := range b {
			if len(x.payload()) > importBatchBytes {
				t.Errorf("payload %d bytes", len(x.payload()))
			}
			var v struct{ Users []json.RawMessage }
			if err := json.Unmarshal(x.payload(), &v); err != nil || len(v.Users) != len(x.items) {
				t.Errorf("payload does not parse: %v", err)
			}
			total += len(x.items)
		}
		if total != 50 {
			t.Errorf("rows = %d", total)
		}
	})
	t.Run("row too large", func(t *testing.T) {
		items := mk(3, 5)
		items[1].User.Name = strings.Repeat("n", importBatchBytes)
		b, big := splitBatches(items, importBatchRows, importBatchBytes)
		if len(big) != 1 || big[0].Row != 2 || len(b) != 1 || len(b[0].items) != 2 {
			t.Fatalf("batches = %d, big = %v", len(b), big)
		}
	})
}

// fakeServer answers /management/v1/environments/env/users/import. Rows whose
// email starts with "dup" conflict, those starting with "bad" fail.
func fakeServer(t *testing.T, requests *[][]importUser, pre func(n int, w http.ResponseWriter) bool) (*client, func()) {
	t.Helper()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/management/v1/environments/env/users/import" || r.Method != "POST" || r.Header.Get("X-API-Key") != "k" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		call := int(atomic.AddInt32(&n, 1))
		if pre != nil && pre(call, w) {
			return
		}
		var body struct{ Users []importUser }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("bad body: %v", err)
		}
		*requests = append(*requests, body.Users)
		var results []string
		for i, u := range body.Users {
			switch {
			case strings.HasPrefix(u.Email, "dup"):
				results = append(results, fmt.Sprintf(`{"index":%d,"error":{"code":"CONFLICT","message":"email is taken: %s"}}`, i, u.PasswordHash))
			case strings.HasPrefix(u.Email, "bad"):
				results = append(results, fmt.Sprintf(`{"index":%d,"error":{"code":"VALIDATION","message":"name is bad"}}`, i))
			default:
				results = append(results, fmt.Sprintf(`{"index":%d,"id":"00000000-0000-0000-0000-000000000001"}`, i))
			}
		}
		fmt.Fprintf(w, `{"results":[%s]}`, strings.Join(results, ","))
	}))
	return &client{base: srv.URL + "/management/v1", key: "k", http: srv.Client()}, srv.Close
}

func jsonl(users ...importUser) []byte {
	var b bytes.Buffer
	for _, u := range users {
		json.NewEncoder(&b).Encode(u)
	}
	return b.Bytes()
}

func TestImportEndToEnd(t *testing.T) {
	var reqs [][]importUser
	c, done := fakeServer(t, &reqs, nil)
	defer done()

	data := jsonl(
		importUser{Email: "a@x.io", Name: "A", PasswordHash: fakeBcrypt},
		importUser{Email: "dup@x.io", Name: "D", ExternalID: "ext-d", PasswordHash: fakeBcrypt},
		importUser{Email: "bad@x.io", Name: "B", ExternalID: "ext-b", PasswordHash: fakeBcrypt},
		importUser{Email: "", Name: "No email"},
		importUser{Email: "h@x.io", Name: "H", PasswordHash: "md5$abc"},
	)
	cases := []struct {
		name         string
		skipExisting bool
		want         string
		wantCodes    []string
	}{
		{"conflict fails", false, "created 1, skipped 0, failed 4", []string{"CONFLICT", "VALIDATION", "INVALID", "INVALID"}},
		{"skip existing", true, "created 1, skipped 1, failed 3", []string{"CONFLICT", "VALIDATION", "INVALID", "INVALID"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqs = nil
			errFile := filepath.Join(t.TempDir(), "errors.jsonl")
			var out, errOut bytes.Buffer
			sum, err := runImport(c, "/environments/env", data, importOptions{
				SkipExisting: tc.skipExisting, ErrorsFile: errFile, HomeOrg: "11111111-1111-1111-1111-111111111111",
				Out: &out, Err: &errOut,
			})
			if err == nil {
				t.Fatal("expected a non-nil error (rows failed)")
			}
			if strings.TrimSpace(out.String()) != tc.want {
				t.Errorf("summary = %q, want %q", out.String(), tc.want)
			}
			if len(reqs) != 1 || len(reqs[0]) != 3 {
				t.Fatalf("requests = %v", reqs)
			}
			for _, u := range reqs[0] {
				if u.HomeOrg != "11111111-1111-1111-1111-111111111111" {
					t.Errorf("home org = %q", u.HomeOrg)
				}
			}
			if sum.Created != 1 {
				t.Errorf("created = %d", sum.Created)
			}

			raw, _ := os.ReadFile(errFile)
			if strings.Contains(string(raw), fakeBcrypt) || strings.Contains(out.String()+errOut.String(), fakeBcrypt) || strings.Contains(string(raw), "md5$abc") {
				t.Fatal("a password hash leaked into the output")
			}
			var lines []importIssue
			for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				var is importIssue
				if err := json.Unmarshal([]byte(l), &is); err != nil {
					t.Fatalf("errors line %q: %v", l, err)
				}
				lines = append(lines, is)
			}
			var codes []string
			for _, l := range lines {
				codes = append(codes, l.Code)
			}
			wantAll := append([]string{}, tc.wantCodes...)
			if tc.skipExisting {
				if len(lines) != 4 {
					t.Fatalf("lines = %v", lines)
				}
			}
			if len(codes) != len(wantAll) {
				t.Fatalf("codes = %v, want %v", codes, wantAll)
			}
			// Sorted by row: 2 dup, 3 bad, 4 no email, 5 bad hash.
			for i, row := range []int{2, 3, 4, 5} {
				if lines[i].Row != row || lines[i].Code != wantAll[i] {
					t.Errorf("line %d = %+v", i, lines[i])
				}
			}
			if lines[0].ExternalID != "ext-d" || lines[0].Email != "dup@x.io" {
				t.Errorf("line 0 = %+v", lines[0])
			}
		})
	}
}

func TestImportExitState(t *testing.T) {
	var reqs [][]importUser
	c, done := fakeServer(t, &reqs, nil)
	defer done()
	var out bytes.Buffer
	// All good → nil error.
	_, err := runImport(c, "/environments/env", jsonl(importUser{Email: "a@x.io", Name: "A"}), importOptions{Out: &out})
	if err != nil || strings.TrimSpace(out.String()) != "created 1, skipped 0, failed 0" {
		t.Fatalf("err = %v, out = %q", err, out.String())
	}
	// Only skipped (existing) rows → still success.
	out.Reset()
	_, err = runImport(c, "/environments/env", jsonl(importUser{Email: "dup@x.io", Name: "A"}), importOptions{SkipExisting: true, Out: &out})
	if err != nil || strings.TrimSpace(out.String()) != "created 0, skipped 1, failed 0" {
		t.Fatalf("err = %v, out = %q", err, out.String())
	}
	// Skipped by the converter (no email) → success; a failure → error.
	out.Reset()
	_, err = runImport(c, "/environments/env", []byte(`{"user_id":"1","name":"x"}`+"\n"), importOptions{From: "auth0", Out: &out})
	if err != nil || !strings.HasPrefix(out.String(), "created 0, skipped 1") {
		t.Fatalf("err = %v, out = %q", err, out.String())
	}
	_, err = runImport(c, "/environments/env", jsonl(importUser{Email: "bad@x.io", Name: "A"}), importOptions{Out: &out})
	if err == nil {
		t.Fatal("failed row must give an error")
	}
	if _, err = runImport(c, "/environments/env", jsonl(importUser{Email: "a@x.io", Name: "A"}), importOptions{HomeOrg: "nope"}); err == nil {
		t.Fatal("bad --home-organization accepted")
	}
}

func TestImportBatchesRequests(t *testing.T) {
	var reqs [][]importUser
	c, done := fakeServer(t, &reqs, nil)
	defer done()
	var users []importUser
	for i := 0; i < 230; i++ {
		users = append(users, importUser{Email: fmt.Sprintf("u%d@x.io", i), Name: "U"})
	}
	var out bytes.Buffer
	if _, err := runImport(c, "/environments/env", jsonl(users...), importOptions{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 3 || len(reqs[0]) != 100 || len(reqs[2]) != 30 {
		t.Fatalf("requests = %d", len(reqs))
	}
	if !strings.HasPrefix(out.String(), "created 230,") {
		t.Errorf("out = %q", out.String())
	}
}

func TestImportRetries(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		retryAfter string
		failures   int // answers before success
		wantSleeps []time.Duration
		wantFailed int
	}{
		{"429 Retry-After", 429, "3", 2, []time.Duration{3 * time.Second, 3 * time.Second}, 0},
		{"503 backoff", 503, "", 3, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}, 0},
		{"gives up after 5 tries", 429, "", 99, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reqs [][]importUser
			var calls int32
			c, done := fakeServer(t, &reqs, func(n int, w http.ResponseWriter) bool {
				atomic.StoreInt32(&calls, int32(n))
				if n > tc.failures {
					return false
				}
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, `{"error":{"code":"RATE_LIMITED","message":"slow down"}}`)
				return true
			})
			defer done()
			var sleeps []time.Duration
			var out bytes.Buffer
			sum, err := runImport(c, "/environments/env", jsonl(importUser{Email: "a@x.io", Name: "A"}), importOptions{
				Out: &out, Sleep: func(d time.Duration) { sleeps = append(sleeps, d) },
			})
			if fmt.Sprint(sleeps) != fmt.Sprint(tc.wantSleeps) {
				t.Errorf("sleeps = %v, want %v", sleeps, tc.wantSleeps)
			}
			if sum.Failed != tc.wantFailed || (err != nil) != (tc.wantFailed > 0) {
				t.Errorf("summary = %+v, err = %v", sum, err)
			}
			if tc.wantFailed == 0 && sum.Created != 1 {
				t.Errorf("created = %d", sum.Created)
			}
			if tc.wantFailed > 0 && atomic.LoadInt32(&calls) != 5 {
				t.Errorf("calls = %d, want 5", calls)
			}
		})
	}
}

func TestImportStopsOnAuthFailure(t *testing.T) {
	var reqs [][]importUser
	var calls int32
	c, done := fakeServer(t, &reqs, func(n int, w http.ResponseWriter) bool {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"code":"UNAUTHORIZED","message":"invalid key"}}`)
		return true
	})
	defer done()
	var users []importUser
	for i := 0; i < 150; i++ {
		users = append(users, importUser{Email: fmt.Sprintf("u%d@x.io", i), Name: "U"})
	}
	var out bytes.Buffer
	sum, err := runImport(c, "/environments/env", jsonl(users...), importOptions{Out: &out})
	if err == nil || sum.Failed != 150 || calls != 1 {
		t.Fatalf("sum = %+v, err = %v, calls = %d", sum, err, calls)
	}
}

func TestImportDryRunMakesNoRequest(t *testing.T) {
	var hit int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&hit, 1) }))
	defer srv.Close()
	c := &client{base: srv.URL, key: "k", http: srv.Client()}

	data := jsonl(
		importUser{Email: "a@x.io", Name: "A", PasswordHash: fakeBcrypt},
		importUser{Email: "b@x.io", Name: ""},
		importUser{Email: "c@x.io", Name: "C", PasswordHash: "md5$abc"},
	)
	var out, errOut bytes.Buffer
	sum, err := runImport(c, "/environments/env", data, importOptions{DryRun: true, Out: &out, Err: &errOut})
	if hit != 0 {
		t.Fatalf("dry run made %d requests", hit)
	}
	if err == nil || sum.Created != 1 || sum.Failed != 2 {
		t.Fatalf("sum = %+v, err = %v", sum, err)
	}
	if !strings.Contains(out.String(), "dry run: would create 1, skipped 0, failed 2") {
		t.Errorf("out = %q", out.String())
	}
	if strings.Contains(out.String()+errOut.String(), "md5$abc") || strings.Contains(out.String()+errOut.String(), fakeBcrypt) {
		t.Error("hash printed")
	}
	// The command also works without credentials when --dry-run.
	cmd := usersImportCmd()
	file := filepath.Join(t.TempDir(), "u.jsonl")
	os.WriteFile(file, jsonl(importUser{Email: "a@x.io", Name: "A"}), 0o600)
	var cout bytes.Buffer
	cmd.SetOut(&cout)
	cmd.SetArgs([]string{file, "--dry-run"})
	if err := cmd.Execute(); err != nil || !strings.Contains(cout.String(), "would create 1") {
		t.Fatalf("command: %v %q", err, cout.String())
	}
}

func TestRetryDelay(t *testing.T) {
	for _, c := range []struct {
		header  string
		attempt int
		want    time.Duration
	}{
		{"7", 1, 7 * time.Second}, {"0", 3, 0}, {"", 1, time.Second}, {"", 4, 8 * time.Second},
		{"soon", 2, 2 * time.Second}, {"Wed, 21 Oct 2015 07:28:00 GMT", 2, 0}, {"99999", 1, importMaxWait},
		{time.Now().Add(time.Hour).UTC().Format(http.TimeFormat), 1, importMaxWait},
	} {
		if got := retryDelay(c.header, c.attempt); got != c.want {
			t.Errorf("retryDelay(%q, %d) = %v, want %v", c.header, c.attempt, got, c.want)
		}
	}
}
