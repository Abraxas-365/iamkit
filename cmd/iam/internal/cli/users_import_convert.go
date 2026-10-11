package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// convertImport turns an export into import rows. Row numbers are positions in
// the input: the line for JSON Lines and CSV, the 1-based index for JSON arrays
// and the Firebase/Cognito lists. A returned error means the whole input is
// unusable; a bad row is an importItem with a Code.
func convertImport(data []byte, o importOptions) ([]importItem, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	switch o.From {
	case "", "iamkit":
		return convertIAMKit(data)
	case "auth0":
		return convertAuth0(data, o)
	case "firebase":
		return convertFirebase(data, o)
	case "clerk":
		return convertClerk(data, o)
	case "cognito":
		return convertCognito(data)
	}
	return nil, fmt.Errorf("unknown --from %q (iamkit, auth0, firebase, clerk, cognito)", o.From)
}

// localPart is the part of an email before the @.
func localPart(email string) string {
	if i := strings.Index(email, "@"); i > 0 {
		return email[:i]
	}
	return email
}

func joinName(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

// lines calls fn for each non-blank line with its 1-based line number.
func lines(data []byte, fn func(n int, line []byte)) {
	for i, line := range bytes.Split(data, []byte("\n")) {
		if line = bytes.TrimSpace(line); len(line) > 0 {
			fn(i+1, line)
		}
	}
}

// peek extracts email and external_id from a row that could not be decoded, so
// the errors file can still name it. Only those two string fields are read.
func peek(raw []byte) importUser {
	var m map[string]json.RawMessage
	var u importUser
	if json.Unmarshal(raw, &m) != nil {
		return u
	}
	for key, dst := range map[string]*string{"email": &u.Email, "external_id": &u.ExternalID, "user_id": &u.ExternalID, "localId": &u.ExternalID} {
		if v, ok := m[key]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil {
				*dst = s
			}
		}
	}
	return u
}

// ---- iamkit ----

func convertIAMKit(data []byte) ([]importItem, error) {
	var raws []struct {
		row int
		raw []byte
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("input is not a JSON array of users: %w", err)
		}
		for i, r := range arr {
			raws = append(raws, struct {
				row int
				raw []byte
			}{i + 1, r})
		}
	} else {
		lines(data, func(n int, line []byte) {
			raws = append(raws, struct {
				row int
				raw []byte
			}{n, line})
		})
	}
	var items []importItem
	for _, r := range raws {
		var u importUser
		dec := json.NewDecoder(bytes.NewReader(r.raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&u); err != nil {
			items = append(items, invalid(r.row, peek(r.raw), "not a valid user: %s", jsonProblem(err)))
			continue
		}
		if len(u.Metadata) > 0 && !bytes.HasPrefix(bytes.TrimSpace(u.Metadata), []byte("{")) && string(bytes.TrimSpace(u.Metadata)) != "null" {
			items = append(items, invalid(r.row, u, "metadata must be an object"))
			continue
		}
		if string(bytes.TrimSpace(u.Metadata)) == "null" {
			u.Metadata = nil
		}
		items = append(items, importItem{Row: r.row, User: u})
	}
	if len(items) == 0 {
		return nil, errors.New("the input has no users")
	}
	return items, nil
}

// jsonProblem describes a decode error without echoing input values.
func jsonProblem(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return "invalid JSON"
	case errors.As(err, &typ):
		return "field " + typ.Field + " has the wrong type"
	}
	return strings.TrimPrefix(err.Error(), "json: ")
}

// ---- auth0 ----

type auth0Row struct {
	UserID       string          `json:"user_id"`
	Email        string          `json:"email"`
	Verified     bool            `json:"email_verified"`
	Name         string          `json:"name"`
	GivenName    string          `json:"given_name"`
	FamilyName   string          `json:"family_name"`
	Nickname     string          `json:"nickname"`
	Username     string          `json:"username"`
	PasswordHash string          `json:"passwordHash"`
	Custom       *auth0Custom    `json:"custom_password_hash"`
	UserMeta     json.RawMessage `json:"user_metadata"`
	AppMeta      json.RawMessage `json:"app_metadata"`
}

type auth0Custom struct {
	Algorithm string `json:"algorithm"`
	Hash      struct {
		Value string `json:"value"`
	} `json:"hash"`
}

func convertAuth0(data []byte, o importOptions) ([]importItem, error) {
	var items []importItem
	lines(data, func(n int, line []byte) {
		var r auth0Row
		if err := json.Unmarshal(line, &r); err != nil {
			items = append(items, invalid(n, peek(line), "not a valid Auth0 user: %s", jsonProblem(err)))
			return
		}
		u := importUser{
			Email: strings.TrimSpace(r.Email), EmailVerified: r.Verified,
			ExternalID: r.UserID, Username: r.Username,
		}
		if u.Email == "" {
			items = append(items, skipped(n, u, "the user has no email"))
			return
		}
		u.Name = joinName(r.Name)
		if u.Name == "" {
			u.Name = joinName(r.GivenName, r.FamilyName)
		}
		if u.Name == "" {
			u.Name = joinName(r.Nickname)
		}
		if u.Name == "" {
			u.Name = localPart(u.Email)
		}
		if o.Metadata {
			meta := map[string]json.RawMessage{}
			if isObject(r.UserMeta) {
				meta["auth0_user_metadata"] = r.UserMeta
			}
			if isObject(r.AppMeta) {
				meta["auth0_app_metadata"] = r.AppMeta
			}
			if len(meta) > 0 {
				u.Metadata, _ = json.Marshal(meta)
			}
		}
		hash := strings.TrimSpace(r.PasswordHash)
		if hash == "" && r.Custom != nil {
			hash = strings.TrimSpace(r.Custom.Hash.Value)
		}
		if hash != "" {
			if hashRecognised(hash) {
				u.PasswordHash = hash
			} else if !o.PasswordlessUnsupported {
				items = append(items, skipped(n, u, "password hash format is not supported (use --passwordless-unsupported to import the user without a password)"))
				return
			}
		}
		items = append(items, importItem{Row: n, User: u})
	})
	if len(items) == 0 {
		return nil, errors.New("the input has no users")
	}
	return items, nil
}

func isObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 2 && t[0] == '{' // not empty, not {}
}

// ---- firebase ----

type firebaseRow struct {
	LocalID      string `json:"localId"`
	Email        string `json:"email"`
	Verified     bool   `json:"emailVerified"`
	DisplayName  string `json:"displayName"`
	PasswordHash string `json:"passwordHash"`
	Salt         string `json:"salt"`
}

// stdBase64 decodes std or URL-safe base64, padded or not, and re-encodes it
// as padded std base64.
func stdBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return base64.StdEncoding.EncodeToString(b), true
		}
	}
	return "", false
}

// firebaseParams holds the validated, normalised project parameters.
type firebaseParams struct{ mem, rounds, saltSep, key string }

func firebaseProject(o importOptions) (firebaseParams, error) {
	var p firebaseParams
	var missing []string
	for _, f := range []struct{ name, val string }{
		{"--hash-key", o.HashKey}, {"--salt-separator", o.SaltSeparator},
		{"--rounds", o.Rounds}, {"--mem-cost", o.MemCost},
	} {
		if strings.TrimSpace(f.val) == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return p, fmt.Errorf("--from firebase needs %s (Firebase console › Authentication › Users › Password hash parameters) because users have passwords", strings.Join(missing, ", "))
	}
	mem, err := strconv.Atoi(strings.TrimSpace(o.MemCost))
	if err != nil || mem < 1 || mem > 15 {
		return p, errors.New("--mem-cost must be a number from 1 to 15")
	}
	rounds, err := strconv.Atoi(strings.TrimSpace(o.Rounds))
	if err != nil || rounds < 1 || rounds > 16 {
		return p, errors.New("--rounds must be a number from 1 to 16")
	}
	var ok bool
	if p.saltSep, ok = stdBase64(o.SaltSeparator); !ok {
		return p, errors.New("--salt-separator is not valid base64")
	}
	if p.key, ok = stdBase64(o.HashKey); !ok {
		return p, errors.New("--hash-key is not valid base64")
	}
	p.mem, p.rounds = strconv.Itoa(mem), strconv.Itoa(rounds)
	return p, nil
}

func convertFirebase(data []byte, o importOptions) ([]importItem, error) {
	var doc struct {
		Users []json.RawMessage `json:"users"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("input is not a Firebase export ({\"users\":[…]}): %w", err)
	}
	if len(doc.Users) == 0 {
		return nil, errors.New("the input has no users")
	}
	rows := make([]firebaseRow, len(doc.Users))
	bad := make([]error, len(doc.Users))
	needParams := false
	for i, raw := range doc.Users {
		bad[i] = json.Unmarshal(raw, &rows[i])
		if bad[i] == nil && strings.TrimSpace(rows[i].PasswordHash) != "" && strings.TrimSpace(rows[i].Email) != "" {
			needParams = true
		}
	}
	var params firebaseParams
	if needParams {
		var err error
		if params, err = firebaseProject(o); err != nil {
			return nil, err
		}
	}
	var items []importItem
	for i, r := range rows {
		n := i + 1
		if bad[i] != nil {
			items = append(items, invalid(n, peek(doc.Users[i]), "not a valid Firebase user: %s", jsonProblem(bad[i])))
			continue
		}
		u := importUser{
			Email: strings.TrimSpace(r.Email), EmailVerified: r.Verified,
			ExternalID: r.LocalID, Name: joinName(r.DisplayName),
		}
		if u.Email == "" {
			items = append(items, skipped(n, u, "the user has no email"))
			continue
		}
		if u.Name == "" {
			u.Name = localPart(u.Email)
		}
		if strings.TrimSpace(r.PasswordHash) != "" {
			hash, ok1 := stdBase64(r.PasswordHash)
			salt, ok2 := stdBase64(r.Salt)
			if !ok1 || !ok2 {
				items = append(items, invalid(n, u, "passwordHash or salt is missing or not valid base64"))
				continue
			}
			u.PasswordHash = fmt.Sprintf("$firebase-scrypt$m=%s,r=%s$%s$%s$%s$%s",
				params.mem, params.rounds, salt, hash, params.saltSep, params.key)
		}
		items = append(items, importItem{Row: n, User: u})
	}
	return items, nil
}

// ---- clerk ----

func convertClerk(data []byte, o importOptions) ([]importItem, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the input has no users")
		}
		return nil, fmt.Errorf("reading CSV header: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		if _, dup := col[h]; !dup {
			col[h] = i
		}
	}
	if _, ok := col["primary_email_address"]; !ok {
		return nil, errors.New("the CSV has no primary_email_address column (is it a Clerk export?)")
	}
	var items []importItem
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line, _ := r.FieldPos(0)
		if err != nil {
			items = append(items, invalid(line, importUser{}, "unreadable CSV record: %v", err))
			if line == 0 {
				break
			}
			continue
		}
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue
		}
		u := importUser{
			Email: get("primary_email_address"), ExternalID: get("id"), Username: get("username"),
		}
		if u.Email == "" {
			items = append(items, skipped(line, u, "the user has no primary email"))
			continue
		}
		if v := get("verified_email_addresses"); v != "" {
			for _, e := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
				if strings.EqualFold(e, u.Email) {
					u.EmailVerified = true
				}
			}
		}
		u.Name = joinName(get("first_name"), get("last_name"))
		if u.Name == "" {
			u.Name = get("username")
		}
		if u.Name == "" {
			u.Name = localPart(u.Email)
		}
		digest, hasher := get("password_digest"), strings.ToLower(get("password_hasher"))
		if digest != "" {
			if clerkHashOK(hasher, digest) {
				u.PasswordHash = digest
			} else if !o.PasswordlessUnsupported {
				items = append(items, skipped(line, u, "password hasher %q is not supported (use --passwordless-unsupported to import the user without a password)", hasher))
				continue
			}
		}
		items = append(items, importItem{Row: line, User: u})
	}
	if len(items) == 0 {
		return nil, errors.New("the input has no users")
	}
	return items, nil
}

// clerkHashOK reports whether Clerk's digest is already in a format IAMKit
// stores as it is.
func clerkHashOK(hasher, digest string) bool {
	switch hasher {
	case "bcrypt":
		return strings.HasPrefix(digest, "$2a$") || strings.HasPrefix(digest, "$2b$") || strings.HasPrefix(digest, "$2y$")
	case "argon2id":
		return strings.HasPrefix(digest, "$argon2id$")
	case "argon2i":
		return strings.HasPrefix(digest, "$argon2i$")
	case "pbkdf2_sha256", "pbkdf2_sha256_django":
		return strings.HasPrefix(digest, "pbkdf2_sha256$")
	}
	return false
}

// ---- cognito ----

func convertCognito(data []byte) ([]importItem, error) {
	type attr struct{ Name, Value string }
	type cogUser struct {
		Username   string
		Attributes []attr
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var users []json.RawMessage
	found := false
	for {
		var doc struct {
			Users []json.RawMessage `json:"Users"`
		}
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("input is not a Cognito list-users export: %w", err)
		}
		if doc.Users != nil {
			found = true
		}
		users = append(users, doc.Users...) // paginated output is several documents
	}
	if !found {
		return nil, errors.New("input is not a Cognito list-users export ({\"Users\":[…]})")
	}
	if len(users) == 0 {
		return nil, errors.New("the input has no users")
	}
	var items []importItem
	for i, raw := range users {
		n := i + 1
		var cu cogUser
		if err := json.Unmarshal(raw, &cu); err != nil {
			items = append(items, invalid(n, importUser{}, "not a valid Cognito user: %s", jsonProblem(err)))
			continue
		}
		at := map[string]string{}
		for _, a := range cu.Attributes {
			at[a.Name] = a.Value
		}
		u := importUser{
			Email:         strings.TrimSpace(at["email"]),
			EmailVerified: strings.EqualFold(at["email_verified"], "true"),
			ExternalID:    at["sub"],
		}
		if u.ExternalID == "" {
			u.ExternalID = cu.Username
		}
		if u.Email == "" {
			items = append(items, skipped(n, u, "the user has no email"))
			continue
		}
		u.Name = joinName(at["name"])
		if u.Name == "" {
			u.Name = joinName(at["given_name"], at["family_name"])
		}
		if u.Name == "" {
			u.Name = localPart(u.Email)
		}
		items = append(items, importItem{Row: n, User: u})
	}
	return items, nil
}
