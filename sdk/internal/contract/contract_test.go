package contract_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/apiclient"
	"github.com/Abraxas-365/iamkit/sdk/authclient"
	"github.com/Abraxas-365/iamkit/sdk/iamclient"
	"github.com/Abraxas-365/iamkit/sdk/scimclient"
)

// The SDK contract check: every exported client method is called against a
// server simulated from api/openapi.json. A call fails the test when its
// route is not documented, when its query parameters or JSON body name
// fields the operation does not accept, when the simulated response does
// not decode, or when a field of the returned type is not in the response
// schema. The document is generated from the server's handlers and the e2e
// suite validates the server against it, so SDK ↔ document is SDK ↔ server.

// skipped are methods the simulation cannot exercise, with the reason.
var skipped = map[string]string{
	"iamclient.Client.Do":   "low-level call with a caller-supplied path",
	"apiclient.Client.Do":   "low-level call with a caller-supplied path",
	"authclient.KeySet.Key": "needs real RSA keys in the JWKS; covered by keyset_test.go",
}

// clientChecked are methods whose result is checked on the client after a
// documented exchange (token boundaries, signatures): an error there is
// expected from simulated data.
var clientChecked = map[string]bool{
	"authclient.Client.Introspect": true,
}

// Field rules. Input and result types are shared between endpoints (one
// TokenPair for every token answer, one User for lists and reads), so a
// field tagged omitempty may be absent from one operation's schema. A
// field without omitempty is always sent or always expected: one the
// operation does not document is a bug (sent and ignored, or never
// filled).

func TestSDKMatchesOpenAPI(t *testing.T) {
	spec := loadSpec(t)
	params := paramNames(t, "apiclient", "authclient", "iamclient", "scimclient")
	sim := &simulator{spec: spec, used: map[string]bool{}}
	server := httptest.NewServer(sim)
	defer server.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyLogin, err := authclient.NewKeyLogin(server.URL, uuid, "kid", key)
	if err != nil {
		t.Fatal(err)
	}
	management := iamclient.New(server.URL, "ik_mgmt_test")
	api := apiclient.New(server.URL, "token")
	receivers := []struct {
		name  string
		value any
	}{
		{"iamclient.Client", management},
		{"iamclient.Environment", management.Environment(uuid)},
		{"apiclient.Client", api},
		{"apiclient.Environment", api.Environment(uuid)},
		{"apiclient.OrgAdmin", api.Environment(uuid).OrgAdmin(uuid)},
		{"authclient.Client", authclient.New(server.URL)},
		{"authclient.OAuthClient", authclient.NewOAuth(server.URL, "client", "secret")},
		{"authclient.KeyLogin", keyLogin},
		{"scimclient.Client", scimclient.New(server.URL, "ik_scim_test")},
	}

	called := 0
	for _, receiver := range receivers {
		value := reflect.ValueOf(receiver.value)
		for i := 0; i < value.NumMethod(); i++ {
			method := value.Type().Method(i)
			name := receiver.name + "." + method.Name
			fn := value.Method(i)
			if fn.Type().NumIn() == 0 || fn.Type().In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
				continue // pure helpers (HasPermission, EndSessionURL, …)
			}
			if reason, ok := skipped[name]; ok {
				t.Logf("skip %s: %s", name, reason)
				continue
			}
			called++
			t.Run(name, func(t *testing.T) {
				sim.begin(optionalFields(fn.Type()))
				out, err := invoke(fn, params[name])
				exchanges := sim.end()
				if len(exchanges) == 0 {
					t.Fatalf("no request reached the server (client-side error: %v)", err)
				}
				for _, ex := range exchanges {
					for _, issue := range ex.issues {
						t.Errorf("%s %s: %s", ex.method, ex.path, issue)
					}
				}
				last := exchanges[len(exchanges)-1]
				if err != nil && !clientChecked[name] {
					t.Errorf("%s %s: answered %d from the document, method failed: %v", last.method, last.path, last.status, err)
				}
				if out.IsValid() && last.schema != nil && !clientChecked[name] {
					// Any documented 2xx body may come back (201 or 202).
					var best []string
					for i, schema := range last.schemas {
						issues := sim.spec.fields(out.Type(), schema, "")
						if i == 0 || len(issues) < len(best) {
							best = issues
						}
					}
					for _, issue := range best {
						t.Errorf("%s %s: result %s", last.method, last.path, issue)
					}
					if missing := sim.spec.unexposed(out.Type(), last.schema); len(missing) > 0 {
						sim.note(fmt.Sprintf("%s (%s %s): %s", name, last.method, last.template, strings.Join(missing, ", ")))
					}
				}
			})
		}
	}
	if called < 300 {
		t.Fatalf("only %d methods exercised; did the clients move?", called)
	}
	if os.Getenv("SDK_CONTRACT_COVERAGE") != "" {
		sim.report(t)
	}
}

// ── Invocation ──

const uuid = "4f2d8a1e-0c3b-4a5e-9f61-7b8c9d0e1f2a"

// stringArg picks a valid value for a string parameter by its name.
func stringArg(name string) string {
	switch name {
	case "condition":
		return "function:pre_sign_in"
	case "locale":
		return "en"
	case "collection":
		return "users"
	case "kind":
		return "email"
	case "state":
		return "active"
	case "status":
		return "failed"
	case "secret":
		return "ik_svc_test"
	case "token":
		return "ik_pat_test"
	case "email":
		return "ada@example.com"
	case "phone":
		return "+15555550100"
	case "filter":
		return `userName eq "ada@example.com"`
	case "expiresIn":
		return "1h"
	case "issuer", "audience":
		return "https://api.example.com"
	}
	return uuid
}

func invoke(fn reflect.Value, names []string) (reflect.Value, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	kind := fn.Type()
	args := []reflect.Value{reflect.ValueOf(ctx)}
	for i := 1; i < kind.NumIn(); i++ {
		arg := kind.In(i)
		if kind.IsVariadic() && i == kind.NumIn()-1 {
			value := reflect.MakeSlice(arg, 1, 1)
			fill(value.Index(0), "")
			args = append(args, value)
			continue
		}
		value := reflect.New(arg).Elem()
		name := ""
		if i < len(names) {
			name = names[i]
		}
		fill(value, name)
		args = append(args, value)
	}
	var results []reflect.Value
	if kind.IsVariadic() {
		results = fn.CallSlice(args)
	} else {
		results = fn.Call(args)
	}
	var err error
	if last := results[len(results)-1]; !last.IsNil() {
		err = last.Interface().(error)
	}
	if len(results) == 2 {
		return results[0], err
	}
	return reflect.Value{}, err
}

var (
	timeType = reflect.TypeOf(time.Time{})
	rawType  = reflect.TypeOf(json.RawMessage{})
)

// fill sets every field of value so the body names every field the SDK
// can send.
func fill(value reflect.Value, name string) {
	switch value.Kind() {
	case reflect.String:
		value.SetString(stringArg(name))
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value.SetUint(1)
	case reflect.Float32, reflect.Float64:
		value.SetFloat(1)
	case reflect.Pointer:
		elem := reflect.New(value.Type().Elem())
		fill(elem.Elem(), name)
		value.Set(elem)
	case reflect.Slice:
		if value.Type() == rawType {
			value.SetBytes([]byte(`{}`))
			return
		}
		slice := reflect.MakeSlice(value.Type(), 1, 1)
		fill(slice.Index(0), name)
		value.Set(slice)
	case reflect.Map:
		m := reflect.MakeMap(value.Type())
		k := reflect.New(value.Type().Key()).Elem()
		fill(k, "key")
		if k.Kind() == reflect.String {
			k.SetString("key")
		}
		v := reflect.New(value.Type().Elem()).Elem()
		if v.Kind() == reflect.Interface {
			v.Set(reflect.ValueOf("value"))
		} else {
			fill(v, "value")
		}
		m.SetMapIndex(k, v)
		value.Set(m)
	case reflect.Func:
		value.Set(reflect.MakeFunc(value.Type(), func([]reflect.Value) []reflect.Value {
			out := make([]reflect.Value, value.Type().NumOut())
			for i := range out {
				out[i] = reflect.Zero(value.Type().Out(i))
			}
			return out
		}))
	case reflect.Struct:
		if value.Type() == timeType {
			value.Set(reflect.ValueOf(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)))
			return
		}
		for i := 0; i < value.NumField(); i++ {
			if value.Type().Field(i).IsExported() {
				fill(value.Field(i), strings.ToLower(value.Type().Field(i).Name[:1])+value.Type().Field(i).Name[1:])
			}
		}
	}
}

// paramNames maps "pkg.Type.Method" to its parameter names (index 0 = ctx).
func paramNames(t *testing.T, packages ...string) map[string][]string {
	out := map[string][]string{}
	for _, pkg := range packages {
		parsed, err := parser.ParseDir(token.NewFileSet(), filepath.Join("..", "..", pkg), func(info os.FileInfo) bool {
			return !strings.HasSuffix(info.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range parsed {
			for _, file := range p.Files {
				for _, decl := range file.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Recv == nil || !fn.Name.IsExported() {
						continue
					}
					receiver := fn.Recv.List[0].Type
					if star, ok := receiver.(*ast.StarExpr); ok {
						receiver = star.X
					}
					ident, ok := receiver.(*ast.Ident)
					if !ok {
						continue
					}
					var names []string
					for _, field := range fn.Type.Params.List {
						for _, n := range field.Names {
							names = append(names, n.Name)
						}
					}
					out[pkg+"."+ident.Name+"."+fn.Name.Name] = names
				}
			}
		}
	}
	return out
}

// ── Simulated server ──

type exchange struct {
	method, path, template string
	status                 int
	schema                 map[string]any
	schemas                []map[string]any // every documented 2xx body
	issues                 []string
}

type simulator struct {
	spec     *spec
	mu       sync.Mutex
	log      []exchange
	optional map[string]bool
	used     map[string]bool
	notes    []string
}

func (s *simulator) begin(optional map[string]bool) {
	s.mu.Lock()
	s.log, s.optional = nil, optional
	s.mu.Unlock()
}

func (s *simulator) note(line string) {
	s.mu.Lock()
	s.notes = append(s.notes, line)
	s.mu.Unlock()
}

// optionalFields are the omitempty JSON names of a method's struct
// arguments (one level, embedded structs included).
func optionalFields(fn reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := 1; i < fn.NumIn(); i++ {
		arg := fn.In(i)
		for arg.Kind() == reflect.Pointer || arg.Kind() == reflect.Slice {
			arg = arg.Elem()
		}
		if arg.Kind() != reflect.Struct || arg == timeType {
			continue
		}
		for _, f := range jsonFields(arg) {
			if f.optional {
				out[f.name] = true
			}
		}
	}
	return out
}

func (s *simulator) end() []exchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.log
}

func (s *simulator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ex := exchange{method: r.Method, path: r.URL.Path}
	s.mu.Lock()
	optional := s.optional
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.log = append(s.log, ex)
		s.mu.Unlock()
	}()
	template, operation := s.spec.find(r.Method, r.URL.Path)
	if operation == nil {
		ex.issues = append(ex.issues, "route is not in api/openapi.json")
		ex.status = http.StatusNotFound
		http.Error(w, `{"error":{"code":"NOT_FOUND","message":"undocumented"}}`, ex.status)
		return
	}
	ex.template = template
	s.mu.Lock()
	s.used[r.Method+" "+template] = true
	s.mu.Unlock()

	accepted := map[string]bool{}
	if list, ok := operation["parameters"].([]any); ok {
		for _, p := range list {
			p := p.(map[string]any)
			if p["in"] == "query" {
				accepted[p["name"].(string)] = true
			}
		}
	}
	for name := range r.URL.Query() {
		if !accepted[name] {
			ex.issues = append(ex.issues, fmt.Sprintf("query parameter %q is not documented", name))
		}
	}
	body, _ := io.ReadAll(r.Body)
	if schema := s.spec.requestSchema(operation, r.Header.Get("Content-Type")); schema != nil && len(strings.TrimSpace(string(body))) > 0 {
		var sent any
		if err := json.Unmarshal(body, &sent); err != nil {
			ex.issues = append(ex.issues, "request body is not JSON")
		} else {
			for _, issue := range s.spec.validate(sent, schema, "body") {
				var field string
				if n, _ := fmt.Sscanf(issue, "body.%s is not a documented field", &field); n == 1 && optional[field] {
					continue // an omitempty field of a shared input type
				}
				ex.issues = append(ex.issues, issue)
			}
		}
	}

	status, contentType, schema := s.spec.success(operation)
	ex.status, ex.schema = status, schema
	ex.schemas = s.spec.bodies(operation)
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if contentType == "" && status != http.StatusNoContent {
		// Undocumented body (fosite endpoints): any JSON.
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	if status == http.StatusNoContent || contentType == "application/x-ndjson" {
		return
	}
	// A response without a schema may be any JSON: null decodes into
	// every Go type.
	_ = json.NewEncoder(w).Encode(s.spec.example(schema, 0))
}

func (s *simulator) report(t *testing.T) {
	var missing []string
	for _, op := range s.spec.operations() {
		if !s.used[op] {
			missing = append(missing, op)
		}
	}
	sort.Strings(missing)
	t.Logf("%d of %d documented operations have no SDK method:\n%s", len(missing), len(s.spec.operations()), strings.Join(missing, "\n"))
	sort.Strings(s.notes)
	t.Logf("response fields without an SDK field:\n%s", strings.Join(s.notes, "\n"))
}

// ── OpenAPI document ──

type spec struct {
	paths   map[string]map[string]any
	schemas map[string]any
}

func loadSpec(t *testing.T) *spec {
	dir, _ := os.Getwd()
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "api", "openapi.json"))
		if err == nil {
			var doc struct {
				Paths      map[string]map[string]any `json:"paths"`
				Components struct {
					Schemas map[string]any `json:"schemas"`
				} `json:"components"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			return &spec{paths: doc.Paths, schemas: doc.Components.Schemas}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("api/openapi.json not found: the contract check runs inside the IAMKit repository")
		}
		dir = parent
	}
}

func (s *spec) operations() []string {
	var out []string
	for path, item := range s.paths {
		if path == "/openapi.json" || path == "/health" {
			continue
		}
		for method := range item {
			out = append(out, strings.ToUpper(method)+" "+path)
		}
	}
	return out
}

// find matches a request path, preferring literal segments over parameters.
func (s *spec) find(method, path string) (string, map[string]any) {
	segments := strings.Split(path, "/")
	best, bestScore := "", -1
	for template, item := range s.paths {
		if _, ok := item[strings.ToLower(method)]; !ok {
			continue
		}
		parts := strings.Split(template, "/")
		if len(parts) != len(segments) {
			continue
		}
		score := 0
		for i, part := range parts {
			if strings.HasPrefix(part, "{") {
				continue
			}
			if part != segments[i] {
				score = -1
				break
			}
			score++
		}
		if score > bestScore {
			best, bestScore = template, score
		}
	}
	if best == "" {
		return "", nil
	}
	return best, s.paths[best][strings.ToLower(method)].(map[string]any)
}

func (s *spec) requestSchema(operation map[string]any, contentType string) map[string]any {
	body, _ := operation["requestBody"].(map[string]any)
	content, _ := body["content"].(map[string]any)
	media, _ := content[strings.Split(contentType, ";")[0]].(map[string]any)
	schema, _ := media["schema"].(map[string]any)
	return schema
}

func (s *spec) success(operation map[string]any) (int, string, map[string]any) {
	responses := operation["responses"].(map[string]any)
	codes := make([]string, 0, len(responses))
	for code := range responses {
		if strings.HasPrefix(code, "2") {
			codes = append(codes, code)
		}
	}
	sort.Strings(codes)
	if len(codes) == 0 {
		return http.StatusOK, "", nil
	}
	var status int
	fmt.Sscanf(codes[0], "%d", &status)
	response := responses[codes[0]].(map[string]any)
	content, _ := response["content"].(map[string]any)
	for _, media := range []string{"application/json", "application/scim+json", "application/x-ndjson"} {
		if m, ok := content[media].(map[string]any); ok {
			schema, _ := m["schema"].(map[string]any)
			return status, media, schema
		}
	}
	return status, "", nil
}

// bodies returns the JSON schema of every 2xx response.
func (s *spec) bodies(operation map[string]any) []map[string]any {
	var out []map[string]any
	for code, r := range operation["responses"].(map[string]any) {
		if !strings.HasPrefix(code, "2") {
			continue
		}
		content, _ := r.(map[string]any)["content"].(map[string]any)
		for _, media := range []string{"application/json", "application/scim+json"} {
			if m, ok := content[media].(map[string]any); ok {
				if schema, ok := m["schema"].(map[string]any); ok {
					out = append(out, schema)
				}
			}
		}
	}
	return out
}

func (s *spec) resolve(schema map[string]any) map[string]any {
	for depth := 0; depth < 10; depth++ {
		ref, ok := schema["$ref"].(string)
		if !ok {
			return schema
		}
		schema = s.schemas[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any)
	}
	return schema
}

func types(schema map[string]any) []string {
	switch v := schema["type"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, t := range v {
			out = append(out, t.(string))
		}
		return out
	}
	return nil
}

// free reports a schema that accepts any value.
func (s *spec) free(schema map[string]any) bool {
	schema = s.resolve(schema)
	if branches, ok := schema["anyOf"].([]any); ok {
		for _, b := range branches {
			if s.free(b.(map[string]any)) {
				return true
			}
		}
		return false
	}
	return schema["type"] == nil && schema["properties"] == nil
}

// branches returns the alternatives of an anyOf (or the schema itself).
func (s *spec) branches(schema map[string]any) []map[string]any {
	schema = s.resolve(schema)
	list, ok := schema["anyOf"].([]any)
	if !ok {
		return []map[string]any{schema}
	}
	var out []map[string]any
	for _, b := range list {
		out = append(out, s.branches(b.(map[string]any))...)
	}
	return out
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

// validate checks a sent JSON value: documented fields and types.
func (s *spec) validate(value any, schema map[string]any, at string) []string {
	if s.free(schema) {
		return nil
	}
	var best []string
	for i, branch := range s.branches(schema) {
		issues := s.validateOne(value, branch, at)
		if len(issues) == 0 {
			return nil
		}
		if i == 0 || len(issues) < len(best) {
			best = issues
		}
	}
	return best
}

func (s *spec) validateOne(value any, schema map[string]any, at string) []string {
	allowed := types(schema)
	kind := jsonType(value)
	if len(allowed) > 0 {
		ok := false
		for _, a := range allowed {
			if a == kind || (a == "integer" && kind == "number") {
				ok = true
			}
		}
		if !ok {
			return []string{fmt.Sprintf("%s is %s, the document says %v", at, kind, allowed)}
		}
	}
	var issues []string
	switch v := value.(type) {
	case map[string]any:
		properties, _ := schema["properties"].(map[string]any)
		extra, _ := schema["additionalProperties"].(map[string]any)
		for key, item := range v {
			if p, ok := properties[key].(map[string]any); ok {
				issues = append(issues, s.validate(item, p, at+"."+key)...)
			} else if extra != nil {
				issues = append(issues, s.validate(item, extra, at+"."+key)...)
			} else if properties != nil || schema["additionalProperties"] == false {
				issues = append(issues, fmt.Sprintf("%s.%s is not a documented field", at, key))
			}
		}
	case []any:
		if items, ok := schema["items"].(map[string]any); ok {
			for _, item := range v {
				issues = append(issues, s.validate(item, items, at+"[]")...)
			}
		}
	}
	return issues
}

var uuidField = regexp.MustCompile(`(?i)uuid`)

// example builds a response with every documented field set.
func (s *spec) example(schema map[string]any, depth int) any {
	if schema == nil || depth > 12 || s.free(schema) {
		return nil
	}
	branches := s.branches(schema)
	schema = branches[len(branches)-1]
	for _, b := range branches {
		if b["properties"] != nil {
			schema = b
		}
	}
	kinds := types(schema)
	kind := ""
	for _, k := range kinds {
		if k != "null" {
			kind = k
		}
	}
	if kind == "" && schema["properties"] != nil {
		kind = "object"
	}
	switch kind {
	case "string":
		if schema["format"] == "date-time" {
			return "2026-01-02T03:04:05Z"
		}
		if d, _ := schema["description"].(string); uuidField.MatchString(d) {
			return uuid
		}
		return "x"
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		items, _ := schema["items"].(map[string]any)
		if items == nil {
			return []any{}
		}
		return []any{s.example(items, depth+1)}
	case "object":
		out := map[string]any{}
		properties, _ := schema["properties"].(map[string]any)
		for key, p := range properties {
			out[key] = s.example(p.(map[string]any), depth+1)
		}
		if extra, ok := schema["additionalProperties"].(map[string]any); ok && len(properties) == 0 {
			out["key"] = s.example(extra, depth+1)
		}
		return out
	}
	return nil
}

// fields reports fields of a result type the response schema does not have.
func (s *spec) fields(kind reflect.Type, schema map[string]any, at string) []string {
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	if schema == nil || s.free(schema) || kind == timeType || kind == rawType {
		return nil
	}
	properties := map[string]map[string]any{}
	open := false
	isArray := false
	var items map[string]any
	for _, b := range s.branches(schema) {
		if p, ok := b["properties"].(map[string]any); ok {
			for k, v := range p {
				properties[k] = v.(map[string]any)
			}
		}
		if b["additionalProperties"] != nil && b["additionalProperties"] != false {
			open = true
		}
		if i, ok := b["items"].(map[string]any); ok {
			isArray, items = true, i
		}
	}
	switch kind.Kind() {
	case reflect.Struct:
		if open {
			return nil
		}
		var issues []string
		for _, f := range jsonFields(kind) {
			p, ok := properties[f.name]
			if !ok && f.optional {
				continue // an omitempty field of a shared result type
			}
			if !ok {
				issues = append(issues, fmt.Sprintf("field %s%s is not in the response schema", at, f.name))
				continue
			}
			issues = append(issues, s.fields(f.kind, p, at+f.name+".")...)
		}
		return issues
	case reflect.Slice:
		if isArray {
			return s.fields(kind.Elem(), items, at)
		}
		// List helpers unwrap a {items,page} envelope, and methods return
		// the list of a one-field object ({"recovery_codes": [...]}).
		if len(properties) == 1 {
			for name := range properties {
				properties["items"] = properties[name]
			}
		}
		if p, ok := properties["items"]; ok {
			for _, b := range s.branches(p) {
				if i, ok := b["items"].(map[string]any); ok {
					return s.fields(kind.Elem(), i, at)
				}
			}
		}
		return []string{fmt.Sprintf("%sresult is a list, the response is not", at)}
	case reflect.Map:
		for _, b := range s.branches(schema) {
			if extra, ok := b["additionalProperties"].(map[string]any); ok {
				return s.fields(kind.Elem(), extra, at)
			}
		}
	}
	return nil
}

type jsonField struct {
	name     string
	kind     reflect.Type
	optional bool
}

func jsonFields(kind reflect.Type) []jsonField {
	var out []jsonField
	for i := 0; i < kind.NumField(); i++ {
		f := kind.Field(i)
		tag := f.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if f.Anonymous && name == "" {
			embedded := f.Type
			if embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				out = append(out, jsonFields(embedded)...)
				continue
			}
		}
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, jsonField{name, f.Type, strings.Contains(tag, ",omitempty")})
	}
	return out
}

// unexposed lists response fields the result type has no field for
// (informational: the SDK may leave out what callers do not need).
func (s *spec) unexposed(kind reflect.Type, schema map[string]any) []string {
	wrapped := kind.Kind() == reflect.Slice
	for kind.Kind() == reflect.Pointer || kind.Kind() == reflect.Slice {
		kind = kind.Elem()
	}
	if kind.Kind() != reflect.Struct || kind == timeType {
		return nil
	}
	properties := map[string]bool{}
	for _, b := range s.branches(schema) {
		p, _ := b["properties"].(map[string]any)
		if len(p) == 1 && wrapped {
			// A one-field wrapper ({"items": [...]}) the method unwraps.
			for _, only := range p {
				for _, ob := range s.branches(only.(map[string]any)) {
					if i, ok := ob["items"].(map[string]any); ok {
						for _, eb := range s.branches(i) {
							q, _ := eb["properties"].(map[string]any)
							for k := range q {
								properties[k] = true
							}
						}
					}
				}
			}
			continue
		}
		if items, ok := p["items"].(map[string]any); ok && p["page"] != nil {
			for _, ib := range s.branches(items) {
				if i, ok := ib["items"].(map[string]any); ok {
					for _, eb := range s.branches(i) {
						q, _ := eb["properties"].(map[string]any)
						for k := range q {
							properties[k] = true
						}
					}
				}
			}
			continue
		}
		for k := range p {
			properties[k] = true
		}
	}
	for _, f := range jsonFields(kind) {
		delete(properties, f.name)
	}
	var out []string
	for k := range properties {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
