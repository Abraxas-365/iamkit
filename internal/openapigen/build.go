package openapigen

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Route is one registered Fiber route and the source of its final handler.
type Route struct {
	Method, Path string
	Handler      string // runtime function name
	File         string
	Line         int
}

// Family groups the documented surfaces.
type Family struct {
	Prefix, Tag string
	Security    []map[string][]string
	Errors      bool // errors use the {"error": {...}} envelope
}

var families = []Family{
	{"/management/v1", "Management API", []map[string][]string{{"managementKey": {}}, {"operatorSession": {}}}, true},
	{"/api/v1", "Scoped API", []map[string][]string{{"accessToken": {}}}, true},
	{"/identity/v1", "Identity API", nil, true},
	{"/scim/v2", "SCIM 2.0", []map[string][]string{{"scimToken": {}}, {"scimKey": {}}}, false},
	{"/oauth", "OAuth 2.0 / OpenID Connect", nil, false},
	{"/.well-known", "OAuth 2.0 / OpenID Connect", nil, false},
	{"/health", "Operations", nil, true},
	{"/openapi.json", "Operations", nil, false},
}

// Documented reports whether a path belongs to the spec (browser pages,
// the SAML IdP and the console are not REST surfaces).
func Documented(path string) (Family, bool) {
	for _, f := range families {
		if path == f.Prefix || strings.HasPrefix(path, f.Prefix+"/") {
			return f, true
		}
	}
	return Family{}, false
}

var param = regexp.MustCompile(`:([A-Za-z0-9_]+)`)

// OpenAPIPath turns a Fiber path into an OpenAPI template.
func OpenAPIPath(path string) string {
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return param.ReplaceAllString(path, "{$1}")
}

// Build assembles the OpenAPI 3.1 document.
func Build(a *Analyzer, routes []Route, version string) (map[string]any, []string) {
	var warnings []string
	paths := map[string]map[string]any{}
	ids := map[string]bool{}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path != routes[j].Path {
			return routes[i].Path < routes[j].Path
		}
		return routes[i].Method < routes[j].Method
	})
	for _, r := range routes {
		family, ok := Documented(r.Path)
		if !ok {
			continue
		}
		path := OpenAPIPath(r.Path)
		method := strings.ToLower(r.Method)
		item := paths[path]
		if item == nil {
			item = map[string]any{}
			paths[path] = item
		}
		if _, dup := item[method]; dup {
			continue
		}
		src := a.Find(r.Handler, r.File, r.Line)
		op := a.Analyze(src)
		if op.Unresolved {
			warnings = append(warnings, fmt.Sprintf("%s %s: handler %s not found", r.Method, r.Path, r.Handler))
		}
		item[method] = a.operation(family, method, path, op, ids)
	}
	out := map[string]any{}
	for k, v := range paths {
		out[k] = v
	}
	schemas := map[string]any{
		"ErrorDetail": map[string]any{
			"type":     "object",
			"required": []string{"code", "message", "type", "http_status"},
			"properties": map[string]any{
				"code":        map[string]any{"type": "string", "description": "Stable machine-readable code (e.g. VALIDATION_ERROR, ACTION_DENIED)"},
				"message":     map[string]any{"type": "string"},
				"type":        map[string]any{"type": "string"},
				"http_status": map[string]any{"type": "integer"},
				"details":     map[string]any{"type": "object", "description": "Public details only (e.g. password policy rule)"},
			},
		},
		"Error": map[string]any{
			"type":       "object",
			"required":   []string{"error"},
			"properties": map[string]any{"error": ref("ErrorDetail")},
		},
	}
	for k, v := range a.schemas.components {
		schemas[k] = v
	}
	doc := map[string]any{
		"openapi":           "3.1.0",
		"jsonSchemaDialect": "https://spec.openapis.org/oas/3.1/dialect/base",
		"info": map[string]any{
			"title":       "IAMKit API",
			"version":     version,
			"description": "Generated from the server's routes and handlers (`make openapi`); the e2e suite validates every request and response it makes against it. Request bodies document every accepted field; required fields are checked by the server.",
			"license":     map[string]any{"name": "See repository"},
		},
		"paths": out,
		"components": map[string]any{
			"schemas": schemas,
			"securitySchemes": map[string]any{
				"managementKey":   map[string]any{"type": "apiKey", "in": "header", "name": "X-API-Key", "description": "Management key (ik_mgmt_…)"},
				"operatorSession": map[string]any{"type": "apiKey", "in": "cookie", "name": "__Host-iamkit-operator", "description": "Console session; writes also need the X-IAMKit-Console header"},
				"accessToken":     map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "JWT", "description": "End-user or service-account access token (or a machine user's ik_pat_ token)"},
				"scimToken":       map[string]any{"type": "http", "scheme": "bearer", "description": "SCIM provisioning credential"},
				"scimKey":         map[string]any{"type": "apiKey", "in": "header", "name": "X-API-Key", "description": "SCIM provisioning credential (kept for compatibility)"},
			},
		},
	}
	return doc, warnings
}

var nonWord = regexp.MustCompile(`[^A-Za-z0-9]+`)

func operationID(method, path string, ids map[string]bool) string {
	var parts []string
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if strings.HasPrefix(seg, "{") {
			parts = append(parts, "by"+title(strings.Trim(seg, "{}")))
			continue
		}
		if seg == "v1" || seg == "v2" {
			continue
		}
		for _, w := range nonWord.Split(seg, -1) {
			if w != "" {
				parts = append(parts, title(w))
			}
		}
	}
	id := method + strings.Join(parts, "")
	base := id
	for i := 2; ids[id]; i++ {
		id = base + strconv.Itoa(i)
	}
	ids[id] = true
	return id
}

func (a *Analyzer) operation(family Family, method, path string, op Operation, ids map[string]bool) map[string]any {
	out := map[string]any{
		"tags":        []string{family.Tag},
		"operationId": operationID(method, path, ids),
	}
	if op.Summary != "" {
		out["summary"] = op.Summary
	}
	if family.Security != nil {
		out["security"] = family.Security
	}
	var params []any
	for _, m := range param.FindAllStringSubmatch(strings.ReplaceAll(strings.ReplaceAll(path, "{", ":"), "}", ""), -1) {
		params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
	}
	var names []string
	for name := range op.Query {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		params = append(params, map[string]any{"name": name, "in": "query", "schema": map[string]any{"type": op.Query[name]}})
	}
	if len(params) > 0 {
		out["parameters"] = params
	}
	content := map[string]any{}
	if op.Body != nil {
		content["application/json"] = map[string]any{"schema": op.Body}
	}
	if len(op.Form) > 0 {
		props := map[string]any{}
		for _, f := range op.Form {
			props[f] = map[string]any{"type": "string"}
		}
		content["application/x-www-form-urlencoded"] = map[string]any{"schema": map[string]any{"type": "object", "properties": props}}
	}
	if len(content) > 0 {
		out["requestBody"] = map[string]any{"content": content}
	}
	responses := map[string]any{}
	byStatus := map[string][]Response{}
	var anyStatus []Response // status chosen at run time
	for _, r := range op.Responses {
		if r.Status == 0 {
			anyStatus = append(anyStatus, r)
			continue
		}
		key := strconv.Itoa(r.Status)
		byStatus[key] = append(byStatus[key], r)
	}
	for key, list := range byStatus {
		responses[key] = response(key, list)
	}
	if len(anyStatus) > 0 {
		responses["default"] = response("default", anyStatus)
	}
	if family.Errors {
		// Errors from the error handler, plus whatever the handler answers
		// with a status chosen at run time.
		errorsJSON := []Response{{ContentType: "application/json", Schema: ref("Error")}}
		responses["4XX"] = response("4XX", append(append(errorsJSON, Response{ContentType: "text/plain"}), anyStatus...))
		responses["5XX"] = response("5XX", append(errorsJSON, anyStatus...))
	}
	if len(responses) == 0 || op.Open && !hasSuccess(responses) {
		responses["2XX"] = map[string]any{"description": "Success"}
	}
	out["responses"] = responses
	return out
}

func hasSuccess(responses map[string]any) bool {
	for k := range responses {
		if strings.HasPrefix(k, "2") || strings.HasPrefix(k, "3") {
			return true
		}
	}
	return false
}

func response(key string, list []Response) map[string]any {
	out := map[string]any{"description": description(key)}
	byType := map[string][]map[string]any{}
	open := map[string]bool{}
	for _, r := range list {
		if r.Schema == nil {
			if r.ContentType == unknownType {
				return out // a body of unknown type: nothing to check
			}
			if r.ContentType != "" {
				open[r.ContentType] = true
			}
			continue
		}
		byType[r.ContentType] = append(byType[r.ContentType], r.Schema)
	}
	content := map[string]any{}
	for ct := range open {
		content[ct] = map[string]any{}
	}
	for ct, schemas := range byType {
		if !open[ct] {
			content[ct] = map[string]any{"schema": union(schemas)}
		}
	}
	if len(content) > 0 {
		out["content"] = content
	}
	return out
}

func union(list []map[string]any) map[string]any {
	seen := map[string]bool{}
	var unique []any
	for _, s := range list {
		key := fmt.Sprint(s)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, s)
		}
	}
	if len(unique) == 1 {
		return unique[0].(map[string]any)
	}
	return map[string]any{"anyOf": unique}
}

func description(key string) string {
	switch key {
	case "200":
		return "OK"
	case "201":
		return "Created"
	case "202":
		return "Accepted"
	case "204":
		return "No content"
	case "2XX", "default":
		return "Success"
	case "4XX":
		return "Client error"
	case "5XX":
		return "Server error"
	}
	if strings.HasPrefix(key, "3") {
		return "Redirect"
	}
	return "Response " + key
}
