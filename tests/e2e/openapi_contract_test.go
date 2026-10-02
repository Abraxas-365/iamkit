package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Abraxas-365/iamkit/api"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/gofiber/fiber/v2"
)

// The contract check: every request the harness sends and every response
// it reads are validated against api/openapi.json, so the spec cannot
// drift from the server. Requests are checked only when the server
// accepted them (tests send malformed input on purpose).

var contract struct {
	once   sync.Once
	doc    *openapi3.T
	router routers.Router
	err    error
	mu     sync.Mutex
	used   map[string]bool
}

func loadContract() (*openapi3.T, routers.Router, error) {
	contract.once.Do(func() {
		openapi3filter.RegisterBodyDecoder("application/scim+json", openapi3filter.JSONBodyDecoder)
		openapi3filter.RegisterBodyDecoder("application/x-ndjson", openapi3filter.PlainBodyDecoder)
		loader := openapi3.NewLoader()
		doc, err := loader.LoadFromData(api.Spec)
		if err != nil {
			contract.err = err
			return
		}
		if err := doc.Validate(context.Background()); err != nil {
			contract.err = err
			return
		}
		contract.doc = doc
		contract.router, contract.err = gorillamux.NewRouter(doc)
		contract.used = map[string]bool{}
	})
	return contract.doc, contract.router, contract.err
}

// documented mirrors openapigen.Documented: the REST surfaces in the spec.
func documented(path string) bool {
	for _, prefix := range []string{"/management/v1", "/api/v1", "/identity/v1", "/scim/v2", "/oauth", "/.well-known", "/health", "/openapi.json"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// checkContract validates one exchange; body is the request body sent.
func checkContract(t testing.TB, req *http.Request, body []byte, status int, header http.Header, response []byte) {
	// CORS preflights are answered by middleware, not API operations.
	if !documented(req.URL.Path) || (req.Method == http.MethodOptions && req.Header.Get("Access-Control-Request-Method") != "") {
		return
	}
	_, router, err := loadContract()
	if err != nil {
		t.Fatalf("openapi: %v", err)
	}
	if string(body) == "null" {
		body = nil // a nil fiber.Map from a test; the server reads it as {}
	}
	// The router matches against a request it may read; give it a copy.
	probe := req.Clone(context.Background())
	probe.Body = io.NopCloser(bytes.NewReader(body))
	probe.URL = &url.URL{Path: req.URL.Path, RawQuery: req.URL.RawQuery}
	probe.Host = ""
	route, params, err := router.FindRoute(probe)
	if err != nil {
		if status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusTooManyRequests {
			return
		}
		t.Errorf("openapi: %s %s (%d) is not in api/openapi.json — run make openapi", req.Method, req.URL.Path, status)
		return
	}
	contract.mu.Lock()
	contract.used[req.Method+" "+route.Path] = true
	contract.mu.Unlock()
	options := &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc, MultiError: true}
	input := &openapi3filter.RequestValidationInput{Request: probe, PathParams: params, Route: route, Options: options}
	if status >= 200 && status < 300 {
		if err := openapi3filter.ValidateRequest(context.Background(), input); err != nil {
			t.Errorf("openapi: request %s %s does not match the spec: %v", req.Method, req.URL.Path, err)
		}
	}
	out := &openapi3filter.ResponseValidationInput{RequestValidationInput: input, Status: status, Header: header, Options: options}
	out.SetBodyBytes(response)
	if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
		t.Errorf("openapi: response %d of %s %s does not match the spec: %v\n%s", status, req.Method, req.URL.Path, err, truncate(response))
	}
}

func truncate(b []byte) string {
	if len(b) > 600 {
		return string(b[:600]) + "…"
	}
	return string(b)
}

// App is the app under test; every exchange through Test is checked
// against the contract.
type App struct {
	*fiber.App
	t testing.TB
}

func contracted(t testing.TB, app *fiber.App) *App { return &App{App: app, t: t} }

// Test sends req like fiber.App.Test and validates the exchange.
func (a *App) Test(req *http.Request, timeout ...int) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	original := req.Clone(context.Background())
	res, err := a.App.Test(req, timeout...)
	if err != nil || res == nil {
		return res, err
	}
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(raw))
	checkContract(a.t, original, body, res.StatusCode, res.Header, raw)
	return res, nil
}

// reportContract prints how many documented operations the suite used
// (IAMKIT_OPENAPI_COVERAGE=1 lists the unused ones).
func reportContract() {
	doc, _, err := loadContract()
	if err != nil || doc == nil {
		return
	}
	var all, unused []string
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			key := method + " " + path
			all = append(all, key)
			if !contract.used[key] {
				unused = append(unused, key)
			}
		}
	}
	fmt.Printf("openapi: %d of %d operations exercised\n", len(all)-len(unused), len(all))
	if os.Getenv("IAMKIT_OPENAPI_COVERAGE") != "" {
		sort.Strings(unused)
		for _, key := range unused {
			fmt.Println("  unused:", key)
		}
	}
}
