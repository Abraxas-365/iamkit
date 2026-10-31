package e2e_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// syncBuffer is a log buffer the child process writes while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freePort reserves a loopback port and releases it for the caller to use.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// serveIAMKit exposes the harness app on a loopback socket, so processes
// outside the test (the Python example) reach the JWKS and introspection.
func (e *Env) serveIAMKit() string {
	e.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	go e.App.App.Listener(ln)
	e.t.Cleanup(func() { ln.Close() })
	return "http://" + ln.Addr().String()
}

type mcpReply struct {
	Status int
	Header http.Header
	Body   string
	JSON   map[string]any
}

// mcpPost sends one Streamable HTTP message to the example.
func mcpPost(t *testing.T, target, token string, message map[string]any) mcpReply {
	t.Helper()
	raw, _ := json.Marshal(message)
	req, err := http.NewRequest("POST", target, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	out := mcpReply{Status: res.StatusCode, Header: res.Header, Body: string(body)}
	_ = json.Unmarshal(body, &out.JSON)
	return out
}

func toolCall(id int, name string, args map[string]any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}}
}

// toolText returns the text of a tools/call answer, failing on errors.
func toolText(t *testing.T, r mcpReply) string {
	t.Helper()
	result, _ := r.JSON["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if r.Status != 200 || result == nil || result["isError"] == true || len(content) == 0 {
		t.Fatalf("tool call: %d %s", r.Status, r.Body)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	return text
}

// TestPythonResourceServer runs examples/mcp-server-python (FastMCP behind
// iamkit.resource_server) against this deployment: metadata, the 401
// challenge, a resource-flow token, tool calls, a step-up 403 and, with
// introspection on, the 401 for an answer that describes another grant and
// the one that follows disconnecting the client.
func TestPythonResourceServer(t *testing.T) {
	uv, err := exec.LookPath("uv")
	if err != nil {
		t.Skip("uv is not on PATH: install it (https://docs.astral.sh/uv/) to run the Python resource server test")
	}
	e := newEnv(t)
	t.Setenv("OIDC_HMAC_SECRET", strings.Repeat("s", 32))
	iam := e.serveIAMKit()
	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	resourceURL := base + "/mcp"

	// The MCP server as a resource: read and write permissions, alice may only read.
	resource := e.ID("POST", e.Base+"/resources", fiber.Map{"name": "Notes MCP", "prefix": "notes", "audience": resourceURL, "permissions": []string{"notes:read", "notes:write"}})
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource}, 201)
	e.Must("POST", e.Base+"/protected-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource, "name": "Notes", "default_scopes": []string{"notes:read"}}, 201)
	client := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource, "redirect_uris": []string{"https://app.example/callback"}, "public": true, "hosted_login": true}, 201).JSON["client_id"].(string)
	e.Grant(e.Org, e.Alice, resource, "notes:read")
	introspector := e.Must("POST", e.Base+"/oauth-clients", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": resource, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON

	// Start the example with `uv run`, checking tokens against this deployment.
	dir, err := filepath.Abs("../../examples/mcp-server-python")
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	ctx, stop := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, uv, "run", "python", "server.py")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"IAMKIT_ISSUER="+testIssuer,
		"IAMKIT_ENVIRONMENT_ID="+e.EnvID,
		"IAMKIT_JWKS_URL="+iam+"/.well-known/jwks.json",
		"IAMKIT_INTROSPECTION_URL="+iam,
		"IAMKIT_INTROSPECTION_CLIENT_ID="+introspector["client_id"].(string),
		"IAMKIT_INTROSPECTION_CLIENT_SECRET="+introspector["client_secret"].(string),
		"MCP_RESOURCE_URL="+resourceURL,
		fmt.Sprintf("PORT=%d", port),
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
	)
	cmd.Stdout, cmd.Stderr = logs, logs
	// uv starts the server as a child: stop the whole group, not just uv.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		stop()
		<-exited
		if t.Failed() {
			t.Logf("example output:\n%s", logs)
		}
	})
	ready := time.Now().Add(3 * time.Minute) // the first run installs the environment
	for {
		res, err := http.Get(base + "/health")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				break
			}
		}
		select {
		case <-exited:
			t.Fatalf("the example exited:\n%s", logs)
		default:
		}
		if time.Now().After(ready) {
			t.Fatalf("the example did not start:\n%s", logs)
		}
		time.Sleep(250 * time.Millisecond)
	}

	// 1. Protected resource metadata (RFC 9728), at the path-inserted URL.
	metadataURL := base + "/.well-known/oauth-protected-resource/mcp"
	res, err := http.Get(metadataURL)
	if err != nil {
		t.Fatal(err)
	}
	var prm map[string]any
	json.NewDecoder(res.Body).Decode(&prm)
	res.Body.Close()
	if res.StatusCode != 200 || prm["resource"] != resourceURL || !jsonEqual(prm["authorization_servers"], []any{testIssuer}) || !jsonEqual(prm["scopes_supported"], []any{"notes:read"}) || res.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("metadata: %d %v %v", res.StatusCode, prm, res.Header)
	}

	// 2. No token: 401 naming the metadata.
	initialize := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "e2e", "version": "1"}}}
	denied := mcpPost(t, resourceURL, "", initialize)
	if want := `Bearer resource_metadata="` + metadataURL + `"`; denied.Status != 401 || denied.Header.Get("WWW-Authenticate") != want {
		t.Fatalf("no token: %d %q (want %q) %s", denied.Status, denied.Header.Get("WWW-Authenticate"), want, denied.Body)
	}
	if garbage := mcpPost(t, resourceURL, "not-a-token", initialize); garbage.Status != 401 || !strings.Contains(garbage.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("garbage token: %d %q", garbage.Status, garbage.Header.Get("WWW-Authenticate"))
	}

	// 3. A resource-flow token for this server.
	b := e.browser()
	code := b.signIn(b.get(resourceAuthorize(client, url.Values{"resource": {resourceURL}})))
	status, tokens, _ := e.tokenCall(codeForm(client, code, resourceURL), "")
	if status != 200 {
		t.Fatalf("token: %d %v", status, tokens)
	}
	access := tokens["access_token"].(string)

	// 4. initialize and tools/call work with it.
	if r := mcpPost(t, resourceURL, access, initialize); r.Status != 200 || r.JSON["result"] == nil {
		t.Fatalf("initialize: %d %s", r.Status, r.Body)
	}
	var who map[string]any
	if err = json.Unmarshal([]byte(toolText(t, mcpPost(t, resourceURL, access, toolCall(2, "whoami", nil)))), &who); err != nil || who["user"] != e.Alice || who["organization"] != e.Org || !slices.Contains(scopesList(who["scopes"]), "notes:read") || slices.Contains(scopesList(who["scopes"]), "notes:write") {
		t.Fatalf("whoami: %v %v", who, err)
	}
	if text := toolText(t, mcpPost(t, resourceURL, access, toolCall(3, "list_notes", nil))); text != "No notes yet." {
		t.Fatalf("list_notes: %q", text)
	}

	// 5. A tool that needs more than the token grants: 403 with the scopes to ask for.
	short := mcpPost(t, resourceURL, access, toolCall(4, "add_note", map[string]any{"text": "hello"}))
	challenge := short.Header.Get("WWW-Authenticate")
	if short.Status != 403 || short.JSON["error"] != "insufficient_scope" || !strings.Contains(challenge, `error="insufficient_scope"`) || !strings.Contains(challenge, "notes:read") || !strings.Contains(challenge, "notes:write") || !strings.Contains(challenge, `resource_metadata="`+metadataURL+`"`) {
		t.Fatalf("add_note: %d %q %s", short.Status, challenge, short.Body)
	}

	// 6. IAMKit describes the token as the token does (RFC 9068 client_id,
	// scopes); an answer about another grant is refused even though the
	// token is valid locally. The grant is edited underneath the token to
	// make IAMKit answer for another one.
	described := e.introspectAs(introspector["client_id"].(string), introspector["client_secret"].(string), access)
	if c := claims(t, access); described["active"] != true || c["client_id"] != client || described["client_id"] != client || !sameSet(strings.Fields(described["scope"].(string)), scopesList(c["scp"])) {
		t.Fatalf("introspection %v describes another token than %v", described, c)
	}
	signature := sha256.Sum256([]byte(access[strings.LastIndex(access, ".")+1:]))
	key := hex.EncodeToString(signature[:])
	var stored string
	e.DB.Get(&stored, `SELECT data::text FROM oauth_requests WHERE kind='access' AND signature_hash=$1`, key)
	widen := e.DB.MustExec(`UPDATE oauth_requests SET data=jsonb_set(data,'{GrantedScope}',data->'GrantedScope' || '["notes:write"]') WHERE kind='access' AND signature_hash=$1`, key)
	if n, _ := widen.RowsAffected(); n != 1 {
		t.Fatalf("edited %d grants", n)
	}
	if other := mcpPost(t, resourceURL, access, toolCall(5, "list_notes", nil)); other.Status != 401 || other.JSON["error"] != "invalid_token" {
		t.Fatalf("answer about another grant: %d %s", other.Status, other.Body)
	}
	e.DB.MustExec(`UPDATE oauth_requests SET data=$2::jsonb WHERE kind='access' AND signature_hash=$1`, key, stored)
	toolText(t, mcpPost(t, resourceURL, access, toolCall(6, "list_notes", nil)))

	// 7. alice disconnects the client; the token is still valid locally, but
	// introspection says it is not, and the server closes.
	me := "?environment_id=" + e.EnvID + "&audience=" + url.QueryEscape(e.Audience)
	alice := e.Login(e.AliceEmail)
	e.Must("DELETE", "/identity/v1/me/connected-apps/"+client+me, alice, nil, 204)
	gone := mcpPost(t, resourceURL, access, toolCall(7, "list_notes", nil))
	if gone.Status != 401 || gone.JSON["error"] != "invalid_token" || !strings.Contains(gone.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("after disconnect: %d %q %s", gone.Status, gone.Header.Get("WWW-Authenticate"), gone.Body)
	}
}

func scopesList(v any) []string {
	var out []string
	items, _ := v.([]any)
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
