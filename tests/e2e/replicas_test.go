package e2e_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/server"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// pair is two IAMKit replicas (two bootstraps) on one database and one
// Redis testcontainer, wired the way REDIS_URL wires a deployment
// (bootstrap.WithRedis: shared cache, windows and limiter storage). Both
// reach the same fake documents host.
type pair struct {
	A, B *Env
	Host *metadataHost
	// Redis is the shared Redis URL (more replicas: Env.replica).
	Redis string
}

// newPair starts Redis and two replicas. rate is Server.RateLimitPerMinute
// (0: out of the way, 100000); opts apply to both.
func newPair(t *testing.T, rate int, opts ...bootstrap.Option) *pair {
	t.Helper()
	if rate == 0 {
		rate = 100000
	}
	redisURL, _ := startRedis(t)
	configure := func(s *server.Server) { s.RateLimitPerMinute = rate; s.TrustedProxies = []string{"0.0.0.0/8"} }
	a := newEnvWith(t, configure, append([]bootstrap.Option{bootstrap.WithRedis(openRedis(t, redisURL))}, opts...)...)
	b := a.replica(redisURL, rate, opts...)
	host := a.metadataHost()
	b.CIMD.Set(host)
	return &pair{A: a, B: b, Host: host, Redis: redisURL}
}

// replica is a second server on e's database, issuer, keys and mail, with
// its own Redis connection, caches, workers and outbound transports.
func (e *Env) replica(redisURL string, rate int, opts ...bootstrap.Option) *Env {
	e.t.Helper()
	sealer, err := cryptox.Parse(testEncryptionKey, "")
	if err != nil {
		e.t.Fatal(err)
	}
	idp, cimd := &switchTransport{}, &switchTransport{}
	all := append([]bootstrap.Option{bootstrap.WithResolver(e.DNS), bootstrap.WithSealer(sealer), bootstrap.WithFederationTransport(idp), bootstrap.WithClientMetadataTransport(cimd), bootstrap.WithRedis(openRedis(e.t, redisURL))}, opts...)
	s := bootstrap.New(e.DB, e.Key, testIssuer, e.Mail, all...)
	s.RateLimitPerMinute = rate
	s.TrustedProxies = []string{"0.0.0.0/8"}
	app := s.App()
	e.t.Cleanup(func() { app.Shutdown() })
	h := *e.Harness
	h.App, h.IdP, h.CIMD, h.Server = contracted(e.t, app, s.WaitDeliveries), idp, cimd, s
	b := *e
	b.Harness = &h
	return &b
}

// clearOfMinute waits for the start of the next minute when fewer than need
// remain in this one, so a test counting a per-minute window (fixed
// windows: usage.Window) cannot straddle two of them.
func clearOfMinute(need time.Duration) {
	if left := time.Until(time.Now().Truncate(time.Minute).Add(time.Minute)); left < need {
		time.Sleep(left + 200*time.Millisecond)
	}
}

func (e *Env) anonymousAuthorize(clientID string, redirect string) page {
	e.t.Helper()
	return e.browser().get(resourceAuthorize(clientID, url.Values{"redirect_uri": {redirect}}))
}

// anonymousAuthorizeFrom is anonymousAuthorize from the client address ip
// (the replicas trust the proxy newPair sets up).
func (e *Env) anonymousAuthorizeFrom(ip, clientID string, redirect string) page {
	e.t.Helper()
	b := e.browser()
	b.ip = ip
	return b.get(resourceAuthorize(clientID, url.Values{"redirect_uri": {redirect}}))
}

// TestReplicasShareClientMetadata: with a shared Redis a document (and the
// failure to read one) fetched through one replica is not fetched again by
// the other; the key set and the unknown-kid refetch throttle are shared;
// a client assertion spent at one replica is refused at the other.
func TestReplicasShareClientMetadata(t *testing.T) {
	p := newPair(t, 0)
	A, B, host := p.A, p.B, p.Host
	A.mcpServer(fiber.Map{})

	// (a) Documents: positive and negative answers, in both directions.
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	if page := A.anonymousAuthorize(claudeCodeID, loopback); page.Status != 303 {
		t.Fatalf("A authorize: %d %s", page.Status, page.Body)
	}
	if page := B.anonymousAuthorize(claudeCodeID, loopback); page.Status != 303 {
		t.Fatalf("B authorize: %d %s", page.Status, page.Body)
	}
	if n := host.Reads(claudeCodeID); n != 1 {
		t.Fatalf("document read %d times by two replicas, want 1", n)
	}
	for i, order := range [][2]*Env{{A, B}, {B, A}} {
		missing := "https://claude.ai/oauth/missing-" + itoa(i)
		for _, e := range order {
			if page := e.anonymousAuthorize(missing, loopback); page.Status != 400 || page.Location != "" {
				t.Fatalf("missing document: %d %q", page.Status, page.Location)
			}
		}
		if n := host.Reads(missing); n != 1 {
			t.Fatalf("failed document %d read %d times by two replicas, want 1 (negative cache)", i, n)
		}
	}

	// ChatGPT: private_key_jwt with a jwks_uri; its origin is allowlisted.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	host.Put(chatGPTID, map[string]any{"client_id": chatGPTID, "client_name": "ChatGPT", "redirect_uris": []string{"https://chatgpt.com/connector_platform_oauth_redirect"}, "token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "RS256", "jwks_uri": chatGPTJWKS})
	host.Put(chatGPTJWKS, map[string]any{"keys": []any{rsaJWK(key, "k1")}})
	A.DB.MustExec(`INSERT INTO oauth_client_allowlist(id,environment_id,origin,path_prefix) VALUES(gen_random_uuid(),$1,'https://chatgpt.com','/oauth/client.json')`, A.EnvID)
	redirect := "https://chatgpt.com/connector_platform_oauth_redirect"
	signed := func(kid, jti string) string {
		return assertion(t, jwt.SigningMethodRS256, key, kid, chatGPTID, testIssuer+"/oauth/token", jti)
	}
	exchange := func(e *Env, jti string) (map[string]any, string) {
		t.Helper()
		b := e.browser()
		code := b.signInTo(b.get(resourceAuthorize(chatGPTID, url.Values{"redirect_uri": {redirect}})), redirect)
		form := codeForm(chatGPTID, code)
		form.Set("redirect_uri", redirect)
		form.Set("client_assertion_type", assertionType)
		assertionJWT := signed("k1", jti)
		form.Set("client_assertion", assertionJWT)
		status, tokens, _ := e.tokenCall(form, "")
		if status != 200 {
			t.Fatalf("private_key_jwt exchange: %d %v", status, tokens)
		}
		return tokens, assertionJWT
	}
	refresh := func(e *Env, token, assertionJWT string) (int, map[string]any) {
		t.Helper()
		form := refreshForm(chatGPTID, token)
		form.Set("client_assertion_type", assertionType)
		form.Set("client_assertion", assertionJWT)
		status, out, _ := e.tokenCall(form, "")
		return status, out
	}
	tokensA, usedAtA := exchange(A, uuid.NewString())
	tokensB, usedAtB := exchange(B, uuid.NewString())
	if n := host.Reads(chatGPTID); n != 1 {
		t.Fatalf("ChatGPT document read %d times, want 1", n)
	}
	if n := host.Reads(chatGPTJWKS); n != 1 {
		t.Fatalf("key set read %d times by two replicas, want 1", n)
	}

	// (c) A spent assertion is spent everywhere (the jti lives in the
	// database, not in a replica).
	if status, out := refresh(B, tokensA["refresh_token"].(string), usedAtA); status != 400 || out["error"] != "jti_known" {
		t.Fatalf("assertion spent at A, replayed at B: %d %v", status, out)
	}
	if status, out := refresh(A, tokensB["refresh_token"].(string), usedAtB); status != 400 || out["error"] != "jti_known" {
		t.Fatalf("assertion spent at B, replayed at A: %d %v", status, out)
	}
	// A fresh assertion works at the replica that did not issue the token.
	if status, out := refresh(B, tokensA["refresh_token"].(string), signed("k1", uuid.NewString())); status != 200 {
		t.Fatalf("fresh assertion at B for A's token: %d %v", status, out)
	}

	// (b) An unknown kid refetches the key set once a minute for the whole
	// fleet: A's refetch makes B's attempt a cache read.
	if status, _ := refresh(A, tokensA["refresh_token"].(string), signed("unknown-1", uuid.NewString())); status == 200 {
		t.Fatalf("unknown kid at A: %d", status)
	}
	afterA := host.Reads(chatGPTJWKS)
	if afterA != 2 {
		t.Fatalf("unknown kid at A: key set read %d times, want 2 (one forced refetch)", afterA)
	}
	for i, e := range []*Env{B, A, B} {
		if status, _ := refresh(e, tokensA["refresh_token"].(string), signed("unknown-"+itoa(i+2), uuid.NewString())); status == 200 {
			t.Fatalf("unknown kid %d: %d", i+2, status)
		}
	}
	if n := host.Reads(chatGPTJWKS); n != afterA {
		t.Fatalf("key set refetched %d more times within the refresh interval", n-afterA)
	}
}

// TestReplicasBlockAtOnce: blocking a client through one replica ends its
// access on the other at once, though that replica holds the client's
// document in the shared cache and served the client before.
func TestReplicasBlockAtOnce(t *testing.T) {
	p := newPair(t, 0)
	A, B, host := p.A, p.B, p.Host
	_, protected, _ := A.mcpServer(fiber.Map{})
	host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	base := A.Base + "/protected-resources/" + protected

	// It waits for IT (asked through B), IT approves through A.
	if page := B.loginAndAsk(claudeCodeID); page.Status != 403 {
		t.Fatalf("pending: %d", page.Status)
	}
	var rowID string
	A.DB.Get(&rowID, `SELECT id FROM oauth_clients WHERE external_id=$1`, claudeCodeID)
	A.approveClient(base, rowID)
	registered := A.Must("POST", A.Base+"/oauth-clients", A.Owner, fiber.Map{"application_id": A.Client, "resource_id": A.Res, "redirect_uris": []string{"https://app.example/callback"}}, 201).JSON
	rid, rsecret := registered["client_id"].(string), registered["client_secret"].(string)

	// Tokens issued by B: a JWT access token with its refresh token, and an
	// opaque one.
	status, jwtTokens := B.authorizeExternal(claudeCodeID)
	if status != 200 {
		t.Fatalf("B issues JWT tokens: %d %v", status, jwtTokens)
	}
	A.DB.MustExec(`UPDATE oauth_clients SET access_token_format='opaque' WHERE id=$1`, rowID)
	status, opaque := B.authorizeExternal(claudeCodeID, "openid mcp:tools:read")
	if status != 200 || !strings.HasPrefix(opaque["access_token"].(string), "ory_at_") {
		t.Fatalf("B issues opaque tokens: %d %v", status, opaque)
	}
	jwtAccess, opaqueAccess := jwtTokens["access_token"].(string), opaque["access_token"].(string)

	// Everything works at B while approved (and warms B).
	if got := B.introspectAs(rid, rsecret, opaqueAccess); got["active"] != true {
		t.Fatalf("opaque introspection before block: %v", got)
	}
	if got := B.introspectAs(rid, rsecret, jwtAccess); got["active"] != true {
		t.Fatalf("JWT introspection before block: %v", got)
	}
	if res := B.Do("GET", "/oauth/userinfo", opaqueAccess, nil); res.Status != 200 {
		t.Fatalf("userinfo before block: %d %s", res.Status, res.Body)
	}
	if page := B.anonymousAuthorize(claudeCodeID, loopback); page.Status != 303 {
		t.Fatalf("authorize before block: %d", page.Status)
	}

	// IT blocks it through A.
	A.Must("POST", base+"/clients/"+rowID+"/block", A.Owner, nil, 200)

	for name, token := range map[string]string{"JWT": jwtTokens["refresh_token"].(string), "opaque": opaque["refresh_token"].(string)} {
		if status, out, _ := B.tokenCall(refreshForm(claudeCodeID, token), ""); status != 400 || out["error"] != "invalid_grant" {
			t.Fatalf("B refreshes %s tokens after the block at A: %d %v", name, status, out)
		}
	}
	for name, token := range map[string]string{"JWT": jwtAccess, "opaque": opaqueAccess} {
		if got := B.introspectAs(rid, rsecret, token); got["active"] != false {
			t.Fatalf("B introspects %s token after the block at A: %v", name, got)
		}
	}
	if res := B.Do("GET", "/oauth/userinfo", opaqueAccess, nil); res.Status != 401 {
		t.Fatalf("B userinfo after the block at A: %d %s", res.Status, res.Body)
	}
	if page := B.anonymousAuthorize(claudeCodeID, loopback); page.Status != 403 || page.Location != "" || !strings.Contains(page.Body, "blocked") {
		t.Fatalf("B authorize after the block at A: %d %s", page.Status, page.Body)
	}
	if n := host.Reads(claudeCodeID); n != 1 {
		t.Fatalf("document read %d times, want 1: the block needs no refetch", n)
	}
}

// TestReplicasShareFetchBudget: an environment reads at most
// config.ClientMetadataNewFetchesPerMinute distinct documents of unknown
// clients a minute across all its replicas (the rest of
// ClientMetadataFetchesPerMinute is for known clients), and a document one
// replica read is free at the other. Every request comes from its own
// address: the per-address budget has its own test.
func TestReplicasShareFetchBudget(t *testing.T) {
	p := newPair(t, 0)
	A, B, host := p.A, p.B, p.Host
	A.mcpServer(fiber.Map{})
	clearOfMinute(20 * time.Second)

	budget := config.ClientMetadataNewFetchesPerMinute
	put := func(i int) string {
		id := "https://budget.example/clients/" + itoa(i)
		host.Put(id, map[string]any{"client_id": id, "client_name": "App", "redirect_uris": []string{"http://localhost/callback"}, "token_endpoint_auth_method": "none"})
		return id
	}
	ip := func(i int) string { return "198.51.100." + itoa(i+1) }
	rowsBefore := A.count(`SELECT count(*) FROM oauth_clients`)
	eventsBefore := A.count(`SELECT count(*) FROM events`)
	var first, second string
	for i := range budget {
		e := A
		if i%2 == 1 {
			e = B
		}
		id := put(i)
		if i == 0 {
			first = id
		}
		if i == 1 {
			second = id
		}
		if page := e.anonymousAuthorizeFrom(ip(i), id, loopback); page.Status != 303 {
			t.Fatalf("document %d within the budget: %d %s", i, page.Status, page.Body)
		}
	}
	for i, e := range []*Env{A, B, A, B} {
		if page := e.anonymousAuthorizeFrom(ip(budget+i), put(100+i), loopback); page.Status != 429 {
			t.Fatalf("document beyond the budget at replica %d: %d, want 429 (budget counted per replica?)", i, page.Status)
		}
	}
	if rows, events := A.count(`SELECT count(*) FROM oauth_clients`), A.count(`SELECT count(*) FROM events`); rows != rowsBefore || events != eventsBefore {
		t.Fatalf("an anonymous flood across the replicas wrote %d rows and %d events", rows-rowsBefore, events-eventsBefore)
	}
	total := 0
	for i := range budget {
		total += host.Reads("https://budget.example/clients/" + itoa(i))
	}
	if total != budget {
		t.Fatalf("network reads = %d, want exactly the budget %d", total, budget)
	}
	for i := 100; i < 104; i++ {
		if n := host.Reads("https://budget.example/clients/" + itoa(i)); n != 0 {
			t.Fatalf("refused document %d was read %d times", i, n)
		}
	}
	// What the other replica read is cached and costs nothing.
	if page := B.anonymousAuthorizeFrom(ip(0), first, loopback); page.Status != 303 {
		t.Fatalf("document read by A, asked at B: %d", page.Status)
	}
	if page := A.anonymousAuthorizeFrom(ip(1), second, loopback); page.Status != 303 {
		t.Fatalf("document read by B, asked at A: %d", page.Status)
	}
	if n := host.Reads(first) + host.Reads(second); n != 2 {
		t.Fatalf("cached documents were read again: %d reads, want 2", n)
	}
}

// TestReplicasShareFetchBudgetPerAddress is M-4: one address makes the
// deployment read at most config.ClientMetadataFetchesPerIPPerMinute
// documents a minute, whichever replica it reaches; other addresses are not
// affected, and what it asked for again is cached.
func TestReplicasShareFetchBudgetPerAddress(t *testing.T) {
	p := newPair(t, 0)
	A, B, host := p.A, p.B, p.Host
	A.mcpServer(fiber.Map{})
	clearOfMinute(20 * time.Second)

	put := func(i int) string {
		id := "https://perip.example/clients/" + itoa(i)
		host.Put(id, map[string]any{"client_id": id, "client_name": "App", "redirect_uris": []string{"http://localhost/callback"}, "token_endpoint_auth_method": "none"})
		return id
	}
	const flooder, other = "203.0.113.50", "203.0.113.51"
	n := config.ClientMetadataFetchesPerIPPerMinute
	for i := range n {
		e := A
		if i%2 == 1 {
			e = B
		}
		if page := e.anonymousAuthorizeFrom(flooder, put(i), loopback); page.Status != 303 {
			t.Fatalf("document %d within the address's budget: %d %s", i, page.Status, page.Body)
		}
	}
	for i, e := range []*Env{A, B} {
		id := put(100 + i)
		page := e.anonymousAuthorizeFrom(flooder, id, loopback)
		if page.Status != 429 || !strings.Contains(page.Body, "CLIENT_METADATA_FETCH_BUDGET") {
			t.Fatalf("document beyond the address's budget at replica %d: %d %s", i, page.Status, page.Body)
		}
		if host.Reads(id) != 0 {
			t.Fatalf("a refused document was read")
		}
		if page := e.anonymousAuthorizeFrom(other, id, loopback); page.Status != 303 {
			t.Fatalf("another address at replica %d: %d %s", i, page.Status, page.Body)
		}
	}
	// A document already cached is free for the address that spent its budget.
	if page := B.anonymousAuthorizeFrom(flooder, "https://perip.example/clients/0", loopback); page.Status != 303 {
		t.Fatalf("cached document for the flooder: %d %s", page.Status, page.Body)
	}
}

// TestReplicasShareAuthorizeRateLimit: /oauth/authorize answers each address
// at most RateLimitPerMinute/2 times a minute in total, whichever replica
// the requests reach (the limiters' storage is Redis).
func TestReplicasShareAuthorizeRateLimit(t *testing.T) {
	p := newPair(t, 0)
	p.A.mcpServer(fiber.Map{})
	p.Host.Put(claudeCodeID, claudeDoc("http://localhost/callback"))
	// Two more replicas whose limit is 10 a minute (the setup above needs
	// the generous one), so 10/2 = 5 authorizations per address.
	C, D := p.A.replica(p.Redis, 10), p.A.replica(p.Redis, 10)
	C.CIMD.Set(p.Host)
	D.CIMD.Set(p.Host)

	for i, e := range []*Env{C, C, C, D, D} {
		if page := e.anonymousAuthorize(claudeCodeID, loopback); page.Status != 303 {
			t.Fatalf("request %d within the limit: %d %s", i+1, page.Status, page.Body)
		}
	}
	for i, e := range []*Env{D, C} {
		if page := e.anonymousAuthorize(claudeCodeID, loopback); page.Status != 429 {
			t.Fatalf("request %d over the limit: %d, want 429 (limit counted per replica?)", 6+i, page.Status)
		}
	}
}

// TestReplicasShareThePendingCap: the backlog cap of an environment holds
// when sign-ins that ask for access arrive concurrently at both replicas.
func TestReplicasShareThePendingCap(t *testing.T) {
	p := newPair(t, 0, bootstrap.WithClientMetadataMaxPending(3))
	A, B, host := p.A, p.B, p.Host
	A.mcpServer(fiber.Map{})

	const clients = 8
	ids := make([]string, clients)
	for i := range ids {
		ids[i] = "https://apps.example/client/" + itoa(i)
		host.Put(ids[i], map[string]any{"client_id": ids[i], "client_name": "App", "redirect_uris": []string{"http://localhost/callback"}, "token_endpoint_auth_method": "none"})
	}
	statuses := make([]int, clients)
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := A
			if i%2 == 1 {
				e = B
			}
			statuses[i] = e.loginAndAsk(id).Status
		}()
	}
	wg.Wait()
	var waiting, refused int
	for _, s := range statuses {
		switch s {
		case 403:
			waiting++
		case 429:
			refused++
		}
	}
	if waiting != 3 || refused != clients-3 {
		t.Fatalf("statuses %v: %d waiting, %d refused; want 3 and %d", statuses, waiting, refused, clients-3)
	}
	if n := A.count(`SELECT count(*) FROM oauth_clients WHERE source='cimd' AND admission='pending'`); n != 3 {
		t.Fatalf("pending rows = %d, want the cap 3", n)
	}
	if n := A.count(`SELECT count(*) FROM events WHERE type='oauth_client.access_requested'`); n != 3 {
		t.Fatalf("access_requested events = %d, want 3", n)
	}
}
