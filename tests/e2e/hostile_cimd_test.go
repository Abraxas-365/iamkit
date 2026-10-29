package e2e_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/server"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/net/dns/dnsmessage"
)

// hostile is the client_id origin of the hostile host (the httptest
// certificate names example.com).
const hostile = "https://example.com"

// hostileHost is a real HTTPS server misbehaving on purpose, one behavior per
// path. Client ID URLs cannot carry a port, so its transport sends every
// dial to the server's socket and trusts its certificate; everything else
// on the path is production: the fetcher's http.Client (total timeout, no
// redirects), size cap, media type check, validation and cache. Dialing
// through the guarded dialer is TestGuardedDialerRefusesPrivateResolution.
type hostileHost struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  map[string]int
	ended chan string // handlers that saw the client leave
}

func newHostileHost(t *testing.T) *hostileHost {
	t.Helper()
	h := &hostileHost{hits: map[string]int{}, ended: make(chan string, 32)}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hostileHost) transport() http.RoundTripper {
	pool := x509.NewCertPool()
	pool.AddCert(h.srv.Certificate())
	addr := h.srv.Listener.Addr().String()
	return &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   config.ExternalHTTPTimeout,
		ResponseHeaderTimeout: config.ExternalHTTPTimeout,
		ForceAttemptHTTP2:     true,
	}
}

func (h *hostileHost) Hits(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

func hostileDoc(path string, pad int) string {
	doc := `{"client_id":"` + hostile + path + `","client_name":"Hostile","redirect_uris":["http://localhost/callback"],"token_endpoint_auth_method":"none"`
	if pad > 0 {
		doc += `,"padding":"` + strings.Repeat("x", pad) + `"`
	}
	return doc + `}`
}

func (h *hostileHost) serve(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.hits[r.URL.Path]++
	h.mu.Unlock()
	asJSON := func() { w.Header().Set("Content-Type", "application/json") }
	switch r.URL.Path {
	case "/no-store": // valid, but says never to cache it
		asJSON()
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(hostileDoc(r.URL.Path, 0)))
	case "/redirect": // to a valid document: never followed
		http.Redirect(w, r, "/redirected", http.StatusFound)
	case "/redirected":
		asJSON()
		_, _ = w.Write([]byte(hostileDoc(r.URL.Path, 0)))
	case "/big": // 6 KB, over the 5 KB cap
		asJSON()
		_, _ = w.Write([]byte(hostileDoc(r.URL.Path, 6*1024)))
	case "/endless": // never stops writing
		asJSON()
		w.WriteHeader(200)
		chunk := bytes.Repeat([]byte("x"), 4096)
		for {
			if _, err := w.Write(chunk); err != nil {
				h.ended <- r.URL.Path
				return
			}
			w.(http.Flusher).Flush()
		}
	case "/bomb": // 256 MB of JSON whitespace in a few hundred KB of gzip
		asJSON()
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
		gz := gzip.NewWriter(w)
		blank := bytes.Repeat([]byte(" "), 1<<20)
		_, _ = gz.Write([]byte(`{"padding":"`))
		for range 256 {
			if _, err := gz.Write(blank); err != nil {
				h.ended <- r.URL.Path
				return
			}
			if f, ok := w.(http.Flusher); ok {
				_ = gz.Flush()
				f.Flush()
			}
		}
		_ = gz.Close()
		h.ended <- r.URL.Path
	case "/html": // right bytes, wrong media type
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(hostileDoc(r.URL.Path, 0)))
	case "/slow-headers": // no answer within the fetch timeout
		select {
		case <-time.After(config.ClientMetadataTimeout + 5*time.Second):
		case <-r.Context().Done():
			h.ended <- r.URL.Path
			return
		}
	case "/slowloris": // headers at once, then a byte every 200 ms
		asJSON()
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		body := hostileDoc(r.URL.Path, 0)
		for i := 0; i < len(body); i++ {
			select {
			case <-r.Context().Done():
				h.ended <- r.URL.Path
				return
			case <-time.After(200 * time.Millisecond):
			}
			if _, err := w.Write([]byte{body[i]}); err != nil {
				h.ended <- r.URL.Path
				return
			}
			w.(http.Flusher).Flush()
		}
	default:
		http.NotFound(w, r)
	}
}

// TestHostileMetadataHost: a client_id whose host misbehaves (a real HTTPS
// server, read by the production fetcher) ends in a page within the fetch
// timeout — never a row, an event, a redirect or an unbounded read — and a
// bad answer is remembered so the host is not asked again at once. A
// document that changes its redirect_uris after approval is
// TestExternalClientApprovalBoundToMetadata; names that resolve to private
// addresses are TestGuardedDialerRefusesPrivateResolution.
func TestHostileMetadataHost(t *testing.T) {
	host := newHostileHost(t)
	e := newEnvWith(t, func(s *server.Server) { s.RateLimitPerMinute = 100000 })
	e.mcpServer(fiber.Map{})
	e.CIMD.Set(host.transport())
	rowsBefore := e.count(`SELECT count(*) FROM oauth_clients`)
	eventsBefore := e.count(`SELECT count(*) FROM events`)

	// Cache-Control: no-store is held to the minimum TTL: two requests, one
	// read, and the document is good for authorizing.
	for range 2 {
		if p := e.anonymousAuthorize(hostile+"/no-store", loopback); p.Status != 303 {
			t.Fatalf("no-store document: %d %s", p.Status, p.Body)
		}
	}
	if n := host.Hits("/no-store"); n != 1 {
		t.Fatalf("no-store document read %d times by two requests, want 1 (cached at least %s)", n, config.ClientMetadataMinTTL)
	}

	// Each misbehavior: a page that says why, in time, remembered. The slow
	// ones run together so the test lasts one timeout.
	cases := []struct{ path, want string }{
		{"/redirect", "answered 302"},
		{"/big", "larger than 5 KB"},
		{"/endless", "larger than 5 KB"},
		{"/bomb", "larger than 5 KB"},
		{"/html", "not served as application/json"},
		{"/slow-headers", "timed out"},
		{"/slowloris", "timed out"},
		{"/missing", "answered 404"},
	}
	type outcome struct {
		page page
		took time.Duration
	}
	results := make([]outcome, len(cases))
	var wg sync.WaitGroup
	for i, c := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			p := e.anonymousAuthorize(hostile+c.path, loopback)
			results[i] = outcome{p, time.Since(start)}
		}()
	}
	wg.Wait()
	for i, c := range cases {
		p, took := results[i].page, results[i].took
		if p.Status != 400 || p.Location != "" || !strings.Contains(p.Body, c.want) {
			t.Errorf("%s: %d %q, want a 400 page saying %q\n%.2000s", c.path, p.Status, p.Location, c.want, p.Body)
		}
		if limit := config.ClientMetadataTimeout + 2*time.Second; took > limit {
			t.Errorf("%s took %s, want under %s", c.path, took, limit)
		}
	}
	if n := host.Hits("/redirected"); n != 0 {
		t.Errorf("a redirect was followed (%d reads of its target)", n)
	}
	// The server saw each endless or dripping read cut off by the client.
	for _, path := range []string{"/endless", "/bomb", "/slow-headers", "/slowloris"} {
		select {
		case got := <-host.ended:
			_ = got
		case <-time.After(5 * time.Second):
			t.Errorf("%s: the host never saw the client give up", path)
		}
	}
	// A bad answer is remembered: asking again does not ask the host again.
	for _, c := range cases {
		before := host.Hits(c.path)
		p := e.anonymousAuthorize(hostile+c.path, loopback)
		if p.Status != 400 || !strings.Contains(p.Body, c.want) || host.Hits(c.path) != before {
			t.Errorf("%s again: %d, hits %d -> %d (want the remembered refusal)", c.path, p.Status, before, host.Hits(c.path))
		}
	}
	if rows, events := e.count(`SELECT count(*) FROM oauth_clients`), e.count(`SELECT count(*) FROM events`); rows != rowsBefore || events != eventsBefore {
		t.Fatalf("hostile documents left %d rows and %d events", rows-rowsBefore, events-eventsBefore)
	}
}

// dnsServer answers A and AAAA queries from names (host → addresses) over
// UDP on loopback, so a resolver can be pointed at it.
func dnsServer(t *testing.T, names map[string][]string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var in dnsmessage.Message
			if in.Unpack(buf[:n]) != nil || len(in.Questions) != 1 {
				continue
			}
			q := in.Questions[0]
			out := dnsmessage.Message{Header: dnsmessage.Header{ID: in.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: in.Questions}
			for _, text := range names[strings.TrimSuffix(q.Name.String(), ".")] {
				ip := net.ParseIP(text)
				h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 1}
				switch {
				case q.Type == dnsmessage.TypeA && ip.To4() != nil:
					h.Type = dnsmessage.TypeA
					var a [4]byte
					copy(a[:], ip.To4())
					out.Answers = append(out.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: a}})
				case q.Type == dnsmessage.TypeAAAA && ip.To4() == nil:
					h.Type = dnsmessage.TypeAAAA
					var a [16]byte
					copy(a[:], ip.To16())
					out.Answers = append(out.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: a}})
				}
			}
			if raw, err := out.Pack(); err == nil {
				_, _ = conn.WriteTo(raw, from)
			}
		}
	}()
	return conn.LocalAddr().String()
}

// TestGuardedDialerRefusesPrivateResolution: a client_id whose name resolves
// (here through a real DNS server) to a loopback, private, link-local or
// metadata address is refused at connect time by the production guarded
// dialer — also when the name has a public address too, and with a real
// server listening at the private address. The guarded dialer is wired as
// the production transport is (netx.Guarded); only its resolver is pointed
// at the test's DNS.
func TestGuardedDialerRefusesPrivateResolution(t *testing.T) {
	// A server on loopback that must never be reached.
	var reached sync.Mutex
	reachedCount := 0
	secret := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Lock()
		reachedCount++
		reached.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(secret.Close)

	names := map[string][]string{
		"loopback.rebind.example":  {"127.0.0.1"},
		"private.rebind.example":   {"10.0.0.5"},
		"linklocal.rebind.example": {"169.254.169.254"},
		"lan.rebind.example":       {"192.168.1.10"},
		"v6.rebind.example":        {"::1"},
		"mapped.rebind.example":    {"::ffff:127.0.0.1"},
		"cgnat.rebind.example":     {"100.64.0.1"},
		// Public and private together: the dial tries them in turn and
		// must not end up on the private one (the public one is reserved
		// TEST-NET, also refused).
		"mixed.rebind.example": {"203.0.113.7", "127.0.0.1"},
	}
	dns := dnsServer(t, names)
	dialer := netx.GuardedDialer()
	dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dns)
	}}
	e := newEnvWith(t, func(s *server.Server) { s.RateLimitPerMinute = 100000 })
	e.mcpServer(fiber.Map{})
	e.CIMD.Set(&http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: config.ExternalHTTPTimeout, ResponseHeaderTimeout: config.ExternalHTTPTimeout})

	for name := range names {
		start := time.Now()
		p := e.anonymousAuthorize("https://"+name+"/client.json", loopback)
		if p.Status != 400 || p.Location != "" || !strings.Contains(p.Body, "does not resolve to a public address") {
			t.Errorf("%s: %d %q\n%.1500s", name, p.Status, p.Location, p.Body)
		}
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("%s took %s", name, took)
		}
		// The page never names the address.
		for _, leak := range []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.10", "100.64.0.1"} {
			if strings.Contains(p.Body, leak) {
				t.Errorf("%s: the page shows %s", name, leak)
			}
		}
	}
	reached.Lock()
	defer reached.Unlock()
	if reachedCount != 0 {
		t.Fatalf("the server on loopback was reached %d times", reachedCount)
	}
	if n := e.count(`SELECT count(*) FROM oauth_clients WHERE source='cimd'`); n != 0 {
		t.Fatalf("%d clients were stored", n)
	}
}
