package actionhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
)

// The Standard Webhooks reference vector (also sdk/webhook's).
func TestSignVector(t *testing.T) {
	got, err := Sign([]string{"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"}, "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", []byte(`{"test": 2432232314}`))
	if err != nil || got != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatalf("%q %v", got, err)
	}
	two, _ := Sign([]string{"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"}, "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", []byte(`{"test": 2432232314}`))
	if len(strings.Split(two, " ")) != 2 {
		t.Fatalf("one signature per secret: %q", two)
	}
	if _, err := Sign([]string{"whsec_!!"}, "id", "1", nil); err == nil {
		t.Fatal("malformed secret signed")
	}
}

func TestSecretsGenerate(t *testing.T) {
	s, err := Secrets{}.Generate()
	if err != nil || !strings.HasPrefix(s, action.SecretPrefix) || len(s) != len(action.SecretPrefix)+44 {
		t.Fatalf("%q %v", s, err)
	}
}

func outbound(url string) action.Outbound {
	secret, _ := Secrets{}.Generate()
	return action.Outbound{ID: "act_1", URL: url, Secrets: []string{secret}, Timeout: time.Second, Body: []byte(`{"condition":"function:pre_sign_in"}`)}
}

func TestCall(t *testing.T) {
	var headers http.Header
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = w.Write([]byte(`{"deny":true}`))
	}))
	defer server.Close()
	m := outbound(server.URL)
	answer := Caller{Transport: http.DefaultTransport}.Call(context.Background(), m)
	if !answer.OK() || string(answer.Body) != `{"deny":true}` {
		t.Fatalf("answer: %+v", answer)
	}
	want, _ := Sign(m.Secrets, m.ID, headers.Get("webhook-timestamp"), m.Body)
	if headers.Get("webhook-id") != "act_1" || headers.Get("webhook-signature") != want || body != string(m.Body) {
		t.Fatalf("request: %v %q", headers, body)
	}
}

func TestCallFailures(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()
	m := outbound(slow.URL)
	m.Timeout = 100 * time.Millisecond
	if a := (Caller{Transport: http.DefaultTransport}).Call(context.Background(), m); a.OK() || a.Error != "timed out" {
		t.Fatalf("slow: %+v", a)
	}

	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", config.ActionMaxResponse+1)))
	}))
	defer big.Close()
	if a := (Caller{Transport: http.DefaultTransport}).Call(context.Background(), outbound(big.URL)); a.OK() || a.Status != 200 || a.Error == "" {
		t.Fatalf("big: %+v", a)
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example", http.StatusFound)
	}))
	defer redirect.Close()
	if a := (Caller{Transport: http.DefaultTransport}).Call(context.Background(), outbound(redirect.URL)); a.OK() || a.Status != http.StatusFound {
		t.Fatalf("redirect followed: %+v", a)
	}

	// The guarded transport refuses loopback.
	if a := (Caller{}).Call(context.Background(), outbound(big.URL)); a.OK() || a.Error != "the URL does not resolve to a public address" {
		t.Fatalf("guarded: %+v", a)
	}
}
