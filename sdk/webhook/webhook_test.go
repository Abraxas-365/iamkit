package webhook

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func header(id, timestamp, signature string) http.Header {
	h := http.Header{}
	h.Set("webhook-id", id)
	h.Set("webhook-timestamp", timestamp)
	h.Set("webhook-signature", signature)
	return h
}

// The Standard Webhooks reference vector.
func TestVerifyBodyVector(t *testing.T) {
	secret := "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	body := []byte(`{"test": 2432232314}`)
	now := time.Unix(1614265330, 0)
	ok := header("msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", "v1,bogus v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=")
	if err := VerifyBody(secret, ok, body, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBody(secret, ok, body, now.Add(10*time.Minute)); err != ErrTimestamp {
		t.Fatalf("stale: %v", err)
	}
	bad := header("msg_other", "1614265330", "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=")
	if err := VerifyBody(secret, bad, body, now); err != ErrSignature {
		t.Fatalf("tampered: %v", err)
	}
	if err := VerifyBody("nope!", ok, body, now); err != ErrSecret {
		t.Fatalf("secret: %v", err)
	}
}

func TestVerifyRejectsUnsigned(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"id":1}`))
	r.Header = header("msg_1", "0", "")
	if _, err := Verify("whsec_c2VjcmV0", r); err == nil {
		t.Fatal("unsigned request accepted")
	}
}
