package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDeviceGrant(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("client_id") != "tv" {
			t.Errorf("form = %v", r.Form)
		}
		switch r.URL.Path {
		case "/oauth/device_authorization":
			if r.Form.Get("scope") != "openid offline_access" {
				t.Errorf("scope = %q", r.Form.Get("scope"))
			}
			json.NewEncoder(w).Encode(map[string]any{"device_code": "ik_device_x", "user_code": "BCDF-GHJK", "verification_uri": "https://id.example/hosted/device", "verification_uri_complete": "https://id.example/hosted/device?user_code=BCDF-GHJK", "expires_in": 600, "interval": 0})
		case "/oauth/token":
			if r.Form.Get("grant_type") != DeviceGrantType || r.Form.Get("device_code") != "ik_device_x" {
				t.Errorf("poll form = %v", r.Form)
			}
			polls++
			if polls < 3 {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(map[string]any{"error": map[int]string{1: DeviceAuthorizationPending, 2: DeviceSlowDown}[polls]})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "bearer", "id_token": "idt"})
		}
	}))
	defer srv.Close()
	c := NewOAuth(srv.URL, "tv", "")
	auth, err := c.AuthorizeDevice(context.Background(), "openid", "offline_access")
	if err != nil || auth.UserCode != "BCDF-GHJK" || auth.DeviceCode != "ik_device_x" {
		t.Fatalf("AuthorizeDevice = %+v, %v", auth, err)
	}
	if _, err = c.PollDevice(context.Background(), auth.DeviceCode); err == nil || err.(*OAuthError).Code != DeviceAuthorizationPending {
		t.Fatalf("PollDevice = %v", err)
	}
	// WaitDevice keeps polling through pending and slow_down.
	polls = 1
	auth.Interval = 0
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	tokens, err := waitFast(ctx, c, auth)
	if err != nil || tokens.AccessToken != "at" || tokens.IDToken != "idt" || polls != 3 {
		t.Fatalf("WaitDevice = %+v, %v (polls %d, %s)", tokens, err, polls, time.Since(start))
	}
	// Denial ends the wait.
	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]any{"error": DeviceAccessDenied})
	}))
	defer denied.Close()
	var failure *OAuthError
	if _, err = waitFast(ctx, NewOAuth(denied.URL, "tv", ""), auth); !errors.As(err, &failure) || failure.Code != DeviceAccessDenied {
		t.Fatalf("denied = %v", err)
	}
}

// waitFast runs WaitDevice with its timers shortened for the test.
func waitFast(ctx context.Context, c *OAuthClient, auth DeviceAuthorization) (OAuthTokens, error) {
	deviceStep = time.Millisecond
	defer func() { deviceStep = time.Second }()
	return c.WaitDevice(ctx, auth)
}
