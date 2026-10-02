package action

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sign(secret, id, timestamp, body string) string {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "." + body))
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestVerifyAndWrite(t *testing.T) {
	secret := "whsec_c2VjcmV0LXNlY3JldC1zZWNyZXQ="
	body := `{"condition":"function:pre_sign_in","environment_id":"e1","organization_id":"o1","user":{"id":"u1","email":"ada@example.com"},"amr":["pwd"]}`
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("webhook-id", "msg_1")
	r.Header.Set("webhook-timestamp", timestamp)
	r.Header.Set("webhook-signature", sign(secret, "msg_1", timestamp, body))
	in, err := Verify(secret, r)
	if err != nil {
		t.Fatal(err)
	}
	if in.Condition != PreSignIn || in.User.Email != "ada@example.com" || in.OrganizationID != "o1" || in.AMR[0] != "pwd" {
		t.Fatalf("input = %+v", in)
	}

	w := httptest.NewRecorder()
	if err := Write(w, Deny("Blocked")); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || out["deny"] != true || out["message"] != "Blocked" || out["claims"] != nil {
		t.Fatalf("answer = %d %s", w.Code, w.Body)
	}

	tampered := httptest.NewRequest("POST", "/", strings.NewReader(strings.Replace(body, "ada", "eve", 1)))
	tampered.Header = r.Header
	if _, err := Verify(secret, tampered); err == nil {
		t.Fatal("tampered input accepted")
	}
}
