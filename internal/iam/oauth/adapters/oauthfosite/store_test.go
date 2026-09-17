package oauthfosite

import (
	"github.com/ory/fosite"
	"testing"
)

func TestDecodeDoesNotOverwriteIssuanceSession(t *testing.T) {
	client := &fosite.DefaultClient{ID: "client"}
	saved := NewSession()
	saved.AccessClaims.Extra = map[string]interface{}{"permissions": []string{"read", "write"}}
	data, err := encodeRequest(&fosite.Request{ID: "request", Client: client, Session: saved})
	if err != nil {
		t.Fatal(err)
	}
	live := NewSession()
	live.AccessClaims.Extra = map[string]interface{}{"permissions": []string{"read"}}
	decoded, err := decodeRequest(data, client, live)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.GetSession() == live {
		t.Fatal("storage reused caller session")
	}
	permissions := live.AccessClaims.Extra["permissions"].([]string)
	if len(permissions) != 1 || permissions[0] != "read" {
		t.Fatal("storage overwrote current permissions")
	}
}
