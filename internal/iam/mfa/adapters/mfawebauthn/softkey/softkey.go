// Package softkey is a software WebAuthn authenticator for tests: it
// answers registration options with a "none" attestation and assertion
// options with ES256 signatures, like a security key or passkey would.
// Stdlib only; never used by the server itself.
package softkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/url"
)

// Key is one credential on the authenticator.
type Key struct {
	ID     []byte
	Handle []byte // user handle (set at registration)
	RPID   string
	Count  uint32
	// Verified sets the user verification flag (a passkey's PIN or
	// biometric); Discoverable marks a passkey.
	Verified bool
	key      *ecdsa.PrivateKey
}

// Options is the part of the server's options the authenticator reads.
type Options struct {
	Challenge string `json:"challenge"`
	RPID      string `json:"rpId"`
	RP        struct {
		ID string `json:"id"`
	} `json:"rp"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
}

// Create answers registration options (the "options" of a begin response)
// for origin, returning the new key and the credential JSON to post.
func Create(options json.RawMessage, origin string, verified bool) (*Key, json.RawMessage, error) {
	var o Options
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, nil, err
	}
	rpID := o.RP.ID
	if rpID == "" {
		rpID = host(origin)
	}
	handle, err := decode(o.User.ID)
	if err != nil {
		return nil, nil, err
	}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return nil, nil, err
	}
	k := &Key{ID: id, Handle: handle, RPID: rpID, Verified: verified, key: pk}
	client, err := clientData("webauthn.create", o.Challenge, origin)
	if err != nil {
		return nil, nil, err
	}
	auth := k.authData(true)
	att := append([]byte{0xa3}, text("fmt")...)
	att = append(att, text("none")...)
	att = append(att, text("attStmt")...)
	att = append(att, 0xa0)
	att = append(att, text("authData")...)
	att = append(att, bytestr(auth)...)
	out, err := json.Marshal(map[string]any{
		"id": encode(id), "rawId": encode(id), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": encode(client), "attestationObject": encode(att), "transports": []string{"usb"},
		},
	})
	return k, out, err
}

// Get answers assertion options for origin with this key.
func (k *Key) Get(options json.RawMessage, origin string) (json.RawMessage, error) {
	var o Options
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	if k == nil || k.key == nil {
		return nil, errors.New("softkey: no key")
	}
	client, err := clientData("webauthn.get", o.Challenge, origin)
	if err != nil {
		return nil, err
	}
	k.Count++
	auth := k.authData(false)
	sum := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": encode(k.ID), "rawId": encode(k.ID), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": encode(client), "authenticatorData": encode(auth),
			"signature": encode(sig), "userHandle": encode(k.Handle),
		},
	})
}

func (k *Key) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(k.RPID))
	flags := byte(0x01) // user present
	if k.Verified {
		flags |= 0x04
	}
	if attested {
		flags |= 0x40
	}
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, k.Count)
	if !attested {
		return out
	}
	out = append(out, make([]byte, 16)...) // AAGUID
	out = binary.BigEndian.AppendUint16(out, uint16(len(k.ID)))
	out = append(out, k.ID...)
	x, y := make([]byte, 32), make([]byte, 32)
	k.key.X.FillBytes(x)
	k.key.Y.FillBytes(y)
	// COSE EC2 key {1:2, 3:-7, -1:1, -2:x, -3:y}, canonical order.
	out = append(out, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21)
	out = append(out, bytestr(x)...)
	out = append(out, 0x22)
	return append(out, bytestr(y)...)
}

func clientData(kind, challenge, origin string) ([]byte, error) {
	return json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
}

func host(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func text(s string) []byte { return append([]byte{0x60 | byte(len(s))}, s...) }

func bytestr(b []byte) []byte {
	switch {
	case len(b) < 24:
		return append([]byte{0x40 | byte(len(b))}, b...)
	case len(b) < 256:
		return append([]byte{0x58, byte(len(b))}, b...)
	default:
		return append([]byte{0x59, byte(len(b) >> 8), byte(len(b))}, b...)
	}
}

func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
