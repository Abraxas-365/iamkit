package identity

import "strings"

// APIKeyPrefix starts every API key value (user, organization and machine
// user keys alike).
const APIKeyPrefix = "ik_key_"

// IsAPIKey reports whether raw has the API key shape (it says nothing about
// whether the key exists).
func IsAPIKey(raw string) bool { return strings.HasPrefix(raw, APIKeyPrefix) }

// APIKeyLast4 is the last four characters of an API key value, kept to show
// it obfuscated.
func APIKeyLast4(raw string) string {
	if len(raw) < 4 {
		return ""
	}
	return raw[len(raw)-4:]
}

// ObfuscatedAPIKey is how an API key is shown after creation:
// ik_key_…<last4>.
func ObfuscatedAPIKey(last4 string) string { return APIKeyPrefix + "…" + last4 }
