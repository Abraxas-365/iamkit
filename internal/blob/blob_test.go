package blob

import (
	"strings"
	"testing"
)

func TestValidateKey(t *testing.T) {
	valid := []string{"a", "a/b.ndjson.gz", "logs/2026/10/11/09/stream-12.ndjson.gz"}
	invalid := []string{"", "/a", "a/", "a//b", "./a", "a/../b", "a\\b", "a\x00b", strings.Repeat("a", 1025)}
	for _, k := range valid {
		if err := ValidateKey(k); err != nil {
			t.Errorf("%q: unexpected error %v", k, err)
		}
	}
	for _, k := range invalid {
		if ValidateKey(k) == nil {
			t.Errorf("%q: want error", k)
		}
	}
}
