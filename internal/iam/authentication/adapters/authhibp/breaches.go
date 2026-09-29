// Package authhibp checks passwords against Have I Been Pwned's Pwned
// Passwords range API with k-anonymity: only the first five hex characters
// of the password's SHA-1 leave the server.
package authhibp

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

// Endpoint is the public range API.
const Endpoint = "https://api.pwnedpasswords.com/range/"

// Breaches implements authentication.Breaches.
type Breaches struct {
	// Endpoint overrides the range API (tests); "" uses Endpoint.
	Endpoint string
	// Transport overrides the HTTP transport (tests); nil uses the default.
	Transport http.RoundTripper
}

var _ authentication.Breaches = Breaches{}

func (b Breaches) Breached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]
	endpoint := b.Endpoint
	if endpoint == "" {
		endpoint = Endpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+prefix, nil)
	if err != nil {
		return false, errx.Wrap(err, "build breach request", errx.TypeInternal)
	}
	// Padding hides the true size of the response for the prefix.
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "IAMKit")
	res, err := (&http.Client{Transport: b.Transport}).Do(req)
	if err != nil {
		return false, errx.Wrap(err, "breach service unreachable", errx.TypeExternal)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false, errx.External("breach service answered " + res.Status)
	}
	lines := bufio.NewScanner(res.Body)
	for lines.Scan() {
		hash, count, ok := strings.Cut(strings.TrimSpace(lines.Text()), ":")
		// Padding entries have a count of 0.
		if ok && strings.EqualFold(hash, suffix) && count != "0" {
			return true, nil
		}
	}
	if err := lines.Err(); err != nil {
		return false, errx.Wrap(err, "read breach response", errx.TypeExternal)
	}
	return false, nil
}
