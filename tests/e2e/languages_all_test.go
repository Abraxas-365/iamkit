package e2e_test

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/i18n"
)

// TestHostedEveryLanguage renders every previewable hosted page in every
// shipped language through the management preview: the page declares its
// language and direction, and no catalog key or broken placeholder shows.
// IAMKIT_LANGUAGE_SNAPSHOTS=<dir> also writes each page there, for the
// narrow-width overflow check (scripts/check_hosted_languages.js).
func TestHostedEveryLanguage(t *testing.T) {
	e := newEnv(t)
	// 23 languages × 12 pages outrun the per-minute management limit.
	e.Server.RateLimitPerMinute = 10000
	e.App = contracted(t, e.Server.App(), e.Server.WaitDeliveries)
	t.Cleanup(func() { e.App.Shutdown() })
	settings := e.Base + "/login-settings"
	listed := e.Must("GET", settings+"/locales", e.Owner, nil, 200).JSON["items"].([]any)
	if len(listed) != len(i18n.Codes()) {
		t.Fatalf("locales = %d, want %d", len(listed), len(i18n.Codes()))
	}
	snapshots := os.Getenv("IAMKIT_LANGUAGE_SNAPSHOTS")
	pages := []string{"identify", "password", "code", "reset", "organization", "mfa", "enroll", "recovery", "invite", "message", "signup", "signup-code"}
	for _, item := range listed {
		l := item.(map[string]any)
		code, dir := l["code"].(string), "ltr"
		if l["dir"] == "rtl" {
			dir = "rtl"
		}
		if code != "en" && code != "es" && l["beta"] != true {
			t.Errorf("%s: machine-drafted catalogs stay beta until reviewed", code)
		}
		for _, page := range pages {
			html := e.Must("GET", settings+"/preview?"+url.Values{"page": {page}, "locale": {code}}.Encode(), e.Owner, nil, 200).JSON["html"].(string)
			if !strings.Contains(html, `<html lang="`+code+`" dir="`+dir+`">`) {
				t.Errorf("%s/%s: lang/dir missing", code, page)
			}
			if strings.Contains(html, "hosted.") || strings.Contains(html, "%!") || strings.Contains(html, "{count}") {
				t.Errorf("%s/%s: untranslated key or broken placeholder", code, page)
			}
			if snapshots != "" {
				if err := os.WriteFile(filepath.Join(snapshots, code+"."+page+".html"), []byte(html), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
