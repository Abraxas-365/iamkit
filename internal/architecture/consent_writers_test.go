package architecture_test

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"testing"
)

// consentWriters are the functions that may write oauth_consents and
// oauth_client_grants (D32). Consents and administrator grants are records:
// a user's decision or an operator's grant is inserted (or widened/replaced
// by its upsert), revoked once, and deleted only by the prune job long after
// it was revoked. So an UPDATE of either table must revoke live rows (set
// revoked_at, WHERE revoked_at IS NULL): a revoked row is never edited or
// revived. A DELETE must be limited to revoked rows. Keys are
// "<dir without iam/> <func>".
var consentWriters = map[string]bool{
	"oauth/adapters/oauthpg recordConsent":                  true,
	"oauth/adapters/oauthpg revokeConsents":                 true,
	"oauth/adapters/oauthpg revokeClientConsents":           true,
	"oauth/adapters/oauthpg (*Consents).SaveClientGrant":    true,
	"oauth/adapters/oauthpg (*Consents).RevokeClientGrant":  true,
	"oauth/adapters/oauthpg revokeServerGrants":             true,
	"oauth/adapters/oauthpg (*Consents).ExpireClientGrants": true,
	"oauth/adapters/oauthpg (*Consents).PruneConsents":      true,
}

var (
	consentWrite    = regexp.MustCompile(`(?is)\b(insert\s+into|update|delete\s+from)\s+(oauth_consents|oauth_client_grants)\b`)
	consentUpdate   = regexp.MustCompile(`(?is)\bupdate\s+(?:oauth_consents|oauth_client_grants)\b(?:\s+\w+)?\s+set\s+(.*?)(?:\bwhere\b(.*))?$`)
	consentDelete   = regexp.MustCompile(`(?is)\bdelete\s+from\s+(?:oauth_consents|oauth_client_grants)\b(.*)$`)
	setsRevokedAt   = regexp.MustCompile(`(?is)(^|,)\s*revoked_at\s*=\s*now\(\)`)
	onlyLiveRows    = regexp.MustCompile(`(?is)\brevoked_at\s+is\s+null\b`)
	onlyRevokedRows = regexp.MustCompile(`(?is)\brevoked_at\s+is\s+not\s+null\b`)
)

func consentWriteViolations(files []goFile, writers map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range files {
		dir := dirOf(f.rel)
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := dir + " " + funcKey(fn)
			seen[key] = true
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				sql, err := strconv.Unquote(lit.Value)
				if err != nil || !consentWrite.MatchString(sql) {
					return true
				}
				where := fmt.Sprintf("%s:%d", f.rel, f.fset.Position(lit.Pos()).Line)
				if !writers[key] {
					out = append(out, fmt.Sprintf("%s: %s writes consents or administrator grants; only the consent writers may (consentWriters)", where, funcKey(fn)))
					return true
				}
				if m := consentUpdate.FindStringSubmatch(sql); m != nil && (!setsRevokedAt.MatchString(m[1]) || !onlyLiveRows.MatchString(m[2])) {
					out = append(out, fmt.Sprintf("%s: %s updates a consent or grant other than revoking live rows; they are records (D32)", where, funcKey(fn)))
				}
				if m := consentDelete.FindStringSubmatch(sql); m != nil && !onlyRevokedRows.MatchString(m[1]) {
					out = append(out, fmt.Sprintf("%s: %s deletes consents or grants that may be live; only revoked records are pruned (D32)", where, funcKey(fn)))
				}
				return true
			})
		}
	}
	for key := range writers {
		if !seen[key] {
			out = append(out, fmt.Sprintf("%s: function not found (update consentWriters when it moves)", key))
		}
	}
	sort.Strings(out)
	return out
}

func TestConsentsAreRecords(t *testing.T) {
	report(t, consentWriteViolations(sources(t, false), consentWriters))
}

func TestConsentLintCatchesViolations(t *testing.T) {
	files := parseFixtures(t, map[string]string{
		"oauth/adapters/oauthpg/consent.go": "package oauthpg\n" +
			"func recordConsent() { exec(`INSERT INTO oauth_consents(id) VALUES($1) ON CONFLICT DO UPDATE SET scopes=EXCLUDED.scopes`) }\n" +
			"func revokeConsents() { exec(`UPDATE oauth_consents c SET revoked_at=now(), revoked_reason=$2 WHERE c.revoked_at IS NULL`) }\n" +
			"func revive() { exec(`UPDATE oauth_consents SET revoked_at=NULL WHERE id=$1`) }\n" +
			"func (r *Consents) RevokeClientGrant() { exec(`UPDATE oauth_client_grants SET scopes=$2 WHERE id=$1`) }\n" +
			"func (r *Consents) PruneConsents() { exec(`DELETE FROM oauth_client_grants WHERE created_at<$1`) }\n" +
			"func (r *Consents) Agreed() { get(`SELECT id FROM oauth_consents WHERE revoked_at IS NULL FOR NO KEY UPDATE OF oauth_consents`) }\n",
		"billing/adapters/billingpg/x.go": "package billingpg\n" +
			"func purge() { exec(`DELETE FROM oauth_consents WHERE revoked_at IS NOT NULL`) }\n",
	})
	expectViolations(t, consentWriteViolations(files, map[string]bool{
		"oauth/adapters/oauthpg recordConsent":                 true,
		"oauth/adapters/oauthpg revokeConsents":                true,
		"oauth/adapters/oauthpg (*Consents).RevokeClientGrant": true,
		"oauth/adapters/oauthpg (*Consents).PruneConsents":     true,
		"oauth/adapters/oauthpg (*Consents).Gone":              true,
	}),
		"billing/adapters/billingpg/x.go:2: purge writes consents or administrator grants; only the consent writers may (consentWriters)",
		"oauth/adapters/oauthpg (*Consents).Gone: function not found (update consentWriters when it moves)",
		"oauth/adapters/oauthpg/consent.go:4: revive writes consents or administrator grants; only the consent writers may (consentWriters)",
		"oauth/adapters/oauthpg/consent.go:5: (*Consents).RevokeClientGrant updates a consent or grant other than revoking live rows; they are records (D32)",
		"oauth/adapters/oauthpg/consent.go:6: (*Consents).PruneConsents deletes consents or grants that may be live; only revoked records are pruned (D32)",
	)
}
