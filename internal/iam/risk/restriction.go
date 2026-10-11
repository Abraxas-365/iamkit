package risk

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Restriction kinds.
const (
	// RestrictIP matches a client address in a CIDR (a single address is
	// stored as /32 or /128).
	RestrictIP = "ip"
	// RestrictCountry matches the client's GeoIP country (ISO 3166-1
	// alpha-2, upper case).
	RestrictCountry = "country"
	// RestrictEmailDomain matches the typed email's domain or a subdomain
	// of it (usernames never match).
	RestrictEmailDomain = "email_domain"
)

// RestrictionKinds lists the kinds, in display order.
var RestrictionKinds = []string{RestrictIP, RestrictCountry, RestrictEmailDomain}

// Restriction actions.
const (
	// Allow skips the detections for matching sign-ins (never the
	// CAPTCHA, never a deny).
	Allow = "allow"
	// Deny refuses matching sign-ins and signups before any credential is
	// checked (403 SIGN_IN_BLOCKED).
	Deny = "deny"
)

// MaxRestrictions caps the restrictions of one environment.
const MaxRestrictions = 1000

// Restriction is one allow or deny rule.
type Restriction struct {
	ID          identity.RestrictionID `json:"id"`
	Environment identity.EnvironmentID `json:"environment_id"`
	Kind        string                 `json:"kind"`
	Value       string                 `json:"value"`
	Action      string                 `json:"action"`
	Note        string                 `json:"note"`
	CreatedAt   time.Time              `json:"created_at"`
}

// NewRestriction creates a restriction.
type NewRestriction struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action string `json:"action"`
	Note   string `json:"note,omitempty"`
}

var (
	countryCode = regexp.MustCompile(`^[A-Z]{2}$`)
	domainName  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// Normalize canonicalizes the value: a CIDR in its masked form (a bare
// address becomes /32 or /128), an upper-case country, a lower-case
// domain. Values that do not parse are left for Validate.
func (in NewRestriction) Normalize() NewRestriction {
	in.Kind = strings.TrimSpace(in.Kind)
	in.Action = strings.TrimSpace(in.Action)
	in.Note = strings.TrimSpace(in.Note)
	v := strings.TrimSpace(in.Value)
	switch in.Kind {
	case RestrictIP:
		if p, err := netip.ParsePrefix(v); err == nil {
			// An IPv4-mapped prefix (::ffff:a.b.c.d/n) is its IPv4 prefix:
			// client addresses are unmapped before matching.
			if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
				p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
			}
			v = p.Masked().String()
		} else if a, err := netip.ParseAddr(v); err == nil {
			a = a.Unmap().WithZone("")
			v = netip.PrefixFrom(a, a.BitLen()).String()
		}
	case RestrictCountry:
		v = strings.ToUpper(v)
	case RestrictEmailDomain:
		v = strings.TrimPrefix(strings.ToLower(v), "@")
	}
	in.Value = v
	return in
}

// Validate checks a normalized restriction.
func (in NewRestriction) Validate() error {
	if in.Action != Allow && in.Action != Deny {
		return errx.Validation("action must be allow or deny")
	}
	if len([]rune(in.Note)) > 200 {
		return errx.Validation("note must be at most 200 characters")
	}
	switch in.Kind {
	case RestrictIP:
		if _, err := netip.ParsePrefix(in.Value); err != nil {
			return errx.Validation("value must be an IP address or CIDR")
		}
	case RestrictCountry:
		if !countryCode.MatchString(in.Value) {
			return errx.Validation("value must be an ISO 3166-1 alpha-2 country code")
		}
	case RestrictEmailDomain:
		if len(in.Value) > 253 || !domainName.MatchString(in.Value) {
			return errx.Validation("value must be a domain name")
		}
	default:
		return errx.Validation("kind must be ip, country or email_domain")
	}
	return nil
}

// Subject is what restrictions are matched against.
type Subject struct {
	IP      string
	Country string
	// Email is the typed login when it is an email address ("" for
	// usernames and passkeys).
	Email string
}

// Matches reports whether r applies to s.
func (r Restriction) Matches(s Subject) bool {
	switch r.Kind {
	case RestrictIP:
		p, err := netip.ParsePrefix(r.Value)
		if err != nil || s.IP == "" {
			return false
		}
		a, err := netip.ParseAddr(s.IP)
		return err == nil && p.Contains(a.Unmap())
	case RestrictCountry:
		return s.Country != "" && strings.EqualFold(s.Country, r.Value)
	case RestrictEmailDomain:
		// The domain follows the last @ (a quoted local part may hold one).
		at := strings.LastIndex(s.Email, "@")
		if at < 0 {
			return false
		}
		domain := strings.TrimSuffix(strings.ToLower(s.Email[at+1:]), ".")
		return domain == r.Value || strings.HasSuffix(domain, "."+r.Value)
	}
	return false
}

// Decide applies restrictions to s: a matching deny wins over any allow.
func Decide(restrictions []Restriction, s Subject) (denied, allowed bool, rule *Restriction) {
	for i, r := range restrictions {
		if !r.Matches(s) {
			continue
		}
		if r.Action == Deny {
			return true, false, &restrictions[i]
		}
		if !allowed {
			allowed, rule = true, &restrictions[i]
		}
	}
	return false, allowed, rule
}

// RestrictionFilter narrows a restriction list.
type RestrictionFilter struct {
	Kind   string
	Action string
}

// Validate checks the filter.
func (f RestrictionFilter) Validate() error {
	if f.Kind != "" && !slices.Contains(RestrictionKinds, f.Kind) {
		return errx.Validation("kind must be ip, country or email_domain")
	}
	if f.Action != "" && f.Action != Allow && f.Action != Deny {
		return errx.Validation("action must be allow or deny")
	}
	return nil
}

// CodeSignInBlocked is the code of ErrSignInBlocked.
const CodeSignInBlocked = "SIGN_IN_BLOCKED"

// ErrSignInBlocked refuses a sign-in a restriction or detection blocks.
// The same answer for known and unknown accounts.
func ErrSignInBlocked() error {
	e := errx.Forbidden("sign-in from here is not allowed; contact your administrator")
	e.Code = CodeSignInBlocked
	return e
}

// ErrTooManyRestrictions is returned past MaxRestrictions.
func ErrTooManyRestrictions() error {
	e := errx.Business("an environment has at most 1000 restrictions")
	e.Code = "RESTRICTION_LIMIT_REACHED"
	return e
}
