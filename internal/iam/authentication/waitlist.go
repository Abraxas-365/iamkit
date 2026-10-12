package authentication

import (
	"net/url"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Waitlist entry statuses.
const (
	WaitlistPending   = "pending"
	WaitlistApproved  = "approved"
	WaitlistRejected  = "rejected"
	WaitlistCompleted = "completed"
)

// WaitlistStatuses lists the statuses, in lifecycle order.
var WaitlistStatuses = []string{WaitlistPending, WaitlistApproved, WaitlistRejected, WaitlistCompleted}

// WaitlistTokenPrefix starts every approval token.
const WaitlistTokenPrefix = "ik_wait_"

// maxWaitlistToken bounds a presented token before it is hashed.
const maxWaitlistToken = 200

// Audited actions of the waitlist.
const (
	ActionWaitlistApprove = "waitlist.approve"
	ActionWaitlistReject  = "waitlist.reject"
	ActionWaitlistDelete  = "waitlist.delete"
)

// Error codes of the waitlist.
const (
	CodeWaitlistNotPending = "WAITLIST_ENTRY_NOT_PENDING"
	CodeWaitlistToken      = "WAITLIST_TOKEN_INVALID"
)

// ErrWaitlistNotDecidable answers a decision on an entry that is already
// finished (rejected or completed).
func ErrWaitlistNotDecidable() error {
	e := errx.Conflict("the waitlist entry is already rejected or completed")
	e.Code = CodeWaitlistNotPending
	return e
}

// ErrWaitlistToken refuses a sign-up whose waitlist approval is not valid
// (anymore): unknown, expired, used, or for another email.
func ErrWaitlistToken() error {
	e := errx.Validation("the waitlist link is not valid; ask to join the waitlist again")
	e.Code = CodeWaitlistToken
	return e
}

// WaitlistEntry is a person waiting for an operator to let them sign up.
// The token (an ik_wait_ secret) is only ever sent by email.
type WaitlistEntry struct {
	ID          identity.WaitlistEntryID `json:"id" db:"id"`
	Environment identity.EnvironmentID   `json:"environment_id" db:"environment_id"`
	Email       string                   `json:"email" db:"email"`
	Name        string                   `json:"name" db:"name"`
	Locale      string                   `json:"locale" db:"locale"`
	// Status is pending, approved, rejected or completed.
	Status    string    `json:"status" db:"status"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	// DecidedAt and DecidedBy tell when and who approved or rejected.
	DecidedAt *time.Time `json:"decided_at" db:"decided_at"`
	DecidedBy string     `json:"decided_by" db:"decided_by"`
	// ExpiresAt ends an approval: the link stops working after it.
	ExpiresAt *time.Time `json:"expires_at" db:"expires_at"`
	// CompletedUser is the account the sign-up created.
	CompletedUser identity.UserID `json:"completed_user_id" db:"completed_user_id"`
}

// WaitlistFilter narrows a waitlist listing.
type WaitlistFilter struct {
	// Status is one of WaitlistStatuses; empty lists every status.
	Status string
	// Email matches the start of the address (case-insensitive).
	Email string
}

func (f WaitlistFilter) Validate() error {
	if f.Status != "" && !validWaitlistStatus(f.Status) {
		return errx.Validation("status must be pending, approved, rejected or completed")
	}
	if len(f.Email) > 320 {
		return errx.Validation("email filter is too long")
	}
	return nil
}

func validWaitlistStatus(s string) bool {
	for _, v := range WaitlistStatuses {
		if v == s {
			return true
		}
	}
	return false
}

// WaitlistApprove selects the entries a bulk approval decides: the listed
// ids or every pending entry (oldest first). One call decides at most
// config.WaitlistMaxApprove entries; repeat it for more.
type WaitlistApprove struct {
	IDs        []identity.WaitlistEntryID `json:"ids"`
	AllPending bool                       `json:"all_pending"`
}

func (a WaitlistApprove) Validate() error {
	switch {
	case a.AllPending && len(a.IDs) > 0:
		return errx.Validation("use ids or all_pending, not both")
	case !a.AllPending && len(a.IDs) == 0:
		return errx.Validation("ids or all_pending is required")
	case len(a.IDs) > config.WaitlistMaxApprove:
		return errx.Validation("ids must have at most 500 entries")
	}
	for _, id := range a.IDs {
		if id.IsZero() {
			return errx.Validation("ids must be valid UUIDs")
		}
	}
	return nil
}

// WaitlistRejection is the choice of a rejection: Notify emails the person
// (waitlist_rejected); by default a rejection is silent.
type WaitlistRejection struct {
	Notify bool `json:"notify"`
}

func (WaitlistRejection) Validate() error { return nil }

// WaitlistBulkResult is the result of a bulk approval.
type WaitlistBulkResult struct {
	// Approved counts the entries approved (and emailed); Skipped those
	// that could not be (decided meanwhile or failing).
	Approved int `json:"approved"`
	Skipped  int `json:"skipped"`
	// More is true when pending entries remain beyond this call's cap.
	More bool `json:"more"`
}

// WaitlistJoin is a person asking to join the waitlist.
type WaitlistJoin struct {
	ID          identity.WaitlistEntryID
	Environment identity.EnvironmentID
	Email       string
	Name        string
	Locale      string
}

// WaitlistApproval decides an entry: the token's hash and its end.
type WaitlistApproval struct {
	ID        identity.WaitlistEntryID
	TokenHash []byte
	ExpiresAt time.Time
}

// WaitlistToken is what a presented approval token resolves to.
type WaitlistToken struct {
	ID    identity.WaitlistEntryID
	Email string
}

// WaitlistTokenShape reports whether raw can be an approval token.
func WaitlistTokenShape(raw string) bool {
	return strings.HasPrefix(raw, WaitlistTokenPrefix) && len(raw) <= maxWaitlistToken
}

// WaitlistLink appends the approval token to the sign-up page base.
func WaitlistLink(base, token string) string {
	u, err := url.Parse(base)
	if base == "" || err != nil {
		return ""
	}
	q := u.Query()
	q.Set("waitlist", token)
	u.RawQuery = q.Encode()
	return u.String()
}

// validWaitlistDomains checks a policy's auto-approve domains (each a valid
// domain, at most config.WaitlistMaxDomains).
func validWaitlistDomains(domains []string) error {
	if len(domains) > config.WaitlistMaxDomains {
		return errx.Validation("waitlist_auto_approve_domains must have at most 50 domains")
	}
	for _, d := range domains {
		if _, err := identity.Domain(d); err != nil {
			return errx.Validation("waitlist_auto_approve_domains: " + err.Error())
		}
	}
	return nil
}

// AutoApproves reports whether email belongs to one of the policy's
// auto-approve domains.
func (p SignInPolicy) AutoApproves(email string) bool {
	domain := identity.EmailDomain(email)
	if domain == "" {
		return false
	}
	for _, d := range p.WaitlistAutoApproveDomains {
		if v, err := identity.Domain(d); err == nil && v == domain {
			return true
		}
	}
	return false
}
