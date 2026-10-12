package iamclient

import (
	"context"
	"net/url"
	"time"
)

// Waitlist entry statuses.
const (
	WaitlistStatusPending   = "pending"
	WaitlistStatusApproved  = "approved"
	WaitlistStatusRejected  = "rejected"
	WaitlistStatusCompleted = "completed"
)

// WaitlistEntry is a person waiting to sign up. With the sign-in policy's
// Waitlist on, authclient.Signup lists the address as pending instead of
// sending a code; an approval emails a single-use sign-up link.
type WaitlistEntry struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Locale        string `json:"locale"`
	// Status is pending, approved, rejected or completed.
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	DecidedAt *time.Time `json:"decided_at"`
	DecidedBy string     `json:"decided_by"`
	// ExpiresAt is when the approval link stops working.
	ExpiresAt *time.Time `json:"expires_at"`
	// CompletedUserID is the account created from the approval.
	CompletedUserID string `json:"completed_user_id"`
}

// WaitlistFilter narrows WaitlistEntries: Status (empty: all) and Email,
// a prefix.
type WaitlistFilter struct {
	Status string
	Email  string
}

// Query encodes the filter as query parameters.
func (f WaitlistFilter) Query() url.Values {
	q := url.Values{}
	if f.Status != "" {
		q.Set("status", f.Status)
	}
	if f.Email != "" {
		q.Set("email", f.Email)
	}
	return q
}

// WaitlistList is one page of entries, newest first.
type WaitlistList struct {
	Items []WaitlistEntry `json:"items"`
	Page  Paging          `json:"page"`
}

// WaitlistApproval selects entries to approve: IDs, or every pending one
// with AllPending (oldest first, at most 500 per call).
type WaitlistApproval struct {
	IDs        []string `json:"ids,omitempty"`
	AllPending bool     `json:"all_pending,omitempty"`
}

// WaitlistApproved is the outcome of a bulk approval. Skipped entries
// were not pending or approved. When More is true, call again with
// AllPending to continue.
type WaitlistApproved struct {
	Approved int  `json:"approved"`
	Skipped  int  `json:"skipped"`
	More     bool `json:"more"`
}

// WaitlistEntries reads one page of the environment's waitlist.
func (e Environment) WaitlistEntries(ctx context.Context, filter WaitlistFilter, page Page) (WaitlistList, error) {
	var out WaitlistList
	if err := e.client.do(ctx, "GET", e.path("waitlist"), page.Query(filter.Query()), nil, &out); err != nil {
		return WaitlistList{}, err
	}
	if out.Items == nil {
		out.Items = []WaitlistEntry{}
	}
	return out, nil
}

// WaitlistEntry reads one entry.
func (e Environment) WaitlistEntry(ctx context.Context, id string) (WaitlistEntry, error) {
	var out WaitlistEntry
	err := e.operation(ctx, "GET", []string{"waitlist", id}, nil, &out)
	return out, err
}

// ApproveWaitlistEntry approves a pending (or approved: a new link) entry
// and emails the person. 409 WAITLIST_ENTRY_NOT_PENDING for a decided one.
func (e Environment) ApproveWaitlistEntry(ctx context.Context, id string) (WaitlistEntry, error) {
	var out WaitlistEntry
	err := e.operation(ctx, "POST", []string{"waitlist", id, "approve"}, map[string]any{}, &out)
	return out, err
}

// ApproveWaitlist approves several entries (or every pending one).
func (e Environment) ApproveWaitlist(ctx context.Context, input WaitlistApproval) (WaitlistApproved, error) {
	var out WaitlistApproved
	err := e.operation(ctx, "POST", []string{"waitlist", "approve"}, input, &out)
	return out, err
}

// RejectWaitlistEntry rejects an entry; notify also emails the person.
func (e Environment) RejectWaitlistEntry(ctx context.Context, id string, notify bool) (WaitlistEntry, error) {
	var out WaitlistEntry
	err := e.operation(ctx, "POST", []string{"waitlist", id, "reject"}, map[string]any{"notify": notify}, &out)
	return out, err
}

// DeleteWaitlistEntry removes an entry, so its email can join again.
func (e Environment) DeleteWaitlistEntry(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"waitlist", id}, nil, nil)
}
