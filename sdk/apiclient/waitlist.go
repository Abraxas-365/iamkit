package apiclient

import "context"

// WaitlistEntries reads one page of the sign-up waitlist; requires
// iam:waitlist:read, like WaitlistEntry.
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

func (e Environment) WaitlistEntry(ctx context.Context, id string) (WaitlistEntry, error) {
	var out WaitlistEntry
	err := e.operation(ctx, "GET", []string{"waitlist", id}, nil, &out)
	return out, err
}

// ApproveWaitlistEntry needs iam:waitlist:write, like every change below.
// It emails the person their sign-up link.
func (e Environment) ApproveWaitlistEntry(ctx context.Context, id string) (WaitlistEntry, error) {
	var out WaitlistEntry
	err := e.operation(ctx, "POST", []string{"waitlist", id, "approve"}, map[string]any{}, &out)
	return out, err
}

// ApproveWaitlist approves several entries, or every pending one.
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
