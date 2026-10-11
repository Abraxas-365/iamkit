package orgadmin_test

import (
	"slices"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestIntentPermissions(t *testing.T) {
	cases := map[string][]string{
		orgadmin.IntentSSO:        {authorization.PermOrgRead, authorization.PermOrgSSOWrite},
		orgadmin.IntentDirectory:  {authorization.PermOrgRead, authorization.PermOrgSSOWrite},
		orgadmin.IntentDomains:    {authorization.PermOrgDomainsWrite, authorization.PermOrgRead},
		orgadmin.IntentLogStreams: {authorization.PermOrgLogStreamsWrite, authorization.PermOrgRead},
	}
	for intent, want := range cases {
		got := orgadmin.IntentPermissions([]string{intent})
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %v want %v", intent, got, want)
		}
	}
	all := orgadmin.IntentPermissions(orgadmin.Intents)
	if len(all) != 4 || slices.Contains(all, authorization.PermOrgMembersRead) {
		t.Fatalf("all = %v", all)
	}
	if got := orgadmin.IntentPermissions([]string{"bogus"}); len(got) != 0 {
		t.Fatalf("unknown intent grants %v", got)
	}
}

func TestSetupLinkInput(t *testing.T) {
	ptr := func(s string) *string { return &s }
	for name, tc := range map[string]struct {
		in  orgadmin.SetupLinkInput
		ttl time.Duration
		ok  bool
	}{
		"default":   {orgadmin.SetupLinkInput{Intents: []string{"sso"}}, config.SetupLinkTTL, true},
		"explicit":  {orgadmin.SetupLinkInput{Intents: []string{"sso"}, ExpiresIn: ptr("48h")}, 48 * time.Hour, true},
		"max":       {orgadmin.SetupLinkInput{Intents: []string{"domains"}, ExpiresIn: ptr("720h")}, 720 * time.Hour, true},
		"too long":  {orgadmin.SetupLinkInput{Intents: []string{"sso"}, ExpiresIn: ptr("721h")}, 0, false},
		"too short": {orgadmin.SetupLinkInput{Intents: []string{"sso"}, ExpiresIn: ptr("1m")}, 0, false},
		"garbage":   {orgadmin.SetupLinkInput{Intents: []string{"sso"}, ExpiresIn: ptr("soon")}, 0, false},
		"no intent": {orgadmin.SetupLinkInput{}, 0, false},
		"unknown":   {orgadmin.SetupLinkInput{Intents: []string{"sso", "root"}}, 0, false},
	} {
		err := tc.in.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: Validate = %v", name, err)
			continue
		}
		if tc.ok {
			if ttl, _ := tc.in.TTL(); ttl != tc.ttl {
				t.Errorf("%s: ttl %v want %v", name, ttl, tc.ttl)
			}
		}
	}
	got := orgadmin.SetupLinkInput{Intents: []string{"domains", "sso", "domains"}}.Normalized()
	if !slices.Equal(got, []string{"sso", "domains"}) {
		t.Fatalf("normalized = %v", got)
	}
}

func TestPrincipalSetup(t *testing.T) {
	link := identity.NewSetupLinkID()
	p := orgadmin.Principal{SetupLink: link, Permissions: orgadmin.IntentPermissions(orgadmin.Intents)}
	if !p.Setup() || p.Actor() != link.String() || p.Owner() || p.RequireOwner() == nil || p.RequireAccount() == nil {
		t.Fatal("setup principal must act as the link and never be an owner")
	}
	user := identity.NewUserID()
	var perms []string
	for _, perm := range authorization.OrgPermissions {
		perms = append(perms, perm)
	}
	owner := orgadmin.Principal{User: user, Permissions: perms}
	if owner.Setup() || owner.Actor() != user.String() || !owner.Owner() || owner.RequireAccount() != nil {
		t.Fatal("owner principal")
	}
	partial := orgadmin.Principal{User: user, Permissions: perms[1:]}
	if partial.Owner() {
		t.Fatal("missing a permission must not be owner")
	}
}
