package provsvc

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/provisioning"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Groups serves SCIM /Groups for a provisioning connection.
type Groups struct{ repository provisioning.GroupRepository }

func NewGroups(r provisioning.GroupRepository) *Groups { return &Groups{r} }

var _ provisioning.GroupCommands = (*Groups)(nil)
var _ provisioning.GroupQueries = (*Groups)(nil)

func (s *Groups) CreateGroup(ctx context.Context, p provisioning.Principal, input provisioning.GroupInput) (identity.GroupID, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.External = strings.TrimSpace(input.External)
	if err := input.Validate(); err != nil {
		return identity.GroupID{}, err
	}
	input.Members = unique(input.Members)
	id := identity.NewGroupID()
	return id, s.repository.CreateGroup(ctx, p, id, input)
}

func (s *Groups) UpdateGroup(ctx context.Context, p provisioning.Principal, id identity.GroupID, input provisioning.GroupUpdate) error {
	if id.IsZero() {
		return errx.NotFound("group not found")
	}
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		input.Name = &name
	}
	if input.External != nil && strings.TrimSpace(*input.External) == "" {
		input.External = nil
	}
	if err := input.Validate(); err != nil {
		return err
	}
	if input.Members != nil {
		members := unique(*input.Members)
		input.Members = &members
	}
	input.Add, input.Remove = unique(input.Add), unique(input.Remove)
	return s.repository.UpdateGroup(ctx, p, id, input)
}

func (s *Groups) DeleteGroup(ctx context.Context, p provisioning.Principal, id identity.GroupID) error {
	if id.IsZero() {
		return errx.NotFound("group not found")
	}
	return s.repository.DeleteGroup(ctx, p, id)
}

func (s *Groups) FindGroup(ctx context.Context, p provisioning.Principal, id identity.GroupID, members bool) (provisioning.Group, error) {
	if id.IsZero() {
		return provisioning.Group{}, errx.NotFound("group not found")
	}
	return s.repository.FindGroup(ctx, p, id, members)
}

func (s *Groups) ListGroups(ctx context.Context, p provisioning.Principal, f provisioning.GroupFilter, page query.Pagination) (query.Paginated[provisioning.Group], error) {
	switch f.Field {
	case "", "displayName", "externalId":
	case "id":
		// id filters match only our own UUIDs; anything else matches nothing.
		if _, err := identity.ParseGroupID(f.Value); err != nil {
			return query.NewPaginated([]provisioning.Group{}, 0, page), nil
		}
	default:
		return query.Paginated[provisioning.Group]{}, errx.Validation("unsupported filter").WithDetail("scimType", "invalidFilter")
	}
	if page.Offset < 0 {
		page.Offset = 0
	}
	if page.Limit < 0 {
		page.Limit = 0
	}
	if page.Limit > provisioning.MaxResults {
		page.Limit = provisioning.MaxResults
	}
	return s.repository.ListGroups(ctx, p, f, page)
}

// unique drops duplicate and zero ids, keeping the first occurrence order.
func unique(ids []identity.UserID) []identity.UserID {
	out := make([]identity.UserID, 0, len(ids))
	seen := make(map[identity.UserID]bool, len(ids))
	for _, id := range ids {
		if id.IsZero() || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
