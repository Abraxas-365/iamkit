package scimclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// Group is a SCIM group of the credential's organization. Members are
// user IDs; a group read with excludedAttributes=members has nil Members.
type Group struct {
	Schemas     []string `json:"schemas,omitempty"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// Member is a group member: Value is the user ID.
type Member struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Type    string `json:"type,omitempty"`
}

// GroupList is a page of groups.
type GroupList = ListResponse[Group]

const groupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

func groupPath(id string) (string, error) {
	if !safeID(id) {
		return "", fmt.Errorf("invalid group ID")
	}
	return "/Groups/" + id, nil
}

func withoutMembers(exclude bool) url.Values {
	if exclude {
		return url.Values{"excludedAttributes": {"members"}}
	}
	return nil
}

// CreateGroup provisions a group with its members.
func (c *Client) CreateGroup(ctx context.Context, input Group) (Group, error) {
	if len(input.Schemas) == 0 {
		input.Schemas = []string{groupSchema}
	}
	var out Group
	err := c.request(ctx, "POST", "/Groups", input, &out)
	return out, err
}

// Group reads a group; excludeMembers leaves the member list out (large
// groups).
func (c *Client) Group(ctx context.Context, id string, excludeMembers bool) (Group, error) {
	var out Group
	path, err := groupPath(id)
	if err != nil {
		return out, err
	}
	err = c.request(ctx, "GET", path+listQuery("", 0, 0, withoutMembers(excludeMembers)), nil, &out)
	return out, err
}

// Groups lists groups matching filter (`displayName eq "…"`, externalId or
// id; "" for all). start is 1-based; count 0 uses the server's page size.
func (c *Client) Groups(ctx context.Context, filter string, start, count int, excludeMembers bool) (GroupList, error) {
	var out GroupList
	err := c.request(ctx, "GET", "/Groups"+listQuery(filter, start, count, withoutMembers(excludeMembers)), nil, &out)
	return out, err
}

// ReplaceGroup replaces the name and the whole member set (no Members
// empties the group); ExternalID changes only when set.
func (c *Client) ReplaceGroup(ctx context.Context, id string, input Group) (Group, error) {
	if len(input.Schemas) == 0 {
		input.Schemas = []string{groupSchema}
	}
	var out Group
	path, err := groupPath(id)
	if err != nil {
		return out, err
	}
	err = c.request(ctx, "PUT", path, input, &out)
	return out, err
}

// PatchGroup applies PatchOp operations (add/remove members, replace
// displayName or externalId). The server answers 204 without the group.
func (c *Client) PatchGroup(ctx context.Context, id string, operations []Operation) error {
	path, err := groupPath(id)
	if err != nil {
		return err
	}
	return c.request(ctx, "PATCH", path, map[string]any{"schemas": []string{patchSchema}, "Operations": operations}, nil)
}

// DeleteGroup removes a group.
func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	path, err := groupPath(id)
	if err != nil {
		return err
	}
	return c.request(ctx, "DELETE", path, nil, nil)
}

// ── Discovery (RFC 7644 §4) ──

// ServiceProviderConfig returns the server's SCIM capabilities.
func (c *Client) ServiceProviderConfig(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := c.request(ctx, "GET", "/ServiceProviderConfig", nil, &out)
	return out, err
}

// Schemas returns the schema definitions (User, Group, enterprise User).
func (c *Client) Schemas(ctx context.Context) (ListResponse[json.RawMessage], error) {
	var out ListResponse[json.RawMessage]
	err := c.request(ctx, "GET", "/Schemas", nil, &out)
	return out, err
}

// ResourceTypes returns the resource types (User, Group).
func (c *Client) ResourceTypes(ctx context.Context) (ListResponse[json.RawMessage], error) {
	var out ListResponse[json.RawMessage]
	err := c.request(ctx, "GET", "/ResourceTypes", nil, &out)
	return out, err
}
