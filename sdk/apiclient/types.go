package apiclient

import "github.com/Abraxas-365/iamkit/sdk/iamclient"

// Data types of the environment routes. /api/v1 and /management/v1 answer
// the same shapes on every route they share, so they are iamclient's types.
type (
	AccessToken             = iamclient.AccessToken
	AddUserKey              = iamclient.AddUserKey
	Application             = iamclient.Application
	ApplicationPatch        = iamclient.ApplicationPatch
	ClientAuthentication    = iamclient.ClientAuthentication
	CreateAccessToken       = iamclient.CreateAccessToken
	CreateUser              = iamclient.CreateUser
	Created                 = iamclient.Created
	DNSRecord               = iamclient.DNSRecord
	DeliveryAttempt         = iamclient.DeliveryAttempt
	DeliveryConfig          = iamclient.DeliveryConfig
	DeliveryPreview         = iamclient.DeliveryPreview
	DeliveryStatus          = iamclient.DeliveryStatus
	Domain                  = iamclient.Domain
	EffectiveRole           = iamclient.EffectiveRole
	EmailCopy               = iamclient.EmailCopy
	EmailPreview            = iamclient.EmailPreview
	EmailTemplate           = iamclient.EmailTemplate
	EmailTemplateSummary    = iamclient.EmailTemplateSummary
	Event                   = iamclient.Event
	EventFilter             = iamclient.EventFilter
	EventPage               = iamclient.EventPage
	EventParty              = iamclient.EventParty
	Factor                  = iamclient.Factor
	Grant                   = iamclient.Grant
	Group                   = iamclient.Group
	GroupFilter             = iamclient.GroupFilter
	GroupInput              = iamclient.GroupInput
	GroupMember             = iamclient.GroupMember
	GroupPatch              = iamclient.GroupPatch
	GroupRoleAssignment     = iamclient.GroupRoleAssignment
	GroupRoleAssignmentView = iamclient.GroupRoleAssignmentView
	GroupRoleFilter         = iamclient.GroupRoleFilter
	Invitation              = iamclient.Invitation
	InvitationInput         = iamclient.InvitationInput
	IssuedAccessToken       = iamclient.IssuedAccessToken
	IssuedInvitation        = iamclient.IssuedInvitation
	IssuedUserKey           = iamclient.IssuedUserKey
	Locale                  = iamclient.Locale
	Member                  = iamclient.Member
	MemberPatch             = iamclient.MemberPatch
	MemberProfile           = iamclient.MemberProfile
	Membership              = iamclient.Membership
	OrgUnit                 = iamclient.OrgUnit
	Organization            = iamclient.Organization
	OrganizationPatch       = iamclient.OrganizationPatch
	Position                = iamclient.Position
	PositionAssignment      = iamclient.PositionAssignment
	ReportingMember         = iamclient.ReportingMember
	Resource                = iamclient.Resource
	ResourceAccess          = iamclient.ResourceAccess
	ResourceGrant           = iamclient.ResourceGrant
	ResourcePatch           = iamclient.ResourcePatch
	Role                    = iamclient.Role
	RoleAssignment          = iamclient.RoleAssignment
	RoleAssignmentView      = iamclient.RoleAssignmentView
	SMSConfig               = iamclient.SMSConfig
	SMSStatus               = iamclient.SMSStatus
	ServiceAccount          = iamclient.ServiceAccount
	ServiceAccountKey       = iamclient.ServiceAccountKey
	SetDeliveryConfig       = iamclient.SetDeliveryConfig
	SetSMSConfig            = iamclient.SetSMSConfig
	UnitImpact              = iamclient.UnitImpact
	Usage                   = iamclient.Usage
	UsageDay                = iamclient.UsageDay
	UsageTotal              = iamclient.UsageTotal
	User                    = iamclient.User
	UserFactors             = iamclient.UserFactors
	UserKey                 = iamclient.UserKey
	UserPatch               = iamclient.UserPatch
	UserSchema              = iamclient.UserSchema
	Webhook                 = iamclient.Webhook
	WebhookDelivery         = iamclient.WebhookDelivery
	WebhookInput            = iamclient.WebhookInput
	WebhookSecret           = iamclient.WebhookSecret
	WebhookTest             = iamclient.WebhookTest
)
