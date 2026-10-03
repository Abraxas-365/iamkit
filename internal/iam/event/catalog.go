package event

// The event type catalog. Types are <family>.<past-tense verb>. Every
// event carries its subject's id and the ids of related entities in Data
// (organization_id, user_id, role_id, …) — never secrets or whole records:
// read the current state through the API. New types may appear in any
// release; consumers must ignore types they do not know.
const (
	UserCreated     = "user.created"
	UserUpdated     = "user.updated"
	UserDeactivated = "user.deactivated"
	UserReactivated = "user.reactivated"
	UserDeleted     = "user.deleted"
	UserLocked      = "user.locked"
	UserUnlocked    = "user.unlocked"
	// UserSessionsRevoked: an operator signed the user out everywhere
	// (data.count sessions ended).
	UserSessionsRevoked = "user.sessions_revoked"
	// UserPasswordChangeRequired: the next password sign-in must choose a
	// new password.
	UserPasswordChangeRequired = "user.password_change_required"
	// UserPasswordChanged: the user set a new password (data.method:
	// sign_in — expired or required at sign-in — or reset).
	UserPasswordChanged = "user.password_changed"
	UserSignedUp        = "user.signed_up"
	UserProfileUpdated  = "user.profile_updated"
	UserProfileSynced   = "user.profile_synced"
	UserMetadataSet     = "user.metadata_set"
	UserMetadataDeleted = "user.metadata_deleted"
	// UserProvisioned: a SCIM directory took over an existing user
	// (data.mode: claimed, reactivated, adopted); UserDeprovisioned: SCIM
	// DELETE removed the user from the directory's organization.
	UserProvisioned        = "user.provisioned"
	UserDeprovisioned      = "user.deprovisioned"
	UserPhoneVerified      = "user.phone_verified"
	UserPhoneRemoved       = "user.phone_removed"
	UserAccessTokenCreated = "user.access_token_created"
	UserAccessTokenRevoked = "user.access_token_revoked"
	UserKeyAdded           = "user.key_added"
	UserKeyRemoved         = "user.key_removed"
	UserSchemaUpdated      = "user_schema.updated"
	UserSchemaDeleted      = "user_schema.deleted"

	OrganizationCreated         = "organization.created"
	OrganizationUpdated         = "organization.updated"
	OrganizationMetadataSet     = "organization.metadata_set"
	OrganizationMetadataDeleted = "organization.metadata_deleted"

	MembershipCreated = "membership.created"
	MembershipUpdated = "membership.updated"
	MembershipRemoved = "membership.removed"

	GroupCreated        = "group.created"
	GroupUpdated        = "group.updated"
	GroupDeleted        = "group.deleted"
	GroupMembersChanged = "group.members_changed"

	DomainCreated  = "domain.created"
	DomainVerified = "domain.verified"
	DomainDeleted  = "domain.deleted"

	OrgUnitCreated     = "org_unit.created"
	OrgUnitUpdated     = "org_unit.updated"
	OrgUnitDeleted     = "org_unit.deleted"
	PositionCreated    = "position.created"
	PositionUpdated    = "position.updated"
	PositionDeleted    = "position.deleted"
	PositionAssigned   = "position.assigned"
	PositionUnassigned = "position.unassigned"

	ApplicationCreated  = "application.created"
	ApplicationUpdated  = "application.updated"
	ApplicationLinked   = "application.resource_linked"
	ApplicationUnlinked = "application.resource_unlinked"

	OAuthClientCreated     = "oauth_client.created"
	OAuthClientUpdated     = "oauth_client.updated"
	OAuthClientDisabled    = "oauth_client.disabled"
	OrgAdminPortalEnabled  = "org_admin_portal.enabled"
	OrgAdminPortalDisabled = "org_admin_portal.disabled"
	LogoutDeliveryFailed   = "logout_delivery.failed"
	LogoutDeliveryRetried  = "logout_delivery.retried"

	ResourceCreated       = "resource.created"
	ResourceUpdated       = "resource.updated"
	ResourceAccessUpdated = "resource.access_updated"
	ResourceGrantUpdated  = "resource_grant.updated"
	ResourceGrantDeleted  = "resource_grant.deleted"

	RoleCreated         = "role.created"
	RoleUpdated         = "role.updated"
	RoleDeleted         = "role.deleted"
	RoleAssigned        = "role.assigned"
	RoleUnassigned      = "role.unassigned"
	GroupRoleAssigned   = "group_role.assigned"
	GroupRoleUnassigned = "group_role.unassigned"
	GrantUpdated        = "grant.updated"
	GrantDeleted        = "grant.deleted"

	ServiceAccountCreated = "service_account.created"
	ServiceAccountUpdated = "service_account.updated"
	ServiceAccountRevoked = "service_account.revoked"

	ConnectionCreated  = "connection.created"
	ConnectionUpdated  = "connection.updated"
	ConnectionDisabled = "connection.disabled"
	ConnectionEnabled  = "connection.enabled"
	IdentityLinked     = "identity.linked"
	IdentityUnlinked   = "identity.unlinked"

	ProvisioningCredentialCreated = "provisioning_credential.created"
	ProvisioningCredentialRevoked = "provisioning_credential.revoked"
	ProvisioningIdentityLinked    = "provisioning_identity.linked"

	InvitationCreated  = "invitation.created"
	InvitationResent   = "invitation.resent"
	InvitationRevoked  = "invitation.revoked"
	InvitationAccepted = "invitation.accepted"

	SessionCreated       = "session.created"
	SessionRevoked       = "session.revoked"
	LoginFailed          = "login.failed"
	ImpersonationStarted = "impersonation.started"
	TokenExchanged       = "token.exchanged"
	DeviceApproved       = "device.approved"
	SAMLAssertionIssued  = "saml.assertion_issued"

	MFAEnrolled            = "mfa.enrolled"
	MFARemoved             = "mfa.removed"
	MFAReset               = "mfa.reset"
	MFALocked              = "mfa.locked"
	MFARecoveryUsed        = "mfa.recovery_used"
	MFARecoveryRegenerated = "mfa.recovery_regenerated"
	MFACloneDetected       = "mfa.clone_detected"

	SAMLServiceProviderCreated = "saml_service_provider.created"
	SAMLServiceProviderUpdated = "saml_service_provider.updated"
	SAMLServiceProviderDeleted = "saml_service_provider.deleted"

	SigningKeyCreated   = "signing_key.created"
	SigningKeyActivated = "signing_key.activated"
	SigningKeyRetired   = "signing_key.retired"

	BrandingUpdated       = "branding.updated"
	BrandingDeleted       = "branding.deleted"
	SignInOptionsUpdated  = "sign_in_options.updated"
	SignInOptionsDeleted  = "sign_in_options.deleted"
	PasswordPolicyUpdated = "password_policy.updated"
	PasswordPolicyDeleted = "password_policy.deleted"
	SignInPolicyUpdated   = "sign_in_policy.updated"
	SignInPolicyDeleted   = "sign_in_policy.deleted"
	DeliveryUpdated       = "delivery.updated"
	DeliveryDeleted       = "delivery.deleted"
	DeliveryTested        = "delivery.tested"
	EmailTemplateUpdated  = "email_template.updated"
	EmailTemplateDeleted  = "email_template.deleted"
	SignInTextsUpdated    = "sign_in_texts.updated"
	SignInTextsDeleted    = "sign_in_texts.deleted"
	// FeatureUpdated / FeatureReset: an environment override of a feature
	// flag was set (data.enabled) or removed; subject = the flag name.
	FeatureUpdated = "feature.updated"
	FeatureReset   = "feature.reset"
	// LimitsUpdated: the environment's limits were replaced (data.limits:
	// the limits set, absent = the deployment's).
	LimitsUpdated = "limits.updated"

	SMSUpdated = "sms.updated"
	SMSDeleted = "sms.deleted"
	SMSTested  = "sms.tested"

	WebhookCreated         = "webhook.created"
	WebhookUpdated         = "webhook.updated"
	WebhookDeleted         = "webhook.deleted"
	WebhookSecretRotated   = "webhook.secret_rotated"
	WebhookReplayed        = "webhook.replayed"
	WebhookDeliveryRetried = "webhook.delivery_retried"
	// WebhookDisabled: the subscription failed for
	// config.EventWebhookDisableAfter and was turned off.
	WebhookDisabled = "webhook.disabled"

	ActionTargetCreated       = "action_target.created"
	ActionTargetUpdated       = "action_target.updated"
	ActionTargetDeleted       = "action_target.deleted"
	ActionTargetSecretRotated = "action_target.secret_rotated"
	// ActionExecutionUpdated / ActionExecutionDeleted: the targets bound
	// to a condition were set or removed; subject = the condition.
	ActionExecutionUpdated = "action_execution.updated"
	ActionExecutionDeleted = "action_execution.deleted"
	// ActionFailed: a target failed (timeout, error status, invalid
	// response); data names the condition, target and whether the flow
	// was interrupted.
	ActionFailed = "action.failed"
)
