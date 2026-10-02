package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func signInPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sign-in-policy",
		Aliases: []string{"sign-in"},
		Short:   "Manage which sign-in methods the environment allows",
		Long: `Manage the environment's sign-in policy: allowed methods (password, email
code, social connections, passkeys), password reset and the default second-factor
rules. Organizations narrow the methods ("iam organizations update
--allow-password=false"); hosted applications narrow them further.
Organization single sign-on is not governed by it.`,
	}
	cmd.AddCommand(signInPolicyGetCmd())
	cmd.AddCommand(signInPolicySetCmd())
	cmd.AddCommand(signInPolicyDeleteCmd())
	return cmd
}

func signInPolicyGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Get the sign-in policy (the default when none is saved)",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/sign-in-policy")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func signInPolicySetCmd() *cobra.Command {
	var password, emailCode, social, passkey, reset, mfa, mfaFederated, signup, terms bool
	var signupOrganization, signupGroup string
	var factors []string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Change the sign-in policy",
		Long: `Change the sign-in policy. Flags left out keep their current value.

Refused methods answer 403 METHOD_NOT_ALLOWED before any account lookup;
--allow-password-reset=false answers 403 PASSWORD_RESET_DISABLED and hides
"Forgot password" on the hosted pages (it needs --allow-password).
--mfa-required / --mfa-for-federated apply to every organization on top of
its own MFA policy.

--allow-signup lets people create their own account (POST
/identity/v1/signup, "Create account" on the hosted pages) after confirming
their email. New accounts join --signup-organization (required) and
optionally --signup-group (an operator-managed group of it). Pass "" to
clear the group. --require-terms makes sign-up record the acceptance of the
terms ("accept_terms", users.terms_accepted_at); the hosted page links the
branding's legal terms URL.

--allow-passkey (default on) lets users sign in with a passkey alone (no
password, no second factor: the passkey verified them); it needs "webauthn"
among --allowed-factors.

--allowed-factors lists the second factors users may enroll and sign in
with (default totp,webauthn): authenticator apps and security keys. "email" sends codes through the email
delivery with purpose "mfa" (a custom webhook must handle it); "sms" needs
"iam sms set". Organizations narrow the list with
"iam organizations update --allowed-factors".`,
		Example: `  iam sign-in-policy set --allow-password=false --allow-password-reset=false
  iam sign-in-policy set --mfa-required
  iam sign-in-policy set --allowed-factors totp,webauthn,sms
  iam sign-in-policy set --allow-signup --signup-organization <org-id> --signup-group <group-id>
  iam sign-in-policy set --require-terms`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			path := envPath() + "/sign-in-policy"
			current, err := c.get(path)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if err := json.Unmarshal(current, &body); err != nil {
				return fmt.Errorf("read current policy: %w", err)
			}
			delete(body, "custom")
			delete(body, "updated_at")
			f := cmd.Flags()
			for flag, value := range map[string]bool{
				"allow-password": password, "allow-email-code": emailCode, "allow-social": social, "allow-passkey": passkey,
				"allow-password-reset": reset, "mfa-required": mfa, "mfa-for-federated": mfaFederated, "allow-signup": signup,
				"require-terms": terms,
			} {
				if f.Changed(flag) {
					body[jsonName(flag)] = value
				}
			}
			if f.Changed("signup-organization") {
				body["signup_organization_id"] = signupOrganization
			}
			if f.Changed("signup-group") {
				body["signup_group_id"] = signupGroup
			}
			if f.Changed("allowed-factors") {
				body["allowed_factors"] = factors
			}
			data, err := c.put(path, body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&password, "allow-password", true, "Allow password sign-in")
	f.BoolVar(&emailCode, "allow-email-code", true, "Allow email-code sign-in")
	f.BoolVar(&social, "allow-social", true, "Allow environment (social) connections")
	f.BoolVar(&passkey, "allow-passkey", true, "Allow passkey sign-in (needs webauthn among --allowed-factors)")
	f.BoolVar(&reset, "allow-password-reset", true, "Offer password reset")
	f.BoolVar(&mfa, "mfa-required", false, "Require a second factor in every organization")
	f.BoolVar(&mfaFederated, "mfa-for-federated", false, "Also require it after SSO/social sign-in")
	f.BoolVar(&signup, "allow-signup", false, "Let people create their own account")
	f.BoolVar(&terms, "require-terms", false, "Require accepting the terms to sign up")
	f.StringVar(&signupOrganization, "signup-organization", "", "Organization new accounts join (needed by --allow-signup)")
	f.StringVar(&signupGroup, "signup-group", "", "Operator-managed group of it new accounts join")
	f.StringSliceVar(&factors, "allowed-factors", nil, "Second factors users may enroll: totp, webauthn, sms, email (comma-separated)")
	return cmd
}

func signInPolicyDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Restore the default sign-in policy (everything allowed)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(envPath() + "/sign-in-policy"); err != nil {
				return err
			}
			newPrinter().ok("Sign-in policy restored to the default")
			return nil
		},
	}
}
