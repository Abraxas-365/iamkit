package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func passwordPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "password-policy",
		Aliases: []string{"password"},
		Short:   "Manage the environment's end-user password policy",
		Long: `Manage the environment's end-user password policy. With --organization,
manage what one organization adds for its members: it only tightens the
environment's policy (longer minimum, extra character classes, shorter
expiry, breach check). Users are environment-wide, so a member of several
organizations meets all of them.`,
	}
	cmd.PersistentFlags().String("organization", "", "Organization ID: manage its requirements instead")
	cmd.AddCommand(passwordPolicyGetCmd())
	cmd.AddCommand(passwordPolicySetCmd())
	cmd.AddCommand(passwordPolicyDeleteCmd())
	return cmd
}

// passwordPolicyPath is the environment's policy, or the organization's
// requirements with --organization.
func passwordPolicyPath(cmd *cobra.Command) (path string, organization bool) {
	if org, _ := cmd.Flags().GetString("organization"); org != "" {
		return envPath() + "/organizations/" + org + "/password-policy", true
	}
	return envPath() + "/password-policy", false
}

func passwordPolicyGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Get the password policy (the default when none is saved)",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := passwordPolicyPath(cmd)
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func passwordPolicySetCmd() *cobra.Command {
	var minLength, maxAge, threshold, minutes int
	var upper, lower, digit, symbol, breach bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Change the password policy",
		Long: `Change the password policy. Flags left out keep their current value.

New passwords (user creation, invitations, resets, expiry) must follow it.
--lockout-threshold wrong passwords in a row lock the account for
--lockout-minutes (doubling per further lockout, up to 24 h; 0 never locks).
--max-age-days makes users choose a new password at their next password
sign-in (0 never expires). --breach-check rejects passwords found in Have I
Been Pwned (k-anonymity; accepted when the service is unreachable).

With --organization, 0 for --min-length / --max-age-days keeps the
environment's value; lockout flags are environment-only.`,
		Example: `  iam password-policy set --min-length 14 --require-digit --lockout-threshold 5
  iam password-policy set --max-age-days 90 --breach-check
  iam password-policy set --organization ORG_ID --min-length 16 --max-age-days 30`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			path, organization := passwordPolicyPath(cmd)
			f := cmd.Flags()
			if organization && (f.Changed("lockout-threshold") || f.Changed("lockout-minutes")) {
				return fmt.Errorf("lockout applies to the whole environment; drop --organization")
			}
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
			for flag, value := range map[string]any{
				"min-length": minLength, "max-age-days": maxAge, "lockout-threshold": threshold, "lockout-minutes": minutes,
				"require-upper": upper, "require-lower": lower, "require-digit": digit, "require-symbol": symbol, "breach-check": breach,
			} {
				if f.Changed(flag) {
					body[jsonName(flag)] = value
				}
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
	f.IntVar(&minLength, "min-length", 12, "Minimum length, 8-72")
	f.BoolVar(&upper, "require-upper", false, "Require an uppercase letter")
	f.BoolVar(&lower, "require-lower", false, "Require a lowercase letter")
	f.BoolVar(&digit, "require-digit", false, "Require a digit")
	f.BoolVar(&symbol, "require-symbol", false, "Require a symbol")
	f.BoolVar(&breach, "breach-check", false, "Reject passwords found in known breaches")
	f.IntVar(&maxAge, "max-age-days", 0, "Days until a password must be replaced (0 = never)")
	f.IntVar(&threshold, "lockout-threshold", 0, "Wrong passwords in a row that lock the account (0 = never)")
	f.IntVar(&minutes, "lockout-minutes", 15, "First lockout duration in minutes, 1-1440")
	return cmd
}

// jsonName turns a flag name (require-upper) into its JSON field (require_upper).
func jsonName(flag string) string { return strings.ReplaceAll(flag, "-", "_") }

func passwordPolicyDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Restore the default password policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, organization := passwordPolicyPath(cmd)
			if _, err := mustClient(cmd).delete(path); err != nil {
				return err
			}
			if organization {
				newPrinter().ok("Organization password requirements removed")
				return nil
			}
			newPrinter().ok("Password policy restored to the default")
			return nil
		},
	}
}
