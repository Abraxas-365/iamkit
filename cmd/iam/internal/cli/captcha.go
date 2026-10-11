package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// The CAPTCHA secret never comes from a flag: it is read from stdin or this
// environment variable.
const envCaptchaSecret = "IAMKIT_CAPTCHA_SECRET"

var captchaProviders = []string{"turnstile", "hcaptcha"}

func captchaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "captcha",
		Short: "Manage the environment's bot protection (Turnstile or hCaptcha)",
		Long: `Configure the CAPTCHA that hosted sign-in pages and the headless routes
(/login, /challenges, /signup, LDAP login) ask for. Turnstile (Cloudflare)
and hCaptcha are supported; the secret is stored encrypted and never shown.
Without a configuration nothing changes for sign-in.`,
	}
	cmd.AddCommand(captchaGetCmd(), captchaSetCmd(), captchaDeleteCmd(), captchaTestCmd())
	return cmd
}

func captchaGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Show the CAPTCHA configuration (the secret is never shown)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/captcha")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func captchaSetCmd() *cobra.Command {
	var provider, siteKey string
	var hosted, headless, secretStdin bool
	var hostnames []string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set the CAPTCHA configuration, replacing the whole one",
		Long: `Sets the environment's CAPTCHA. --provider (turnstile or hcaptcha) and
--site-key are required. The secret is read from stdin (--secret-stdin) or
` + envCaptchaSecret + `; left out, the stored secret is kept (the first time one is
required). The secret is checked with the provider.

--hosted / --headless choose where it is asked (both on by default).
--hostname adds host names a headless token may have been solved on
(repeat or comma-separate).`,
		Example: `  ` + envCaptchaSecret + `=... iam captcha set --provider turnstile --site-key 0x4AAAA...
  printf %s "$SECRET" | iam captcha set --provider hcaptcha --site-key 10000000-ffff-ffff-ffff-000000000001 --secret-stdin --headless=false`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			provider = strings.ToLower(strings.TrimSpace(provider))
			if !contains(captchaProviders, provider) {
				return fmt.Errorf("--provider must be one of %s", strings.Join(captchaProviders, ", "))
			}
			if strings.TrimSpace(siteKey) == "" {
				return fmt.Errorf("--site-key is required")
			}
			body := map[string]any{"provider": provider, "site_key": strings.TrimSpace(siteKey)}
			token, err := secret(secretStdin, envCaptchaSecret, true)
			if err != nil {
				return err
			}
			if token != "" {
				body["secret"] = token
			}
			fl := cmd.Flags()
			if fl.Changed("hosted") {
				body["hosted"] = hosted
			}
			if fl.Changed("headless") {
				body["headless"] = headless
			}
			if len(hostnames) > 0 {
				body["hostnames"] = hostnames
			}
			data, err := mustClient(cmd).put(envPath()+"/captcha", body)
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			p.ok("CAPTCHA updated")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&provider, "provider", "", "Provider: "+strings.Join(captchaProviders, " or ")+" (required)")
	f.StringVar(&siteKey, "site-key", "", "Public site key (required)")
	f.BoolVar(&secretStdin, "secret-stdin", false, "Read the secret key from stdin")
	f.BoolVar(&hosted, "hosted", true, "Ask on the hosted sign-in pages")
	f.BoolVar(&headless, "headless", true, "Ask on the headless routes (login, challenges, signup, LDAP)")
	f.StringSliceVar(&hostnames, "hostname", nil, "Extra host name a headless token may be solved on; repeatable")
	return cmd
}

func captchaDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Remove the CAPTCHA (sign-in stops asking for it)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(envPath() + "/captcha"); err != nil {
				return err
			}
			newPrinter().ok("CAPTCHA removed")
			return nil
		},
	}
}

func captchaTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Check the stored secret with the provider (at most 5 a minute)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).post(envPath()+"/captcha/test", nil); err != nil {
				return err
			}
			newPrinter().ok("The provider accepted the secret")
			return nil
		},
	}
}
