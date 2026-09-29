package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// SMS secrets never come from flags: the Twilio auth token and the
// webhook token are read from stdin or these environment variables.
const (
	envTwilioAuthToken = "IAMKIT_TWILIO_AUTH_TOKEN"
	envSMSWebhookToken = "IAMKIT_SMS_WEBHOOK_TOKEN"
)

func smsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sms",
		Short: "Manage SMS delivery (Twilio or webhook) for SMS second factors",
		Long: `Manage the environment's SMS provider. It texts SMS second-factor codes
and phone confirmations; email delivery never receives them. Without a
provider the "sms" factor cannot be enrolled or used (allow it with
"iam sign-in-policy set --allowed-factors ...,sms").`,
	}
	cmd.AddCommand(smsGetCmd(), smsSetCmd(), smsDeleteCmd(), smsStatusCmd(), smsTestCmd())
	return cmd
}

func smsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Get the SMS provider (secrets are never shown)",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/sms")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func smsSetCmd() *cobra.Command {
	var provider, accountSID, from, service, webhookURL string
	var tokenStdin bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set the environment's SMS provider",
		Long: `Set the environment's SMS provider, replacing the whole configuration.

  twilio   IAMKit sends through the Twilio Messages API: --account-sid plus
           --from (E.164) or --messaging-service.
  webhook  IAMKit posts {phone, purpose, code, body} as JSON to your HTTPS
           endpoint, signed per Standard Webhooks with the token.

The Twilio auth token is read from stdin (--token-stdin) or ` + envTwilioAuthToken + `;
the webhook token from stdin or ` + envSMSWebhookToken + `. Left out, the stored secret
is kept when the provider does not change. Secrets are stored encrypted
(IAMKIT_ENCRYPTION_KEY on the server).`,
		Example: `  ` + envTwilioAuthToken + `=... iam sms set --account-sid AC... --from +15551234567
  printf %s "$TOKEN" | iam sms set --provider webhook --webhook-url https://sms.acme.io/iamkit --token-stdin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			provider = strings.ToLower(strings.TrimSpace(provider))
			body := map[string]any{"provider": provider}
			set := func(key, value string) {
				if value != "" {
					body[key] = value
				}
			}
			switch provider {
			case "twilio":
				set("account_sid", accountSID)
				set("from_number", from)
				set("messaging_service_sid", service)
				token, err := secret(tokenStdin, envTwilioAuthToken, true)
				if err != nil {
					return err
				}
				set("auth_token", token)
			case "webhook":
				set("webhook_url", webhookURL)
				token, err := secret(tokenStdin, envSMSWebhookToken, true)
				if err != nil {
					return err
				}
				set("webhook_token", token)
			default:
				return fmt.Errorf("--provider must be twilio or webhook")
			}
			data, err := mustClient(cmd).put(envPath()+"/sms", body)
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			p.ok("SMS provider updated")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&provider, "provider", "twilio", "Provider: twilio or webhook")
	f.StringVar(&accountSID, "account-sid", "", "Twilio account SID (AC...)")
	f.StringVar(&from, "from", "", "Twilio sender number, E.164")
	f.StringVar(&service, "messaging-service", "", "Twilio messaging service SID (MG...), instead of --from")
	f.StringVar(&webhookURL, "webhook-url", "", "Webhook endpoint (HTTPS)")
	f.BoolVar(&tokenStdin, "token-stdin", false, "Read the auth/webhook token from stdin")
	return cmd
}

func smsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Remove the SMS provider (SMS codes stop being sent)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(envPath() + "/sms"); err != nil {
				return err
			}
			newPrinter().ok("SMS provider removed")
			return nil
		},
	}
}

func smsStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether SMS is configured and its latest attempt and failure",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/sms/status")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func smsTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "test PHONE",
		Short:   "Text a test message (no code) through the provider",
		Example: `  iam sms test +15551234567`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(envPath()+"/sms/test", map[string]string{"phone": args[0]})
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			var a struct {
				Delivered bool   `json:"delivered"`
				Reason    string `json:"reason"`
				Status    *int   `json:"status"`
				LatencyMS int    `json:"latency_ms"`
			}
			if err := json.Unmarshal(data, &a); err != nil {
				return err
			}
			if !a.Delivered {
				msg := a.Reason
				if a.Status != nil {
					msg += fmt.Sprintf(" (HTTP %d)", *a.Status)
				}
				fmt.Fprintln(os.Stderr, "Delivery failed: "+msg)
				return fmt.Errorf("test SMS not delivered")
			}
			p.ok(fmt.Sprintf("Test SMS accepted by the provider in %d ms", a.LatencyMS))
			return nil
		},
	}
}
