package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func deliveryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delivery",
		Short: "Manage email delivery (webhook, SMTP or Resend) and email wording",
	}
	cmd.AddCommand(deliveryGetCmd())
	cmd.AddCommand(deliverySetCmd())
	cmd.AddCommand(deliveryDeleteCmd())
	cmd.AddCommand(deliveryPreviewCmd())
	cmd.AddCommand(deliveryTemplatesCmd())
	return cmd
}

func deliveryGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Get current delivery configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/delivery")
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

// Secrets never come from flags (shell history, process lists): the SMTP
// password and Resend API key are read from stdin or an environment variable.
// The webhook token flag stays for compatibility; IAMKIT_WEBHOOK_TOKEN is
// the safer way to pass it.
const (
	envSMTPPassword = "IAMKIT_SMTP_PASSWORD"
	envResendAPIKey = "IAMKIT_RESEND_API_KEY"
	envWebhookToken = "IAMKIT_WEBHOOK_TOKEN"
)

func deliverySetCmd() *cobra.Command {
	var provider, webhookURL, webhookToken, invitationURL string
	var fromEmail, fromName, replyTo string
	var smtpHost, smtpUsername, smtpTLS string
	var smtpPort int
	var passwordStdin, apiKeyStdin bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set the environment's email delivery",
		Long: `Set the environment's email delivery, replacing the whole configuration.
Only the chosen provider's flags apply.

  webhook  IAMKit posts JSON to your endpoint, which writes and sends the email.
  smtp     IAMKit writes the email and sends it through an SMTP server.
  resend   IAMKit writes the email and sends it through the Resend API.

The SMTP password and Resend API key are read from stdin (--smtp-password-stdin,
--api-key-stdin) or from ` + envSMTPPassword + ` / ` + envResendAPIKey + `; the webhook token
from --webhook-token or ` + envWebhookToken + `. Left out, the stored secret is kept when
the provider does not change (for SMTP, only with the same host, port, TLS mode
and username). Storing SMTP/Resend secrets requires IAMKIT_ENCRYPTION_KEY on the
server.`,
		Example: `  ` + envWebhookToken + `=s3cret iam delivery set --webhook-url https://mail.example.com/hook
  printf %s "$SMTP_PASSWORD" | iam delivery set --provider smtp --from-email no-reply@acme.io \
      --smtp-host smtp.sendgrid.net --smtp-username apikey --smtp-password-stdin
  ` + envResendAPIKey + `=re_... iam delivery set --provider resend --from-email no-reply@acme.io`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if passwordStdin && apiKeyStdin {
				return fmt.Errorf("use only one of --smtp-password-stdin and --api-key-stdin")
			}
			provider = strings.ToLower(strings.TrimSpace(provider))
			if passwordStdin && provider != "smtp" {
				return fmt.Errorf("--smtp-password-stdin applies only to --provider smtp")
			}
			if apiKeyStdin && provider != "resend" {
				return fmt.Errorf("--api-key-stdin applies only to --provider resend")
			}
			if webhookToken == "" && provider == "webhook" {
				webhookToken = os.Getenv(envWebhookToken)
			}
			body := map[string]any{"provider": provider}
			set := func(key, value string) {
				if value != "" {
					body[key] = value
				}
			}
			set("webhook_url", webhookURL)
			set("webhook_token", webhookToken)
			set("invitation_url", invitationURL)
			set("from_email", fromEmail)
			set("from_name", fromName)
			set("reply_to", replyTo)
			set("smtp_host", smtpHost)
			set("smtp_username", smtpUsername)
			set("smtp_tls", smtpTLS)
			if smtpPort != 0 {
				body["smtp_port"] = smtpPort
			}
			password, err := secret(passwordStdin, envSMTPPassword, provider == "smtp")
			if err != nil {
				return err
			}
			set("smtp_password", password)
			key, err := secret(apiKeyStdin, envResendAPIKey, provider == "resend")
			if err != nil {
				return err
			}
			set("api_key", key)

			c := mustClient(cmd)
			if _, err := c.put(envPath()+"/delivery", body); err != nil {
				return err
			}
			newPrinter().ok("Delivery configuration updated")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&provider, "provider", "webhook", "Provider: webhook, smtp or resend")
	f.StringVar(&webhookURL, "webhook-url", "", "Webhook URL (webhook)")
	f.StringVar(&webhookToken, "webhook-token", "", "Webhook bearer token (webhook)")
	f.StringVar(&invitationURL, "invitation-url", "", "App page that accepts invitations (optional; smtp/resend default to the hosted invite page)")
	f.StringVar(&fromEmail, "from-email", "", "Sender address (smtp, resend)")
	f.StringVar(&fromName, "from-name", "", "Sender name (smtp, resend)")
	f.StringVar(&replyTo, "reply-to", "", "Reply-To address (smtp, resend)")
	f.StringVar(&smtpHost, "smtp-host", "", "SMTP host name, without scheme or port")
	f.IntVar(&smtpPort, "smtp-port", 0, "SMTP port (default 587)")
	f.StringVar(&smtpUsername, "smtp-username", "", "SMTP username")
	f.StringVar(&smtpTLS, "smtp-tls", "", "SMTP encryption: starttls or tls (default starttls; tls on port 465)")
	f.BoolVar(&passwordStdin, "smtp-password-stdin", false, "Read the SMTP password from stdin (or set "+envSMTPPassword+")")
	f.BoolVar(&apiKeyStdin, "api-key-stdin", false, "Read the Resend API key from stdin (or set "+envResendAPIKey+")")
	return cmd
}

// secret reads a provider secret from stdin when asked, else from the
// environment variable when it applies to the chosen provider.
func secret(stdin bool, envVar string, applies bool) (string, error) {
	if stdin {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return "", fmt.Errorf("reading secret from stdin: %w", err)
		}
		v := strings.TrimRight(string(raw), "\r\n")
		if v == "" {
			return "", fmt.Errorf("no secret on stdin")
		}
		return v, nil
	}
	if applies {
		return os.Getenv(envVar), nil
	}
	return "", nil
}

func deliveryDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Delete delivery configuration (restore global fallback)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/delivery")
			if err != nil {
				return err
			}
			p.ok("Delivery configuration deleted")
			return nil
		},
	}
}

func deliveryPreviewCmd() *cobra.Command {
	var purpose, locale string
	var html bool
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Render a sample email with the saved branding and wording",
		Long: `Render a sample email with the environment's branding and wording. It prints the
subject and plain-text part (--html: the HTML document). Only smtp and resend send what
the preview shows; a webhook writes its own emails.`,
		Example: `  iam delivery preview --purpose invitation --locale es
  iam delivery preview --html > login.html`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			q := url.Values{"purpose": {purpose}}
			if locale != "" {
				q.Set("locale", locale)
			}
			data, err := c.get(envPath() + "/delivery/preview?" + q.Encode())
			if err != nil {
				return err
			}
			var out struct{ Subject, HTML, Text string }
			if err := json.Unmarshal(data, &out); err != nil {
				return err
			}
			switch {
			case html:
				fmt.Fprintln(p.out, out.HTML)
			case p.wantJSON():
				p.JSON(data)
			default:
				fmt.Fprintf(p.out, "Subject: %s\n\n%s\n", out.Subject, out.Text)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&purpose, "purpose", "login", "Email: login, password_reset, email_verification, invitation or test")
	cmd.Flags().StringVar(&locale, "locale", "", "Language code (default: the environment's email language)")
	cmd.Flags().BoolVar(&html, "html", false, "Print the HTML document instead of the text part")
	return cmd
}

func deliveryTemplatesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "templates",
		Aliases: []string{"template"},
		Short:   "Customize the wording of the emails IAMKit writes (smtp, resend)",
	}
	cmd.AddCommand(templatesListCmd(), templatesGetCmd(), templatesSetCmd(), templatesResetCmd())
	return cmd
}

func templatePath(purpose, locale string) string {
	return envPath() + "/delivery/templates/" + url.PathEscape(purpose) + "/" + url.PathEscape(locale)
}

func templatesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every email and language and whether its wording is customized",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/delivery/templates")
			if err != nil {
				return err
			}
			p.table(data, []string{"PURPOSE", "LOCALE", "WORDING", "UPDATED"}, func(m map[string]any) []string {
				wording := "default"
				if v, _ := m["customized"].(bool); v {
					wording = "custom"
				}
				return []string{str(m, "purpose"), str(m, "locale"), wording, str(m, "updated_at")}
			})
			return nil
		},
	}
}

// copyFields are the wording fields of a template, in display order.
var copyFields = []string{"subject", "heading", "body", "action", "footer"}

func templatesGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get PURPOSE LOCALE",
		Short: "Show one email's wording, IAMKit's defaults and the placeholders",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(templatePath(args[0], args[1]))
			if err != nil {
				return err
			}
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			var view struct {
				Customized   bool              `json:"customized"`
				Template     map[string]string `json:"template"`
				Defaults     map[string]string `json:"defaults"`
				Placeholders []string          `json:"placeholders"`
			}
			if err := json.Unmarshal(data, &view); err != nil {
				return err
			}
			for _, k := range copyFields {
				if v := view.Template[k]; v != "" {
					fmt.Fprintf(p.out, "%s: %s\n", k, v)
				} else if d := view.Defaults[k]; d != "" {
					fmt.Fprintf(p.out, "%s (default): %s\n", k, d)
				}
			}
			fmt.Fprintf(p.out, "\nplaceholders: {{%s}}\n", strings.Join(view.Placeholders, "}}, {{"))
			return nil
		},
	}
}

func templatesSetCmd() *cobra.Command {
	var file string
	values := map[string]*string{}
	cmd := &cobra.Command{
		Use:   "set PURPOSE LOCALE",
		Short: "Change the wording of one email in one language",
		Long: `Change the wording of one email in one language. Flags change only the fields given
(an empty value restores that field's default); --file replaces the whole wording with a
JSON object {"subject","heading","body","action","footer"} ("-" reads stdin).
Text may use the {{placeholders}} listed by "iam delivery templates get".`,
		Example: `  iam delivery templates set login es --subject "Tu código para {{app_name}}"
  iam delivery templates set invitation en --file invitation.json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			path := templatePath(args[0], args[1])
			body := map[string]string{}
			if file != "" {
				var wording struct {
					Subject string `json:"subject"`
					Heading string `json:"heading"`
					Body    string `json:"body"`
					Action  string `json:"action"`
					Footer  string `json:"footer"`
				}
				if err := readJSON(file, &wording); err != nil {
					return err
				}
				body = map[string]string{"subject": wording.Subject, "heading": wording.Heading, "body": wording.Body, "action": wording.Action, "footer": wording.Footer}
			} else {
				current, err := c.get(path)
				if err != nil {
					return err
				}
				var view struct {
					Template map[string]string `json:"template"`
				}
				if err := json.Unmarshal(current, &view); err != nil {
					return err
				}
				body = view.Template
				if body == nil {
					body = map[string]string{}
				}
				changed := false
				for _, k := range copyFields {
					if cmd.Flags().Changed(k) {
						body[k] = *values[k]
						changed = true
					}
				}
				if !changed {
					return fmt.Errorf("nothing to change: give --subject, --heading, --body, --action, --footer or --file")
				}
			}
			data, err := c.put(path, body)
			if err != nil {
				return err
			}
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			p.ok("Email wording updated")
			return nil
		},
	}
	for _, k := range copyFields {
		values[k] = new(string)
		cmd.Flags().StringVar(values[k], k, "", "Custom "+k+" (empty = default)")
	}
	cmd.Flags().StringVar(&file, "file", "", "JSON file with the whole wording (\"-\" = stdin)")
	cmd.MarkFlagsMutuallyExclusive("file", "subject")
	cmd.MarkFlagsMutuallyExclusive("file", "heading")
	cmd.MarkFlagsMutuallyExclusive("file", "body")
	cmd.MarkFlagsMutuallyExclusive("file", "action")
	cmd.MarkFlagsMutuallyExclusive("file", "footer")
	return cmd
}

func readJSON(file string, into any) error {
	var r io.Reader = os.Stdin
	if file != "-" {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("reading %s: %w", file, err)
	}
	return nil
}

func templatesResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset PURPOSE LOCALE",
		Short: "Return one email in one language to IAMKit's wording",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.delete(templatePath(args[0], args[1])); err != nil {
				return err
			}
			newPrinter().ok("Email wording reset to default")
			return nil
		},
	}
}
