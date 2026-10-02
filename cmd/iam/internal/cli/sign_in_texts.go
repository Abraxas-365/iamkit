package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// signInTextsCmd manages the custom wording of the hosted pages.
func signInTextsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sign-in-texts",
		Aliases: []string{"texts"},
		Short:   "Customize the wording of the hosted sign-in pages",
		Long: `Customize any text of the hosted sign-in pages (titles, labels, buttons,
notices, error messages) per language, for the environment, one OAuth client
(--client) or one organization (--organization). Pages resolve each text
organization › client › environment › IAMKit's own wording in the page
language. Texts are plain text and keep the placeholders of IAMKit's message
(%s, {count}); "iam sign-in-texts catalog" lists the keys, defaults,
placeholders and length limits. Email wording is managed with "iam delivery
templates".`,
	}
	cmd.AddCommand(signInTextsCatalogCmd())
	cmd.AddCommand(signInTextsListCmd())
	cmd.AddCommand(signInTextsGetCmd())
	cmd.AddCommand(signInTextsSetCmd())
	cmd.AddCommand(signInTextsDeleteCmd())
	return cmd
}

// textScopeFlags adds --client and --organization.
func textScopeFlags(cmd *cobra.Command, client, organization *string) {
	cmd.Flags().StringVar(client, "client", "", "OAuth client ID (its own texts)")
	cmd.Flags().StringVar(organization, "organization", "", "Organization ID (its own texts)")
}

func signInTextsPath(client, organization, locale string) (string, error) {
	path := envPath() + "/login-settings"
	switch {
	case client != "" && organization != "":
		return "", fmt.Errorf("--client and --organization conflict")
	case client != "":
		path += "/clients/" + url.PathEscape(client)
	case organization != "":
		path += "/organizations/" + url.PathEscape(organization)
	}
	return path + "/texts/" + url.PathEscape(locale), nil
}

func signInTextsCatalogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "catalog [LOCALE]",
		Short: "List the customizable texts of a language (default en)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			locale := "en"
			if len(args) == 1 {
				locale = args[0]
			}
			data, err := mustClient(cmd).get(envPath() + "/login-settings/texts/catalog?locale=" + url.QueryEscape(locale))
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"KEY", "PLACEHOLDERS", "MAX", "DEFAULT"}, func(m map[string]any) []string {
				var placeholders []string
				for _, p := range m["placeholders"].([]any) {
					placeholders = append(placeholders, fmt.Sprint(p))
				}
				return []string{str(m, "key"), strings.Join(placeholders, " "), fmt.Sprint(m["max_length"]), str(m, "default")}
			})
			return nil
		},
	}
}

func signInTextsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the scopes and languages with custom texts",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/login-settings/texts")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"SCOPE", "ID", "LOCALE", "TEXTS", "UPDATED"}, func(m map[string]any) []string {
				scope, id := "environment", ""
				if v := str(m, "client_id"); v != "" {
					scope, id = "client", v
				} else if v := str(m, "organization_id"); v != "" {
					scope, id = "organization", v
				}
				texts, _ := m["texts"].(map[string]any)
				return []string{scope, id, str(m, "locale"), fmt.Sprint(len(texts)), str(m, "updated_at")}
			})
			return nil
		},
	}
}

func signInTextsGetCmd() *cobra.Command {
	var client, organization string
	cmd := &cobra.Command{
		Use:   "get LOCALE",
		Short: "Get the custom texts of a language",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := signInTextsPath(client, organization, args[0])
			if err != nil {
				return err
			}
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			var out struct {
				Texts map[string]string `json:"texts"`
			}
			if err := json.Unmarshal(data, &out); err != nil {
				return err
			}
			keys := make([]string, 0, len(out.Texts))
			for k := range out.Texts {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("%s=%s\n", k, out.Texts[k])
			}
			if len(keys) == 0 {
				fmt.Fprintln(os.Stderr, "No custom texts (IAMKit's wording applies)")
			}
			return nil
		},
	}
	textScopeFlags(cmd, &client, &organization)
	return cmd
}

func signInTextsSetCmd() *cobra.Command {
	var client, organization, file string
	var texts []string
	var replace bool
	cmd := &cobra.Command{
		Use:   "set LOCALE",
		Short: "Change custom texts of a language",
		Long: `Change custom texts of a language. --text KEY=MESSAGE (repeatable) sets one
text and keeps the others; an empty MESSAGE removes it (it inherits again).
--file reads a JSON object {"key": "message"}. --replace drops the texts not
given instead of keeping them.`,
		Example: `  iam sign-in-texts set en --text hosted.title.sign_in="Welcome back" --text hosted.form.continue=Next
  iam sign-in-texts set es --organization ORG_ID --text hosted.title.sign_in="Bienvenido a Acme"
  iam sign-in-texts set en --client CLIENT_ID --file texts.json --replace`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := signInTextsPath(client, organization, args[0])
			if err != nil {
				return err
			}
			c := mustClient(cmd)
			body := map[string]string{}
			if !replace {
				current, err := c.get(path)
				if err != nil {
					return err
				}
				var out struct {
					Texts map[string]string `json:"texts"`
				}
				if err := json.Unmarshal(current, &out); err != nil {
					return fmt.Errorf("read current texts: %w", err)
				}
				for k, v := range out.Texts {
					body[k] = v
				}
			}
			if file != "" {
				raw, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				var given map[string]string
				if err := json.Unmarshal(raw, &given); err != nil {
					return fmt.Errorf("--file must be a JSON object of strings: %w", err)
				}
				for k, v := range given {
					body[k] = v
				}
			}
			for _, t := range texts {
				k, v, ok := strings.Cut(t, "=")
				if !ok || strings.TrimSpace(k) == "" {
					return fmt.Errorf("--text must be KEY=MESSAGE, got %q", t)
				}
				body[strings.TrimSpace(k)] = v
			}
			for k, v := range body {
				if strings.TrimSpace(v) == "" {
					delete(body, k)
				}
			}
			if len(body) == 0 {
				return fmt.Errorf("no texts left: use \"iam sign-in-texts delete %s\" to inherit every text", args[0])
			}
			data, err := c.put(path, map[string]any{"texts": body})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	textScopeFlags(cmd, &client, &organization)
	f := cmd.Flags()
	f.StringArrayVar(&texts, "text", nil, "KEY=MESSAGE (repeatable; empty MESSAGE inherits)")
	f.StringVar(&file, "file", "", "JSON file of {\"key\": \"message\"}")
	f.BoolVar(&replace, "replace", false, "Drop the texts not given")
	return cmd
}

func signInTextsDeleteCmd() *cobra.Command {
	var client, organization string
	cmd := &cobra.Command{
		Use:   "delete LOCALE",
		Short: "Remove the custom texts of a language (everything inherits)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := signInTextsPath(client, organization, args[0])
			if err != nil {
				return err
			}
			if _, err := mustClient(cmd).delete(path); err != nil {
				return err
			}
			newPrinter().ok("Custom texts removed")
			return nil
		},
	}
	textScopeFlags(cmd, &client, &organization)
	return cmd
}
