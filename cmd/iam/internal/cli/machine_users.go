package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func machineUsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "machine-users",
		Aliases: []string{"machine-user"},
		Short:   "Manage machine users and their personal access tokens",
		Long: `Machine users are users without email, password or second factor.
They join organizations and receive roles, groups and grants like people,
and authenticate with personal access tokens (ik_pat_), used directly as a
bearer or exchanged at /identity/v1/token-exchange for an access JWT, or
with keys: a JWT assertion signed with the key is traded at /oauth/token
(grant urn:ietf:params:oauth:grant-type:jwt-bearer) for an access JWT.
Deactivate one with "iam users deactivate".`,
	}
	cmd.AddCommand(machineUsersListCmd())
	cmd.AddCommand(machineUsersCreateCmd())
	cmd.AddCommand(machineTokensCmd())
	cmd.AddCommand(machineKeysCmd())
	return cmd
}

func machineUsersListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List machine users",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			q := listQuery(limit, offset, search)
			sep := "?"
			if q != "" {
				sep = "&"
			}
			data, err := c.get(envPath() + "/users" + q + sep + "kind=machine")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "NAME", "STATE", "LAST USED"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "state"), str(m, "last_signed_in_at")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func machineUsersCreateCmd() *cobra.Command {
	var name, home string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a machine user",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			body := map[string]any{"kind": "machine", "name": name}
			if home != "" {
				body["home_organization_id"] = home
			}
			data, err := c.post(envPath()+"/users", body)
			if err != nil {
				return err
			}
			newPrinter().created("machine user", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Machine user name (required)")
	cmd.Flags().StringVar(&home, "home-organization", "", "Organization that owns the record; the machine user joins it")
	cmd.MarkFlagRequired("name")
	return cmd
}

func machineTokensCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tokens",
		Aliases: []string{"token", "pats"},
		Short:   "Manage a machine user's personal access tokens",
	}
	cmd.AddCommand(machineTokensListCmd(), machineTokensCreateCmd(), machineTokensRevokeCmd())
	return cmd
}

func machineTokensListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list USER_ID",
		Short: "List personal access tokens (never their secrets)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/users/" + args[0] + "/access-tokens" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "NAME", "ORGANIZATION", "RESOURCE", "EXPIRES", "LAST USED", "STATUS"}, func(m map[string]any) []string {
				status := "active"
				if v := str(m, "revoked_at"); v != "" && v != "<nil>" {
					status = "revoked"
				}
				org := str(m, "organization_name")
				if org == "" {
					org = truncateID(str(m, "organization_id"))
				}
				res := str(m, "resource_name")
				if res == "" {
					res = truncateID(str(m, "resource_id"))
				}
				return []string{str(m, "id"), str(m, "name"), org, res, str(m, "expires_at"), str(m, "last_used_at"), status}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search by name")
	return cmd
}

func machineTokensCreateCmd() *cobra.Command {
	var name, org, app, resource, expiresIn string
	cmd := &cobra.Command{
		Use:   "create USER_ID",
		Short: "Create a personal access token (shown once)",
		Long: `Creates a personal access token acting as the machine user in one
organization for one application resource, with the permissions the user
holds there each time it is used. The token is shown only once.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			body := map[string]any{"name": name, "organization_id": org, "application_id": app, "resource_id": resource}
			if expiresIn != "" {
				body["expires_in"] = expiresIn
			}
			data, err := c.post(envPath()+"/users/"+args[0]+"/access-tokens", body)
			if err != nil {
				return err
			}
			// Always output full JSON — the token must be captured.
			newPrinter().JSON(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Token name (required)")
	cmd.Flags().StringVar(&org, "org", "", "Organization ID, one the machine user belongs to (required)")
	cmd.Flags().StringVar(&app, "app", "", "Application ID (required)")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID of the application (required)")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", `Expiration, 1h to 8760h or "never" (default 24h)`)
	for _, f := range []string{"name", "org", "app", "resource"} {
		cmd.MarkFlagRequired(f)
	}
	return cmd
}

func machineTokensRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke USER_ID TOKEN_ID",
		Short: "Revoke a personal access token and the sessions exchanged from it",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.delete(envPath() + "/users/" + args[0] + "/access-tokens/" + args[1]); err != nil {
				return err
			}
			newPrinter().ok("Access token revoked: " + args[1])
			return nil
		},
	}
}

func machineKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "keys",
		Aliases: []string{"key"},
		Short:   "Manage a machine user's keys (JWT-bearer login)",
	}
	cmd.AddCommand(machineKeysListCmd(), machineKeysAddCmd(), machineKeysRemoveCmd())
	return cmd
}

func machineKeysListCmd() *cobra.Command {
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list USER_ID",
		Short: "List a machine user's keys (public halves only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/users/" + args[0] + "/keys" + listQuery(limit, offset, ""))
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "TYPE", "EXPIRES", "LAST USED", "CREATED"}, func(m map[string]any) []string {
				kind := ""
				if key, ok := m["public_key"].(map[string]any); ok {
					kind = str(key, "kty")
					if crv := str(key, "crv"); crv != "" {
						kind += " " + crv
					}
				}
				return []string{str(m, "id"), kind, str(m, "expires_at"), str(m, "last_used_at"), str(m, "created_at")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	return cmd
}

func machineKeysAddCmd() *cobra.Command {
	var publicKeyFile, expiresIn, privateKeyOut string
	cmd := &cobra.Command{
		Use:   "add USER_ID",
		Short: "Add a key: upload a public JWK, or let IAMKit generate a pair",
		Long: `Adds a key to a machine user (at most 10). With --public-key-file the
file holds an RSA (2048 bits or more) or EC public JSON Web Key; without
it IAMKit generates an RSA pair and returns the private key once (PEM,
PKCS #8) — write it straight to a file with --private-key-out.

The key ID is the kid of the assertions it signs: iss = sub = the user ID,
aud = <issuer>/oauth/token, a jti, exp at most one hour ahead.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			body := map[string]any{}
			if publicKeyFile != "" {
				raw, err := os.ReadFile(publicKeyFile)
				if err != nil {
					return err
				}
				if !json.Valid(raw) {
					return fmt.Errorf("%s: not a JSON Web Key", publicKeyFile)
				}
				body["public_key"] = json.RawMessage(raw)
			}
			if expiresIn != "" {
				body["expires_in"] = expiresIn
			}
			data, err := c.post(envPath()+"/users/"+args[0]+"/keys", body)
			if err != nil {
				return err
			}
			if privateKeyOut != "" {
				var issued struct {
					ID         string `json:"id"`
					PrivateKey string `json:"private_key"`
				}
				if err := json.Unmarshal(data, &issued); err != nil {
					return err
				}
				if issued.PrivateKey == "" {
					return fmt.Errorf("no private key returned (the public key was uploaded)")
				}
				if err := os.WriteFile(privateKeyOut, []byte(issued.PrivateKey), 0o600); err != nil {
					return fmt.Errorf("key %s created but the private key could not be written: %w", issued.ID, err)
				}
				newPrinter().ok("Key " + issued.ID + " created; private key written to " + privateKeyOut)
				return nil
			}
			// Always output full JSON — a generated private key must be captured.
			newPrinter().JSON(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&publicKeyFile, "public-key-file", "", "File with the public JSON Web Key to upload (omit to generate a pair)")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", `Expiration, 1h to 8760h or "never" (default 8760h)`)
	cmd.Flags().StringVar(&privateKeyOut, "private-key-out", "", "Write the generated private key (PEM) to this file (mode 0600) instead of printing it")
	cmd.MarkFlagsMutuallyExclusive("public-key-file", "private-key-out")
	return cmd
}

func machineKeysRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove USER_ID KEY_ID",
		Short: "Remove a key and end the sessions opened with it",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.delete(envPath() + "/users/" + args[0] + "/keys/" + args[1]); err != nil {
				return err
			}
			newPrinter().ok("Key removed: " + args[1])
			return nil
		},
	}
}
