package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// metadataCmd manages per-key metadata of users or organizations
// (collection "users" or "organizations").
func metadataCmd(collection, entity string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Read and change one metadata key of a " + entity,
		Long: `Read and change one metadata key. Keys match ^[a-zA-Z0-9_.-]{1,64}$;
values are JSON (at most 4 KiB); metadata holds at most 64 keys and 32 KiB.
Every change is audited.`,
	}
	path := func(id, key string) string { return envPath() + "/" + collection + "/" + id + "/metadata/" + key }
	cmd.AddCommand(&cobra.Command{
		Use:   "get ID KEY",
		Short: "Print one metadata value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(path(args[0], args[1]))
			if err != nil {
				return err
			}
			newPrinter().JSON(data)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "set ID KEY VALUE",
		Short: "Set one key; VALUE is JSON, or a plain string",
		Example: `  iam ` + collection + ` metadata set ID plan '{"tier":"gold"}'
  iam ` + collection + ` metadata set ID region eu`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			value := json.RawMessage(args[2])
			if !json.Valid(value) {
				value, _ = json.Marshal(args[2])
			}
			if _, err := mustClient(cmd).put(path(args[0], args[1]), value); err != nil {
				return err
			}
			newPrinter().ok("Metadata set: " + args[1])
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "delete ID KEY",
		Short: "Remove one key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(path(args[0], args[1])); err != nil {
				return err
			}
			newPrinter().ok("Metadata deleted: " + args[1])
			return nil
		},
	})
	return cmd
}

// jsonInput reads JSON from --data, or --file ("-" is stdin).
func jsonInput(data, file string) (json.RawMessage, error) {
	if (data == "") == (file == "") {
		return nil, fmt.Errorf("give exactly one of --data or --file")
	}
	raw := []byte(data)
	if file != "" {
		var err error
		if file == "-" {
			raw, err = io.ReadAll(os.Stdin)
		} else {
			raw, err = os.ReadFile(file)
		}
		if err != nil {
			return nil, err
		}
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("input is not valid JSON")
	}
	return json.RawMessage(strings.TrimSpace(string(raw))), nil
}

func usersProfileCmd() *cobra.Command {
	var data, file string
	cmd := &cobra.Command{
		Use:   "profile USER_ID",
		Short: "Merge attributes into a user's profile",
		Long: `Merge attributes into a user's profile: top-level keys are replaced, null
removes one. With a user schema (iam user-schema) the result must conform.`,
		Example: `  iam users profile USER_ID --data '{"department":"eng","nickname":null}'`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			patch, err := jsonInput(data, file)
			if err != nil {
				return err
			}
			out, err := mustClient(cmd).patch(envPath()+"/users/"+args[0]+"/profile", patch)
			if err != nil {
				return err
			}
			newPrinter().JSON(out)
			return nil
		},
	}
	cmd.Flags().StringVar(&data, "data", "", "JSON object of attributes")
	cmd.Flags().StringVar(&file, "file", "", "Read the JSON object from a file (- for stdin)")
	return cmd
}

func userSchemaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user-schema",
		Short: "Manage the environment's user profile schema",
		Long: `Manage the environment's user profile schema (JSON Schema 2020-12, type
object). Property annotations:
  "x-iamkit-self": "read" | "write"   the user sees (and edits) it at
                                      /identity/v1/me/profile
  "x-iamkit-claim": "<name>"          released in ID tokens and UserInfo
                                      with the profile scope
Remote $ref are refused. Saving never rewrites profiles; it reports how many
do not conform (they must conform on their next write).`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get",
		Short: "Print the schema and its version",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/user-schema")
			if err != nil {
				return err
			}
			newPrinter().JSON(data)
			return nil
		},
	})
	var file string
	set := &cobra.Command{
		Use:     "set --file schema.json",
		Short:   "Replace the schema",
		Example: `  iam user-schema set --file schema.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			schema, err := jsonInput("", file)
			if err != nil {
				return err
			}
			data, err := mustClient(cmd).put(envPath()+"/user-schema", map[string]json.RawMessage{"schema": schema})
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			var saved struct {
				Version       int `json:"version"`
				NonConforming int `json:"non_conforming"`
			}
			_ = json.Unmarshal(data, &saved)
			p.ok(fmt.Sprintf("User schema saved (version %d); %d existing profiles do not conform", saved.Version, saved.NonConforming))
			return nil
		},
	}
	set.Flags().StringVar(&file, "file", "", "Schema file (- for stdin)")
	cmd.AddCommand(set)
	cmd.AddCommand(&cobra.Command{
		Use:   "delete",
		Short: "Remove the schema: profiles are no longer checked",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(envPath() + "/user-schema"); err != nil {
				return err
			}
			newPrinter().ok("User schema deleted")
			return nil
		},
	})
	return cmd
}
