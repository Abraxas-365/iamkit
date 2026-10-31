package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// permissionDescriptionFile is the file `descriptions set` reads: the
// whole set, as the API takes it.
type permissionDescriptionFile struct {
	Items []struct {
		Permission  string `json:"permission"`
		Locale      string `json:"locale"`
		DisplayName string `json:"display_name"`
		Description string `json:"description"`
	} `json:"items"`
}

func resourceDescriptionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "descriptions",
		Aliases: []string{"permission-descriptions"},
		Short:   "How people read a resource's permissions (names and sentences, translated)",
		Long: `Each permission of a resource's catalog can carry a display name (at most 80
characters) and a description (at most 300), plain text, in a default
language (locale "") and in any available language ("es", "pt-BR"). The
consent page, connected apps and the console show them instead of the
permission's name; without a text the name is shown. Removing a permission
from the catalog deletes its descriptions.`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get RESOURCE_ID",
		Short: "Show the stored descriptions, every language",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/resources/" + args[0] + "/permission-descriptions")
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			var out struct {
				Items json.RawMessage `json:"items"`
			}
			if err := json.Unmarshal(data, &out); err != nil {
				return err
			}
			p.table(out.Items, []string{"PERMISSION", "LOCALE", "NAME", "DESCRIPTION"}, func(m map[string]any) []string {
				return []string{str(m, "permission"), str(m, "locale"), str(m, "display_name"), str(m, "description")}
			})
			return nil
		},
	})
	var file string
	set := &cobra.Command{
		Use:   "set RESOURCE_ID --file descriptions.json",
		Short: "Replace the whole set of descriptions from a JSON file",
		Long: `Replaces the resource's descriptions with the file's: {"items": [{"permission",
"locale", "display_name", "description"}]}. Locale "" (or absent) is the
default text. Every permission must be in the catalog. An empty items list
clears them; putting the same file again changes nothing.`,
		Example: `  iam resources descriptions set RES --file descriptions.json
  iam resources descriptions get RES -o json > descriptions.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var in permissionDescriptionFile
			if err := readJSON(file, &in); err != nil {
				return err
			}
			if in.Items == nil {
				return fmt.Errorf("%s: items is required (use [] to clear)", file)
			}
			if _, err := mustClient(cmd).put(envPath()+"/resources/"+args[0]+"/permission-descriptions", in); err != nil {
				return err
			}
			newPrinter().ok(fmt.Sprintf("Permission descriptions updated: %s (%d)", args[0], len(in.Items)))
			return nil
		},
	}
	set.Flags().StringVar(&file, "file", "", `JSON file with the whole set ("-" = stdin)`)
	_ = set.MarkFlagRequired("file")
	cmd.AddCommand(set)
	return cmd
}
