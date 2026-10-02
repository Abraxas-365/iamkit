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

func eventsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Read the environment's event log",
	}
	cmd.AddCommand(eventsListCmd(), eventsHistoryCmd(), eventsExportCmd())
	return cmd
}

func eventsListCmd() *cobra.Command {
	var types []string
	var subject, organization, after, before string
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List events, newest first (or oldest first with --after)",
		Example: `  iam events list --type user.* --type login.failed
  iam events list --after 0 --limit 200     # read the log as a feed
  iam events list --before 1234             # the page below event 1234`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			params := url.Values{}
			for _, t := range types {
				params.Add("type", t)
			}
			for key, v := range map[string]string{"subject": subject, "organization_id": organization, "after": after, "before": before} {
				if v != "" {
					params.Set(key, v)
				}
			}
			if limit > 0 {
				params.Set("limit", fmt.Sprint(limit))
			}
			path := envPath() + "/events"
			if len(params) > 0 {
				path += "?" + params.Encode()
			}
			data, err := c.get(path)
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "TYPE", "ACTOR", "SUBJECT", "OCCURRED"}, func(m map[string]any) []string {
				actor, _ := m["actor"].(map[string]any)
				subject, _ := m["subject"].(map[string]any)
				return []string{str(m, "id"), str(m, "type"), kindID(actor), kindID(subject), str(m, "occurred_at")}
			})
			if !p.wantJSON() {
				var page struct{ Next int64 }
				if json.Unmarshal(data, &page) == nil && page.Next > 0 {
					flag := "--before"
					if after != "" {
						flag = "--after"
					}
					fmt.Fprintf(os.Stderr, "\nNext page: %s %d\n", flag, page.Next)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&types, "type", nil, "Event type or family (user.created, user.*); repeatable")
	cmd.Flags().StringVar(&subject, "subject", "", "Subject id")
	cmd.Flags().StringVar(&organization, "organization", "", "Organization id")
	cmd.Flags().StringVar(&after, "after", "", "Read oldest first from this event id (0 = the beginning)")
	cmd.Flags().StringVar(&before, "before", "", "Read newest first below this event id")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results (≤ 200)")
	return cmd
}

func eventsHistoryCmd() *cobra.Command {
	var before string
	var limit int
	cmd := &cobra.Command{
		Use:   "history COLLECTION ID",
		Short: "One entity's events newest first, with what each update changed",
		Long: `COLLECTION is users, organizations, applications, oauth-clients, roles or
resources. Updates list their changes as field: old → new.`,
		Example: `  iam events history users 33b4…
  iam events history roles 1a2b… --before 1800`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if before != "" {
				params.Set("before", before)
			}
			if limit > 0 {
				params.Set("limit", fmt.Sprint(limit))
			}
			path := envPath() + "/" + url.PathEscape(args[0]) + "/" + url.PathEscape(args[1]) + "/history"
			if len(params) > 0 {
				path += "?" + params.Encode()
			}
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			p := newPrinter()
			p.table(data, []string{"ID", "TYPE", "ACTOR", "CHANGES", "OCCURRED"}, func(m map[string]any) []string {
				actor, _ := m["actor"].(map[string]any)
				data, _ := m["data"].(map[string]any)
				changes, _ := data["changes"].(map[string]any)
				return []string{str(m, "id"), str(m, "type"), kindID(actor), describeChanges(changes), str(m, "occurred_at")}
			})
			if !p.wantJSON() {
				var page struct{ Next int64 }
				if json.Unmarshal(data, &page) == nil && page.Next > 0 {
					fmt.Fprintf(os.Stderr, "\nNext page: --before %d\n", page.Next)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&before, "before", "", "Read below this event id")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results (≤ 200)")
	return cmd
}

func eventsExportCmd() *cobra.Command {
	var types []string
	var subject, organization, after, output string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the event log as NDJSON (oldest first), e.g. to archive it",
		Example: `  iam events export --file events.ndjson
  iam events export --after 52000 --type user.* >> archive.ndjson`,
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			for _, t := range types {
				params.Add("type", t)
			}
			for key, v := range map[string]string{"subject": subject, "organization_id": organization, "after": after} {
				if v != "" {
					params.Set(key, v)
				}
			}
			path := envPath() + "/events/export"
			if len(params) > 0 {
				path += "?" + params.Encode()
			}
			out := os.Stdout
			if output != "" {
				f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					return err
				}
				defer f.Close()
				out = f
			}
			return mustClient(cmd).stream(path, out)
		},
	}
	cmd.Flags().StringArrayVar(&types, "type", nil, "Event type or family; repeatable")
	cmd.Flags().StringVar(&subject, "subject", "", "Subject id")
	cmd.Flags().StringVar(&organization, "organization", "", "Organization id")
	cmd.Flags().StringVar(&after, "after", "", "Start after this event id (resume an archive)")
	cmd.Flags().StringVar(&output, "file", "", "Write to a new file instead of stdout")
	return cmd
}

// describeChanges renders data.changes as "field: old → new; …".
func describeChanges(changes map[string]any) string {
	keys := make([]string, 0, len(changes))
	for k := range changes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		pair, _ := changes[k].([]any)
		if len(pair) != 2 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s → %s", k, changeValue(pair[0]), changeValue(pair[1])))
	}
	return strings.Join(parts, "; ")
}

func changeValue(v any) string {
	if v == nil {
		return "∅"
	}
	if s, ok := v.(string); ok {
		return s
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

// kindID renders an event actor or subject as kind:id.
func kindID(m map[string]any) string {
	kind, id := str(m, "kind"), str(m, "id")
	if id == "" {
		return kind
	}
	return kind + ":" + id
}
