package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// Detections of the risk policy and what each may do. new_device and
// stale_account can notify but not block; the others can block but not notify.
var (
	riskDetections    = []string{"ip_velocity", "user_brute_force", "impossible_travel", "new_device", "stale_account"}
	riskLoginActions  = []string{"off", "log", "challenge", "block"}
	riskSoftActions   = []string{"off", "log", "notify", "challenge"}
	restrictionKinds  = []string{"ip", "country", "email_domain"}
	restrictionAction = []string{"allow", "deny"}
	attemptOutcomes   = []string{"success", "failure", "blocked", "challenged", "captcha_failed"}
)

func riskActionsFor(detection string) []string {
	if detection == "new_device" || detection == "stale_account" {
		return riskSoftActions
	}
	return riskLoginActions
}

func riskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Risk signals: policy, restrictions and the sign-in attempt log",
		Long: `Risk signals watch sign-ins for brute force, impossible travel, new devices
and stale accounts, and can log, notify, challenge (email code) or block.
Restrictions allow or deny by IP range, country or email domain. Without a
policy and restrictions nothing changes for sign-in.`,
	}
	cmd.AddCommand(riskPolicyCmd(), riskRestrictionsCmd(), riskAttemptsCmd(), riskStatusCmd())
	return cmd
}

// ── Policy ──

func riskPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Show or change the environment's risk policy"}
	cmd.AddCommand(riskPolicyGetCmd(), riskPolicySetCmd(), riskPolicyDeleteCmd())
	return cmd
}

func riskPolicyGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Show the risk policy (the default, every detection off, when none is saved)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/risk-policy")
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			var pol struct {
				Actions             map[string]string  `json:"actions"`
				Thresholds          map[string]float64 `json:"thresholds"`
				NotifyUser          bool               `json:"notify_user"`
				BlockIfUnverifiable bool               `json:"block_if_unverifiable"`
				Saved               bool               `json:"saved"`
			}
			if err := json.Unmarshal(data, &pol); err != nil {
				p.JSON(data)
				return nil
			}
			out := map[string]any{"saved": pol.Saved, "notify_user": pol.NotifyUser, "block_if_unverifiable": pol.BlockIfUnverifiable}
			for _, d := range riskDetections {
				a := pol.Actions[d]
				if a == "" {
					a = "off"
				}
				out[d] = a
			}
			for k, v := range pol.Thresholds {
				out[k] = int(v)
			}
			raw, _ := json.Marshal(out)
			p.detail(raw)
			return nil
		},
	}
}

// policyEdit is what "risk policy set" was asked to change; nil = keep.
type policyEdit struct {
	Actions             map[string]string
	Thresholds          map[string]int
	NotifyUser          *bool
	BlockIfUnverifiable *bool
}

func (e policyEdit) empty() bool {
	return len(e.Actions) == 0 && len(e.Thresholds) == 0 && e.NotifyUser == nil && e.BlockIfUnverifiable == nil
}

func (e policyEdit) validate() error {
	for d, a := range e.Actions {
		if !contains(riskActionsFor(d), a) {
			return fmt.Errorf("--%s must be one of %s", strings.ReplaceAll(d, "_", "-"), strings.Join(riskActionsFor(d), ", "))
		}
	}
	for k, v := range e.Thresholds {
		if v < 1 {
			return fmt.Errorf("--%s must be a positive number", strings.ReplaceAll(k, "_", "-"))
		}
	}
	return nil
}

// apply merges the edit into the current policy: PUT replaces the whole
// policy, so the omitted settings are sent back as they are.
func (e policyEdit) apply(current map[string]any) map[string]any {
	actions := map[string]any{}
	if cur, ok := current["actions"].(map[string]any); ok {
		for k, v := range cur {
			actions[k] = v
		}
	}
	for d, a := range e.Actions {
		actions[d] = a
	}
	thresholds := map[string]any{}
	if cur, ok := current["thresholds"].(map[string]any); ok {
		for k, v := range cur {
			thresholds[k] = v
		}
	}
	for k, v := range e.Thresholds {
		thresholds[k] = v
	}
	body := map[string]any{"actions": actions, "thresholds": thresholds}
	notify, _ := current["notify_user"].(bool)
	if cur, ok := current["notify_user"]; !ok || cur == nil {
		notify = true
	}
	if e.NotifyUser != nil {
		notify = *e.NotifyUser
	}
	body["notify_user"] = notify
	block, _ := current["block_if_unverifiable"].(bool)
	if e.BlockIfUnverifiable != nil {
		block = *e.BlockIfUnverifiable
	}
	body["block_if_unverifiable"] = block
	return body
}

var riskThresholdFlags = []struct{ flag, key, help string }{
	{"ip-failures-per-hour", "ip_failures_per_hour", "Failed sign-ins per hour from one IP that trip ip_velocity"},
	{"ip-distinct-logins-per-hour", "ip_distinct_logins_per_hour", "Distinct logins tried per hour from one IP that trip ip_velocity"},
	{"user-failures-per-hour", "user_failures_per_hour", "Failed sign-ins per hour on one account that trip user_brute_force"},
	{"stale-after-days", "stale_after_days", "Days without a sign-in after which an account is stale (7-3650)"},
	{"travel-speed-kmh", "travel_speed_kmh", "Speed above which a change of location is impossible travel (100-20000)"},
}

func riskPolicySetCmd() *cobra.Command {
	actions := map[string]*string{}
	thresholds := map[string]*int{}
	var notifyUser, blockUnverifiable bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Change the risk policy (settings not given keep their value)",
		Long: `Changes the environment's risk policy. Only the flags you give change; the
rest keep their current value (a first save starts from every detection off).

Detections: ip_velocity, user_brute_force and impossible_travel take
off, log, challenge or block; new_device and stale_account take off, log,
notify or challenge. challenge asks for an emailed code. impossible_travel
needs GeoIP on the deployment (see "iam risk status"); new_device only
evaluates clients that send a device id.`,
		Example: `  iam risk policy set --ip-velocity block --new-device challenge
  iam risk policy set --user-failures-per-hour 5 --notify-user=false`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fl := cmd.Flags()
			edit := policyEdit{Actions: map[string]string{}, Thresholds: map[string]int{}}
			for _, d := range riskDetections {
				if fl.Changed(strings.ReplaceAll(d, "_", "-")) {
					edit.Actions[d] = strings.ToLower(strings.TrimSpace(*actions[d]))
				}
			}
			for _, t := range riskThresholdFlags {
				if fl.Changed(t.flag) {
					edit.Thresholds[t.key] = *thresholds[t.key]
				}
			}
			if fl.Changed("notify-user") {
				edit.NotifyUser = &notifyUser
			}
			if fl.Changed("block-if-unverifiable") {
				edit.BlockIfUnverifiable = &blockUnverifiable
			}
			if edit.empty() {
				return fmt.Errorf("nothing to change: give at least one flag")
			}
			if err := edit.validate(); err != nil {
				return err
			}
			c := mustClient(cmd)
			raw, err := c.get(envPath() + "/risk-policy")
			if err != nil {
				return err
			}
			var current map[string]any
			if err := json.Unmarshal(raw, &current); err != nil {
				return fmt.Errorf("reading the current policy: %w", err)
			}
			data, err := c.put(envPath()+"/risk-policy", edit.apply(current))
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			p.ok("Risk policy updated")
			return nil
		},
	}
	f := cmd.Flags()
	for _, d := range riskDetections {
		v := new(string)
		actions[d] = v
		f.StringVar(v, strings.ReplaceAll(d, "_", "-"), "", "Action for "+d+": "+strings.Join(riskActionsFor(d), ", "))
	}
	for _, t := range riskThresholdFlags {
		v := new(int)
		thresholds[t.key] = v
		f.IntVar(v, t.flag, 0, t.help)
	}
	f.BoolVar(&notifyUser, "notify-user", true, "Email the user when a notify action fires")
	f.BoolVar(&blockUnverifiable, "block-if-unverifiable", false, "Block when a detection cannot be evaluated (e.g. GeoIP lookup failed)")
	return cmd
}

func riskPolicyDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Return to the default policy (every detection off)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(envPath() + "/risk-policy"); err != nil {
				return err
			}
			newPrinter().ok("Risk policy deleted; every detection is off")
			return nil
		},
	}
}

// ── Restrictions ──

func riskRestrictionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "restrictions",
		Aliases: []string{"restriction"},
		Short:   "Allow or deny sign-ins by IP range, country or email domain",
		Long: `A deny restriction refuses matching sign-ins and sign-ups before any
credential is checked (403 SIGN_IN_BLOCKED); an allow restriction skips the
risk detections for matching sign-ins (never the CAPTCHA, never a deny).
Country restrictions need GeoIP on the deployment.`,
	}
	cmd.AddCommand(riskRestrictionsListCmd(), riskRestrictionsAddCmd(), riskRestrictionsRemoveCmd())
	return cmd
}

func riskRestrictionsListCmd() *cobra.Command {
	var kind, action string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List restrictions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if kind != "" && !contains(restrictionKinds, kind) {
				return fmt.Errorf("--kind must be one of %s", strings.Join(restrictionKinds, ", "))
			}
			if action != "" && !contains(restrictionAction, action) {
				return fmt.Errorf("--action must be one of %s", strings.Join(restrictionAction, ", "))
			}
			q := url.Values{}
			if kind != "" {
				q.Set("kind", kind)
			}
			if action != "" {
				q.Set("action", action)
			}
			path := envPath() + "/risk-restrictions"
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "KIND", "VALUE", "ACTION", "NOTE"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "kind"), str(m, "value"), str(m, "action"), str(m, "note")}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "", "Filter by kind: "+strings.Join(restrictionKinds, ", "))
	cmd.Flags().StringVar(&action, "action", "", "Filter by action: "+strings.Join(restrictionAction, ", "))
	return cmd
}

func riskRestrictionsAddCmd() *cobra.Command {
	var kind, value, action, note string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a restriction",
		Example: `  iam risk restrictions add --kind ip --value 203.0.113.0/24 --action deny
  iam risk restrictions add --kind country --value KP --action deny
  iam risk restrictions add --kind email_domain --value acme.com --action allow --note "staff"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !contains(restrictionKinds, kind) {
				return fmt.Errorf("--kind must be one of %s", strings.Join(restrictionKinds, ", "))
			}
			if !contains(restrictionAction, action) {
				return fmt.Errorf("--action must be one of %s", strings.Join(restrictionAction, ", "))
			}
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("--value is required")
			}
			body := map[string]any{"kind": kind, "value": strings.TrimSpace(value), "action": action}
			if note != "" {
				body["note"] = note
			}
			data, err := mustClient(cmd).post(envPath()+"/risk-restrictions", body)
			if err != nil {
				return err
			}
			newPrinter().created("Restriction", data)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&kind, "kind", "", "Kind: "+strings.Join(restrictionKinds, ", ")+" (required)")
	f.StringVar(&value, "value", "", "IP address or CIDR, ISO country code, or domain (required)")
	f.StringVar(&action, "action", "", "Action: allow or deny (required)")
	f.StringVar(&note, "note", "", "Note (at most 200 characters)")
	for _, name := range []string{"kind", "value", "action"} {
		cmd.MarkFlagRequired(name)
	}
	return cmd
}

func riskRestrictionsRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove RESTRICTION_ID",
		Aliases: []string{"delete"},
		Short:   "Remove a restriction",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(envPath() + "/risk-restrictions/" + url.PathEscape(args[0])); err != nil {
				return err
			}
			newPrinter().ok("Restriction removed: " + args[0])
			return nil
		},
	}
}

// ── Attempts ──

func riskAttemptsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "attempts",
		Aliases: []string{"attempt"},
		Short:   "Read the sign-in attempt log",
		Long: `Every sign-in, sign-up and code request that reached a risk check is logged
with its outcome, detections and action. The login typed is never stored.`,
	}
	cmd.AddCommand(riskAttemptsListCmd(), riskAttemptsGetCmd())
	return cmd
}

func riskAttemptsListCmd() *cobra.Command {
	var user, ip, outcome, detection, country, before string
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sign-in attempts, newest first",
		Example: `  iam risk attempts list --outcome blocked --limit 20
  iam risk attempts list --ip 203.0.113.9 --before 0194...   # the page below an attempt`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if outcome != "" && !contains(attemptOutcomes, outcome) {
				return fmt.Errorf("--outcome must be one of %s", strings.Join(attemptOutcomes, ", "))
			}
			if detection != "" && !contains(riskDetections, detection) {
				return fmt.Errorf("--detection must be one of %s", strings.Join(riskDetections, ", "))
			}
			q := url.Values{}
			for k, v := range map[string]string{"user_id": user, "ip": ip, "outcome": outcome, "detection": detection, "country": country, "before": before} {
				if v != "" {
					q.Set(k, v)
				}
			}
			if limit > 0 {
				q.Set("limit", strconv.Itoa(limit))
			}
			path := envPath() + "/sign-in-attempts"
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			p := newPrinter()
			p.table(data, []string{"ID", "WHEN", "OUTCOME", "METHOD", "SURFACE", "IP", "COUNTRY", "DETECTIONS", "ACTION"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "created_at"), str(m, "outcome"), str(m, "method"), str(m, "surface"),
					str(m, "ip"), str(m, "country"), collapsePerms(m["detections"]), str(m, "action")}
			})
			if !p.wantJSON() {
				var page struct{ Next string }
				if json.Unmarshal(data, &page) == nil && page.Next != "" {
					fmt.Fprintf(os.Stderr, "\nNext page: --before %s\n", page.Next)
				}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&user, "user", "", "Filter by user ID")
	f.StringVar(&ip, "ip", "", "Filter by client IP")
	f.StringVar(&outcome, "outcome", "", "Filter by outcome: "+strings.Join(attemptOutcomes, ", "))
	f.StringVar(&detection, "detection", "", "Filter by detection: "+strings.Join(riskDetections, ", "))
	f.StringVar(&country, "country", "", "Filter by country (ISO code)")
	f.StringVar(&before, "before", "", "Read the page below this attempt ID")
	f.IntVar(&limit, "limit", 0, "Max results (default 50, at most 200)")
	return cmd
}

func riskAttemptsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get ATTEMPT_ID",
		Short: "Show one sign-in attempt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/sign-in-attempts/" + url.PathEscape(args[0]))
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

// ── Status ──

func riskStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show what the deployment supports: GeoIP, CAPTCHA and risk signals",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/risk/status")
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			var st map[string]any
			if err := json.Unmarshal(data, &st); err != nil {
				p.JSON(data)
				return nil
			}
			out := map[string]any{"captcha": st["captcha"], "risk_signals": st["risk_signals"]}
			if geo, ok := st["geoip"].(map[string]any); ok {
				for k, v := range geo {
					out["geoip_"+k] = v
				}
			}
			raw, _ := json.Marshal(out)
			p.detail(raw)
			return nil
		},
	}
}

// ── Users: devices ──

func usersDevicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "devices USER_ID",
		Short: "List the devices a user signed in from, newest first",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/users/" + url.PathEscape(args[0]) + "/devices")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"FIRST SEEN", "LAST SEEN", "LAST IP", "COUNTRY", "USER AGENT"}, func(m map[string]any) []string {
				return []string{str(m, "first_seen_at"), str(m, "last_seen_at"), str(m, "last_ip"), str(m, "last_country"), str(m, "user_agent")}
			})
			return nil
		},
	}
}
