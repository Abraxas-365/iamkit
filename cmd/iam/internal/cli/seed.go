package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func seedCmd() *cobra.Command {
	var (
		projectName     string
		envName         string
		orgName         string
		appName         string
		redirectURIs    string
		resourceName    string
		resourcePrefix  string
		resourceAud     string
		permissions     string
		userName        string
		userEmail       string
		userPassword    string
		grantPerms      string
	)

	cmd := &cobra.Command{
		Use:   "seed",
		Short: "Bootstrap a full environment (project, env, org, app, resource, user, membership, grant)",
		Long: `Seed creates a complete IAMKit environment in one command.
Designed for deployment init scripts and CI pipelines.
Outputs a JSON object with all created IDs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			p := newPrinter()

			if grantPerms == "" {
				grantPerms = permissions
			}

			// Project
			fmt.Fprintln(cmd.ErrOrStderr(), "• Creating project:", projectName)
			data, err := c.post("/projects", map[string]string{"name": projectName})
			if err != nil {
				return fmt.Errorf("creating project: %w", err)
			}
			projectID := mustID(data)

			// Environment
			fmt.Fprintln(cmd.ErrOrStderr(), "• Creating environment:", envName)
			data, err = c.post("/projects/"+projectID+"/environments", map[string]string{"name": envName})
			if err != nil {
				return fmt.Errorf("creating environment: %w", err)
			}
			envID := mustID(data)
			e := "/environments/" + envID

			// Organization
			fmt.Fprintln(cmd.ErrOrStderr(), "• Creating organization:", orgName)
			data, err = c.post(e+"/organizations", map[string]string{"name": orgName})
			if err != nil {
				return fmt.Errorf("creating organization: %w", err)
			}
			orgID := mustID(data)

			// Application
			fmt.Fprintln(cmd.ErrOrStderr(), "• Creating application:", appName)
			var uris []string
			if redirectURIs != "" {
				uris = strings.Split(redirectURIs, ",")
			}
			data, err = c.post(e+"/applications", map[string]any{
				"name": appName, "redirect_uris": uris,
			})
			if err != nil {
				return fmt.Errorf("creating application: %w", err)
			}
			appID := mustID(data)

			// Resource
			fmt.Fprintln(cmd.ErrOrStderr(), "• Creating resource:", resourceName)
			perms := splitCSV(permissions)
			data, err = c.post(e+"/resources", map[string]any{
				"name": resourceName, "prefix": resourcePrefix,
				"audience": resourceAud, "permissions": perms,
			})
			if err != nil {
				return fmt.Errorf("creating resource: %w", err)
			}
			resourceID := mustID(data)

			// Link app → resource
			fmt.Fprintln(cmd.ErrOrStderr(), "• Linking application → resource")
			_, err = c.post(e+"/application-resources", map[string]string{
				"application_id": appID, "resource_id": resourceID,
			})
			if err != nil {
				return fmt.Errorf("linking app to resource: %w", err)
			}

			// User
			fmt.Fprintln(cmd.ErrOrStderr(), "• Creating user:", userEmail)
			userBody := map[string]any{"name": userName, "email": userEmail}
			if userPassword != "" {
				userBody["password"] = userPassword
			}
			data, err = c.post(e+"/users", userBody)
			if err != nil {
				return fmt.Errorf("creating user: %w", err)
			}
			userID := mustID(data)

			// Membership
			fmt.Fprintln(cmd.ErrOrStderr(), "• Adding membership")
			_, err = c.post(e+"/memberships", map[string]string{
				"organization_id": orgID, "user_id": userID,
			})
			if err != nil {
				return fmt.Errorf("adding membership: %w", err)
			}

			// Grant
			fmt.Fprintln(cmd.ErrOrStderr(), "• Setting grant")
			gPerms := splitCSV(grantPerms)
			data, err = c.put(e+"/grants", map[string]any{
				"organization_id": orgID, "user_id": userID,
				"resource_id": resourceID, "permissions": gPerms,
			})
			if err != nil {
				return fmt.Errorf("setting grant: %w", err)
			}
			grantID := mustID(data)

			fmt.Fprintln(cmd.ErrOrStderr(), "• Seed complete")

			// Output all IDs
			result := map[string]string{
				"project_id":      projectID,
				"environment_id":  envID,
				"organization_id": orgID,
				"application_id":  appID,
				"resource_id":     resourceID,
				"user_id":         userID,
				"grant_id":        grantID,
			}
			out, _ := json.MarshalIndent(result, "", "  ")
			p.out.Write(out)
			fmt.Fprintln(p.out)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&projectName, "project", "Default", "Project name")
	f.StringVar(&envName, "env", "Development", "Environment name")
	f.StringVar(&orgName, "org", "Default", "Organization name")
	f.StringVar(&appName, "app", "Web App", "Application name")
	f.StringVar(&redirectURIs, "redirect-uris", "http://localhost:3000/callback", "Comma-separated redirect URIs")
	f.StringVar(&resourceName, "resource", "API", "Resource name")
	f.StringVar(&resourcePrefix, "prefix", "api", "Resource prefix")
	f.StringVar(&resourceAud, "audience", "http://localhost:8080", "Resource audience URL")
	f.StringVar(&permissions, "permissions", "api:read,api:write", "Comma-separated permissions")
	f.StringVar(&userName, "user-name", "Admin", "User name")
	f.StringVar(&userEmail, "user-email", "admin@example.com", "User email")
	f.StringVar(&userPassword, "user-password", "", "User password (optional)")
	f.StringVar(&grantPerms, "grant-permissions", "", "Grant permissions (defaults to --permissions)")

	return cmd
}

func mustID(data json.RawMessage) string {
	var obj map[string]any
	if json.Unmarshal(data, &obj) == nil {
		if id, ok := obj["id"]; ok {
			return fmt.Sprintf("%v", id)
		}
	}
	return ""
}
