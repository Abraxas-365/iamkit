package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func configureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure IAMKit CLI credentials and defaults",
		Long: `Interactive setup for the IAMKit CLI. Saves configuration to ~/.iam/.

Files created:
  ~/.iam/config        URL and default environment (mode 0600)
  ~/.iam/credentials   API key (mode 0600)

Use --profile to configure named profiles:
  iam configure --profile production

Resolution order (highest wins):
  1. --url / --key / --environment flags
  2. IAMKIT_URL / IAMKIT_KEY / IAMKIT_ENVIRONMENT env vars
  3. ~/.iam/config + ~/.iam/credentials`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profileName := flagProfile
			if profileName == "" {
				profileName = "default"
			}

			dir, err := iamDir()
			if err != nil {
				return err
			}

			configPath := filepath.Join(dir, "config")
			credsPath := filepath.Join(dir, "credentials")

			// Load existing files so we can show current values as defaults
			cfg := parseINI(configPath)
			creds := parseINI(credsPath)

			reader := bufio.NewReader(os.Stdin)

			currentURL := cfg.get(profileName, "url")
			currentKey := creds.get(profileName, "key")
			currentEnv := cfg.get(profileName, "environment")

			fmt.Fprintf(os.Stderr, "Configuring profile: %s\n\n", profileName)

			url := prompt(reader, "IAMKit URL", currentURL)
			key := prompt(reader, "API Key", maskKey(currentKey))
			env := prompt(reader, "Default environment (optional)", currentEnv)

			// Don't save the masked version — only update if the user typed something new
			if key == maskKey(currentKey) {
				key = currentKey
			}

			cfg.set(profileName, "url", url)
			if env != "" {
				cfg.set(profileName, "environment", env)
			}
			creds.set(profileName, "key", key)

			if err := cfg.write(configPath); err != nil {
				return fmt.Errorf("writing config: %w", err)
			}
			if err := creds.write(credsPath); err != nil {
				return fmt.Errorf("writing credentials: %w", err)
			}

			fmt.Fprintf(os.Stderr, "\nConfiguration saved to %s\n", dir)
			return nil
		},
	}

	return cmd
}

// prompt shows a prompt with an optional default value and reads a line.
func prompt(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultVal)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

// maskKey shows only the first 12 chars of a key for confirmation.
func maskKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12] + "****"
}
