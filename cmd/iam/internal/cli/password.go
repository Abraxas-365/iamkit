package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func passwordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "password",
		Short: "Manage your own console password",
		Long: `Manage the console password of the operator the configured key belongs to.

A password is always your own: the API has no way to set another operator's.`,
	}
	cmd.AddCommand(passwordStatusCmd())
	cmd.AddCommand(passwordSetCmd())
	return cmd
}

func passwordStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether you have a password and may sign in with it",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get("/password")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func passwordSetCmd() *cobra.Command {
	var stdin, currentStdin bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set or change your password",
		Long: `Set or change your console password (12-72 characters).

The password is read without echo from the terminal, or from standard input
with --password-stdin. There is deliberately no --password flag: it would end
up in the shell history and the process list.

With a management key and no password yet, nothing else is needed. When you
already have a password, the current one is required too: it is prompted for,
or read with --current-password-stdin (first line = current, second = new).`,
		Example: `  iam password set
  printf '%s\n' "$NEW" | iam password set --password-stdin
  printf '%s\n%s\n' "$OLD" "$NEW" | iam password set --current-password-stdin --password-stdin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			in := bufio.NewReader(os.Stdin)
			interactive := term.IsTerminal(int(os.Stdin.Fd()))
			if !interactive && !stdin && !currentStdin {
				return errors.New("standard input is not a terminal: pass --password-stdin (and --current-password-stdin if you already have a password)")
			}

			var current string
			if currentStdin {
				v, err := readLine(in)
				if err != nil {
					return fmt.Errorf("current password: %w", err)
				}
				current = v
			} else if interactive {
				// Only ask for the current password when the server wants it.
				if status, err := c.get("/password"); err == nil && passwordIsSet(status) {
					v, err := promptSecret("Current password: ")
					if err != nil {
						return err
					}
					current = v
				}
			}

			var password string
			if stdin || currentStdin {
				v, err := readLine(in)
				if err != nil {
					return fmt.Errorf("new password: %w", err)
				}
				password = v
			} else {
				first, err := promptSecret("New password (12-72 characters): ")
				if err != nil {
					return err
				}
				again, err := promptSecret("Repeat new password: ")
				if err != nil {
					return err
				}
				if first != again {
					return errors.New("the passwords do not match")
				}
				password = first
			}

			body := map[string]string{"password": password}
			if current != "" {
				body["current_password"] = current
			}
			if _, err := c.post("/password", body); err != nil {
				return err
			}
			newPrinter().ok("Password set. Sign in to the console with your email and this password.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&stdin, "password-stdin", false, "Read the new password from standard input")
	cmd.Flags().BoolVar(&currentStdin, "current-password-stdin", false, "Read the current password from standard input (before the new one)")
	return cmd
}

// readLine reads one line, without its line ending.
func readLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		if errors.Is(err, io.EOF) {
			return "", errors.New("no value on standard input")
		}
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("empty value on standard input")
	}
	return line, nil
}

// promptSecret reads a line from the terminal without echoing it.
func promptSecret(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", errors.New("the password cannot be empty")
	}
	return string(b), nil
}

// passwordIsSet reads {"set": bool} from GET /password.
func passwordIsSet(raw []byte) bool {
	var status struct {
		Set bool `json:"set"`
	}
	return json.Unmarshal(raw, &status) == nil && status.Set
}
