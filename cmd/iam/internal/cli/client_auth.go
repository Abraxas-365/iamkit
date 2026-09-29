package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// clientAuthFlags are the token endpoint authentication flags shared by
// service accounts and OAuth clients.
type clientAuthFlags struct {
	method, alg, jwksFile, jwksURI string
}

func (f *clientAuthFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.method, "auth-method", "", "Token endpoint authentication: client_secret_basic, client_secret_post or private_key_jwt")
	cmd.Flags().StringVar(&f.alg, "signing-alg", "", "private_key_jwt assertion algorithm (default RS256; PS256, ES256, …)")
	cmd.Flags().StringVar(&f.jwksFile, "jwks-file", "", "private_key_jwt: file with a JSON Web Key Set of public keys")
	cmd.Flags().StringVar(&f.jwksURI, "jwks-uri", "", "private_key_jwt: HTTPS URL of the client's JSON Web Key Set")
}

// apply adds the flags that were set to body.
func (f *clientAuthFlags) apply(cmd *cobra.Command, body map[string]any) error {
	if cmd.Flags().Changed("auth-method") {
		body["token_endpoint_auth_method"] = f.method
	}
	if cmd.Flags().Changed("signing-alg") {
		body["token_endpoint_auth_signing_alg"] = f.alg
	}
	if cmd.Flags().Changed("jwks-uri") {
		body["jwks_uri"] = f.jwksURI
	}
	if f.jwksFile != "" {
		raw, err := os.ReadFile(f.jwksFile)
		if err != nil {
			return err
		}
		if !json.Valid(raw) {
			return fmt.Errorf("%s is not JSON", f.jwksFile)
		}
		body["jwks"] = json.RawMessage(raw)
	}
	return nil
}
