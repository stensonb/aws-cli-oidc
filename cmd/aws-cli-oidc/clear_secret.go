package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stensonb/aws-cli-oidc/lib/log"
	"github.com/stensonb/aws-cli-oidc/lib/secretstore"
)

var clearSecretCmd = &cobra.Command{
	Use:   "clear-secret",
	Short: "Clear OS secret store that saves AWS credentials",
	Long:  `Clear OS secret store that saves AWS credentials.`,
	RunE:  clearSecret,
}

func init() {
	rootCmd.AddCommand(clearSecretCmd)
}

func clearSecret(cmd *cobra.Command, args []string) error {
	ss, err := secretstore.NewSecretStore(cmd.Context(), "")
	if err != nil {
		return err
	}

	if err := ss.Clear(cmd.Context()); err != nil {
		return fmt.Errorf("failed to clear the secret store: %w", err)
	}
	log.Write("The secret store has been cleared")

	return nil
}
