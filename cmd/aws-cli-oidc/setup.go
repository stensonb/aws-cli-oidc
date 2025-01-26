package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stensonb/aws-cli-oidc/lib"
	"github.com/stensonb/aws-cli-oidc/lib/config"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: fmt.Sprintf("Interactive setup of %s", config.AWS_CLI_OIDC),
	Long:  fmt.Sprintf(`Interactive setup of %s. Will prompt you for OIDC provider URL and other settings.`, config.AWS_CLI_OIDC),
	RunE:  setup,
}

func init() {
	rootCmd.AddCommand(setupCmd)
}

func setup(cmd *cobra.Command, args []string) error {
	return lib.RunSetup(nil)
}
