package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stensonb/aws-cli-oidc/lib"
)

const (
	ProviderFlag    = "provider"
	RoleFlag        = "role"
	MaxDurationFlag = "max-duration"
	UseSecretFlag   = "use-secret"
	JSONFlag        = "json"
)

var getCredCmd = &cobra.Command{
	Use:   "get-cred <OIDC provider name>",
	Short: "Get AWS credentials and out to stdout",
	Long:  `Get AWS credentials and out to stdout through your OIDC provider authentication.`,
	RunE:  getCred,
}

func init() {
	getCredCmd.Flags().StringP(ProviderFlag, "p", "", "OIDC provider name")
	getCredCmd.Flags().StringP(RoleFlag, "r", "", "Override default assume role ARN")
	getCredCmd.Flags().Int32P(MaxDurationFlag, "d", 0, "Override default max session duration, in seconds, of the role session [900-43200]")
	getCredCmd.Flags().BoolP(UseSecretFlag, "s", false, "Store AWS credentials into OS secret store, then load it without re-authentication")
	getCredCmd.Flags().BoolP(JSONFlag, "j", false, "Print the credential as JSON format")
	rootCmd.AddCommand(getCredCmd)
}

func getCred(cmd *cobra.Command, args []string) error {
	providerName, err := cmd.Flags().GetString(ProviderFlag)
	if err != nil {
		return err
	}

	if providerName == "" {
		return fmt.Errorf("the OIDC provider name is required")
	}

	roleArn, err := cmd.Flags().GetString(RoleFlag)
	if err != nil {
		return err
	}

	maxDurationSeconds, err := cmd.Flags().GetInt32(MaxDurationFlag)
	if err != nil {
		return err
	}

	useSecret, err := cmd.Flags().GetBool(UseSecretFlag)
	if err != nil {
		return err
	}

	asJson, err := cmd.Flags().GetBool(JSONFlag)
	if err != nil {
		return err
	}

	client, err := lib.CheckInstalled(cmd.Context(), providerName)
	if err != nil {
		return fmt.Errorf("failed to login OIDC provider")
	}

	return lib.Authenticate(cmd.Context(), client, roleArn, maxDurationSeconds, useSecret, asJson)
}
