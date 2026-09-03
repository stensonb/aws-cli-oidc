package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stensonb/aws-cli-oidc/lib/config"
	"github.com/stensonb/aws-cli-oidc/lib/log"
	"github.com/stensonb/aws-cli-oidc/version"
)

var rootCmd = &cobra.Command{
	Use:     config.AWS_CLI_OIDC,
	Short:   "CLI tool for retrieving AWS temporary credentials using OIDC provider",
	Long:    `CLI tool for retrieving AWS temporary credentials using OIDC provider`,
	Version: version.Version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Exit(err)
	}
}

var debug bool

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "v", false, "Print verbose debug output, including the ID token, SAML assertion, and STS request/response details")
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.SetConfigFile(config.ConfigPath() + "/config.yaml")

	if err := viper.ReadInConfig(); err == nil {
		log.Writeln("Using config file: %s", viper.ConfigFileUsed())
	}

	log.IsTraceEnabled = debug
}
