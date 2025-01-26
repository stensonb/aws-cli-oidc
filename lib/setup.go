package lib

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	input "github.com/natsukagami/go-input"
	"github.com/spf13/viper"
	"github.com/stensonb/aws-cli-oidc/lib/config"
	"github.com/stensonb/aws-cli-oidc/lib/log"
)

func RunSetup(ui *input.UI) error {
	if ui == nil {
		ui = &input.UI{
			Writer: os.Stdout,
			Reader: os.Stdin,
		}
	}

	providerName, err := ui.Ask("OIDC provider name:", &input.Options{
		Loop:     true,
		Required: true,
	})
	if err != nil {
		return err
	}

	server, err := ui.Ask("OIDC provider metadata URL (https://your-oidc-provider/.well-known/openid-configuration):", &input.Options{
		Loop:     true,
		Required: true,
	})
	if err != nil {
		return err
	}

	additionalQuery, err := ui.Ask("Additional query for OIDC authentication request (ie, 'foo=bar&bing=bash') (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	if err != nil {
		return err
	}

	successfulRedirectURL, err := ui.Ask("Successful redirect URL (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	if err != nil {
		return err
	}

	failureRedirectURL, err := ui.Ask("Failure redirect URL (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	if err != nil {
		return err
	}

	clientID, err := ui.Ask("Client ID which is registered in the OIDC provider:", &input.Options{
		Loop:     true,
		Required: true,
	})
	if err != nil {
		return err
	}

	clientSecret, err := ui.Ask("Client secret which is registered in the OIDC provider (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	if err != nil {
		return err
	}

	clientAuthCert, err := ui.Ask("A PEM encoded certificate file which is required to access the OIDC provider with mTLS (Default: none):", &input.Options{
		Default:  "",
		Required: false,
	})
	if err != nil {
		return err
	}

	var clientAuthKey string
	var clientAuthCA string

	if clientAuthCert != "" {
		clientAuthKey, err = ui.Ask("A PEM encoded private key file which is required to access the OIDC provider with mTLS (Default: none):", &input.Options{
			Required: true,
			Loop:     true,
		})
		if err != nil {
			return err
		}

		clientAuthCA, err = ui.Ask("A PEM encoded CA's certificate file which is required to access the OIDC provider with mTLS (Default: none):", &input.Options{
			Required: true,
			Loop:     true,
		})
		if err != nil {
			return err
		}
	}

	insecureSkipVerify, err := ui.Ask("Insecure mode for HTTPS access (Default: false):", &input.Options{
		Default:  "false",
		Required: false,
		ValidateFunc: func(s string) error {
			if strings.ToLower(s) != "false" || strings.ToLower(s) != "true" {
				return fmt.Errorf("must be 'true' or 'false'")
			}
			return nil
		},
	})
	if err != nil {
		return err
	}

	answerFedType, err := ui.Ask(fmt.Sprintf("Choose type of AWS federation [%s/%s]:", config.AWS_FEDERATION_TYPE_OIDC, config.AWS_FEDERATION_TYPE_SAML2), &input.Options{
		Required: true,
		Loop:     true,
		ValidateFunc: func(s string) error {
			if s != config.AWS_FEDERATION_TYPE_SAML2 && s != config.AWS_FEDERATION_TYPE_OIDC {
				return fmt.Errorf("must be '%s' or '%s'", config.AWS_FEDERATION_TYPE_OIDC, config.AWS_FEDERATION_TYPE_SAML2)
			}
			return nil
		},
	})
	if err != nil {
		return err
	}

	maxSessionDurationSeconds, err := ui.Ask("The max session duration, in seconds, of the role session [900-43200] (Default: 3600):", &input.Options{
		Default:  "3600",
		Required: true,
		Loop:     true,
		ValidateFunc: func(s string) error {
			// TODO: DRY parsing duration logic -- search for strconv.ParseInt
			i, err := strconv.ParseInt(s, 10, 32)
			if err != nil || i < 900 || i > 43200 {
				return fmt.Errorf("must be at least 900, no more than 43200")
			}
			return nil
		},
	})
	if err != nil {
		return err
	}

	defaultIAMRoleArn, err := ui.Ask("The default IAM Role ARN when you have multiple roles, as arn:aws:iam::<account-id>:role/<role-name> (Default: none):", &input.Options{
		Default:  "",
		Required: false,
		Loop:     true,
		ValidateFunc: func(s string) error {
			if s == "" {
				return nil
			}

			parsedArn, err := arn.Parse(s)
			if err != nil {
				return fmt.Errorf("must be ARN")
			}

			if !strings.HasPrefix(parsedArn.Resource, "role/") {
				return fmt.Errorf("must be IAM Role ARN")
			}

			return nil
		},
	})
	if err != nil {
		return err
	}

	cfg := map[string]string{
		config.OIDC_PROVIDER_METADATA_URL:                   server,
		config.OIDC_AUTHENTICATION_REQUEST_ADDITIONAL_QUERY: additionalQuery,
		config.SUCCESSFUL_REDIRECT_URL:                      successfulRedirectURL,
		config.FAILURE_REDIRECT_URL:                         failureRedirectURL,
		config.CLIENT_ID:                                    clientID,
		config.CLIENT_SECRET:                                clientSecret,
		config.CLIENT_AUTH_CERT:                             clientAuthCert,
		config.CLIENT_AUTH_KEY:                              clientAuthKey,
		config.CLIENT_AUTH_CA:                               clientAuthCA,
		config.INSECURE_SKIP_VERIFY:                         insecureSkipVerify,
		config.AWS_FEDERATION_TYPE:                          answerFedType,
		config.MAX_SESSION_DURATION_SECONDS:                 maxSessionDurationSeconds,
		config.DEFAULT_IAM_ROLE_ARN:                         defaultIAMRoleArn,
	}

	if answerFedType == config.AWS_FEDERATION_TYPE_OIDC {
		if err := oidcSetup(ui, cfg); err != nil {
			return err
		}
	} else if answerFedType == config.AWS_FEDERATION_TYPE_SAML2 {
		if err := saml2Setup(ui, cfg); err != nil {
			return err
		}
	}

	viper.Set(providerName, cfg)

	err = os.MkdirAll(config.ConfigPath(), 0700)
	if err != nil {
		return err
	}

	configPath := filepath.Join(config.ConfigPath(), "config.yaml")
	viper.SetConfigFile(configPath)

	err = viper.WriteConfig()
	if err != nil {
		return fmt.Errorf("failed to write %s", configPath)
	}

	log.Writeln("Saved %s", configPath)

	return nil
}

func oidcSetup(ui *input.UI, cfg map[string]string) error {
	awsRoleSessionName, err := ui.Ask("AWS federation roleSessionName:", &input.Options{
		Required: true,
		Loop:     true,
	})
	if err != nil {
		return err
	}

	cfg[config.AWS_FEDERATION_ROLE_SESSION_NAME] = awsRoleSessionName

	return nil
}

func saml2Setup(ui *input.UI, cfg map[string]string) error {
	// TODO: why string comparison here?
	answer, err := ui.Ask(`Select the subject token type to exchange for SAML2 assertion:
	1. Access Token (urn:ietf:params:oauth:token-type:access_token)
	2. ID Token (urn:ietf:params:oauth:token-type:id_token)
  `, &input.Options{
		Required: true,
		Loop:     true,
		ValidateFunc: func(s string) error {
			if s != "1" && s != "2" {
				return fmt.Errorf("must be number")
			}
			return nil
		},
	})
	if err != nil {
		return err
	}

	var subjectTokenType string
	if answer == "1" {
		subjectTokenType = config.TOKEN_TYPE_ACCESS_TOKEN
	} else if answer == "2" {
		subjectTokenType = config.TOKEN_TYPE_ID_TOKEN
	}
	cfg[config.OIDC_PROVIDER_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE] = subjectTokenType

	audience, err := ui.Ask("Audience for token exchange:", &input.Options{
		Required: true,
		Loop:     true,
	})
	if err != nil {
		return err
	}

	cfg[config.OIDC_PROVIDER_TOKEN_EXCHANGE_AUDIENCE] = audience

	return nil
}
