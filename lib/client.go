package lib

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	input "github.com/natsukagami/go-input"
	"github.com/spf13/viper"
	"github.com/stensonb/aws-cli-oidc/lib/config"
)

type OIDCMetadataResponse struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenIntrospectionEndpoint                 string   `json:"token_introspection_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	CheckSessionIframe                         string   `json:"check_session_iframe"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TLSClientCertificateBoundAccessTokens      bool     `json:"tls_client_certificate_bound_access_tokens"`
}

type OIDCClient struct {
	restClient *RestClient
	base       *WebTarget
	config     *viper.Viper
	metadata   *OIDCMetadataResponse
}

func CheckInstalled(ctx context.Context, name string) (*OIDCClient, error) {
	ui := &input.UI{
		Writer: os.Stdout,
		Reader: os.Stdin,
	}

	return InitializeClient(ctx, ui, name)
}

func InitializeClient(ctx context.Context, ui *input.UI, name string) (*OIDCClient, error) {
	cfg := viper.Sub(name)
	if cfg == nil {
		answer, err := ui.Ask("OIDC provider URL is not set. Do you want to setup the configuration? [Y/n]", &input.Options{
			Default:  "y",
			Loop:     true,
			Required: true,
			ValidateFunc: func(s string) error {
				if strings.ToLower(s) != "y" && strings.ToLower(s) != "n" {
					return fmt.Errorf("must be y or n")
				}
				return nil
			},
		})
		if err != nil {
			return nil, err
		}

		if strings.ToLower(answer) != "y" {
			return nil, fmt.Errorf("failed to initialize client because of no OIDC provider URL")
		}

		if err := RunSetup(ui); err != nil {
			return nil, err
		}
	}

	providerURL := cfg.GetString(config.OIDC_PROVIDER_METADATA_URL)
	insecure, err := strconv.ParseBool(cfg.GetString(config.INSECURE_SKIP_VERIFY))
	if err != nil {
		return nil, fmt.Errorf("failed to parse insecure_skip_verify option in the config: %w", err)
	}

	restClient, err := NewRestClient(&RestClientConfig{
		ClientCert:         cfg.GetString(config.CLIENT_AUTH_CERT),
		ClientKey:          cfg.GetString(config.CLIENT_AUTH_KEY),
		ClientCA:           cfg.GetString(config.CLIENT_AUTH_CA),
		InsecureSkipVerify: insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP client for the OIDC provider: %w", err)
	}

	base := restClient.Target(providerURL)

	res, err := base.Request().Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get OIDC metadata: %w", err)
	}

	if res.Status() != http.StatusOK {
		if res.MediaType() != "" {
			var json map[string]interface{}
			err := res.ReadJson(&json)
			if err == nil {
				return nil, fmt.Errorf("failed to get OIDC metadata, error: %s error_description: %s",
					json["error"], json["error_description"])
			}
		}
		return nil, fmt.Errorf("failed to get OIDC metadata, statusCode: %d", res.Status())
	}

	var metadata *OIDCMetadataResponse

	err = res.ReadJson(&metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OIDC metadata response: %w", err)
	}

	client := &OIDCClient{restClient, base, cfg, metadata}

	if base == nil {
		return nil, fmt.Errorf("failed to initialize client: %w", err)
	}

	return client, nil
}

func (c *OIDCClient) ClientForm() url.Values {
	form := url.Values{}
	clientId := c.config.GetString(config.CLIENT_ID)
	form.Set("client_id", clientId)
	secret := c.config.GetString(config.CLIENT_SECRET)
	if secret != "" {
		form.Set("client_secret", secret)
	}
	return form
}

func (c *OIDCClient) Authorization() *WebTarget {
	return c.restClient.Target(c.metadata.AuthorizationEndpoint)
}

func (c *OIDCClient) Token() *WebTarget {
	return c.restClient.Target(c.metadata.TokenEndpoint)
}

func (c *OIDCClient) RedirectToSuccessfulPage() *WebTarget {
	url := c.config.GetString(config.SUCCESSFUL_REDIRECT_URL)
	if url == "" {
		return nil
	}
	return c.restClient.Target(url)
}

func (c *OIDCClient) RedirectToFailurePage() *WebTarget {
	url := c.config.GetString(config.FAILURE_REDIRECT_URL)
	if url == "" {
		return nil
	}
	return c.restClient.Target(url)
}
