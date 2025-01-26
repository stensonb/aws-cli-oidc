package lib

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	awsCfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/beevik/etree"
	pkce "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/pkg/browser"
	"github.com/stensonb/aws-cli-oidc/lib/config"
	"github.com/stensonb/aws-cli-oidc/lib/log"
	"github.com/stensonb/aws-cli-oidc/lib/secretstore"
	"github.com/stensonb/aws-cli-oidc/lib/types"
)

const (
	LocalhostIPAddress = "127.0.0.1"
)

func Authenticate(ctx context.Context, client *OIDCClient, roleArn string, maxSessionDurationSeconds int32, useSecret, asJson bool) error {
	// Resolve target IAM Role ARN
	defaultIAMRoleArn := client.config.GetString(config.DEFAULT_IAM_ROLE_ARN)
	if roleArn == "" {
		roleArn = defaultIAMRoleArn
	}

	var awsCreds *types.AWSCredentials
	var err error

	ss, err := secretstore.NewSecretStore(ctx, "")
	if err != nil {
		return err
	}

	// Try to reuse stored credential in secret
	if useSecret {
		awsCreds, err = ss.AWSCredential(roleArn)
	}

	if !isValid(ctx, awsCreds) || err != nil {
		tokenResponse, err := doLogin(ctx, client)
		if err != nil {
			return fmt.Errorf("failed to login the OIDC provider: %w", err)
		}

		log.Writeln("Login successful!")
		log.Traceln("ID token: %s", tokenResponse.IDToken)

		awsFedType := client.config.GetString(config.AWS_FEDERATION_TYPE)

		// Resolve max duration
		if maxSessionDurationSeconds <= 0 {
			maxSessionDurationSecondsString := client.config.GetString(config.MAX_SESSION_DURATION_SECONDS)
			parsedMaxSessionDurationSeconds, err := strconv.ParseInt(maxSessionDurationSecondsString, 10, 32)
			maxSessionDurationSeconds = int32(parsedMaxSessionDurationSeconds)
			if err != nil {
				maxSessionDurationSeconds = 3600
			}
		}

		if awsFedType == config.AWS_FEDERATION_TYPE_OIDC {
			awsCreds, err = GetCredentialsWithOIDC(ctx, client, tokenResponse.IDToken, roleArn, maxSessionDurationSeconds)
			if err != nil {
				return fmt.Errorf("failed to get AWS credentials with OIDC: %w", err)
			}
		} else if awsFedType == config.AWS_FEDERATION_TYPE_SAML2 {
			samlAssertion, err := getSAMLAssertion(ctx, client, tokenResponse)
			if err != nil {
				return fmt.Errorf("failed to get SAML2 assertion from OIDC provider: %w", err)
			}

			samlResponse, err := createSAMLResponse(samlAssertion)
			if err != nil {
				return fmt.Errorf("failed to create SAML Response: %w", err)
			}

			awsCreds, err = GetCredentialsWithSAML(ctx, samlResponse, maxSessionDurationSeconds, roleArn)
			if err != nil {
				return fmt.Errorf("failed to get AWS credentials with SAML2: %w", err)
			}
		} else {
			return fmt.Errorf("invalid AWS federation type")
		}

		if useSecret {
			// Store into secret
			if err := ss.SaveAWSCredential(ctx, roleArn, awsCreds); err != nil {
				return err
			}
			log.Writeln("The AWS credentials have been saved in OS secret store")
		}
	}

	if asJson {
		awsCreds.Version = 1

		jsonBytes, err := json.Marshal(awsCreds)
		if err != nil {
			return fmt.Errorf("failed to marshal AWS credential response to JSON: %w", err)
		}
		_, err = fmt.Println(string(jsonBytes))
		if err != nil {
			return err
		}
	} else {
		log.Writeln("")

		log.Export("AWS_ACCESS_KEY_ID", awsCreds.AWSAccessKey)
		log.Export("AWS_SECRET_ACCESS_KEY", awsCreds.AWSSecretKey)
		log.Export("AWS_SESSION_TOKEN", awsCreds.AWSSessionToken)
	}

	return nil
}

func isValid(ctx context.Context, cred *types.AWSCredentials) bool {
	if cred == nil {
		return false
	}

	gctx, gCancel := context.WithTimeout(ctx, 10*time.Second)
	defer gCancel()

	cfg, err := awsCfg.LoadDefaultConfig(ctx,
		awsCfg.WithRegion("aws-global"), // TODO: make configurable
		awsCfg.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				cred.AWSAccessKey,
				cred.AWSSecretKey,
				cred.AWSSessionToken,
			),
		),
	)
	if err != nil {
		log.Writeln("Failed to load credentials")
		return false
	}

	svc := sts.NewFromConfig(cfg)

	input := &sts.GetCallerIdentityInput{}

	_, err = svc.GetCallerIdentity(gctx, input)

	if err != nil {
		log.Writeln("The previous credential isn't valid")
		return false
	}

	return true
}

func getSAMLAssertion(ctx context.Context, client *OIDCClient, tokenResponse *types.TokenResponse) (string, error) {
	audience := client.config.GetString(config.OIDC_PROVIDER_TOKEN_EXCHANGE_AUDIENCE)
	subjectTokenType := client.config.GetString(config.OIDC_PROVIDER_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE)

	var subjectToken string
	if subjectTokenType == config.TOKEN_TYPE_ID_TOKEN {
		subjectToken = tokenResponse.IDToken
	} else if subjectTokenType == config.TOKEN_TYPE_ACCESS_TOKEN {
		subjectToken = tokenResponse.AccessToken
	}

	form := client.ClientForm()
	form.Set("audience", audience)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", subjectTokenType)
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:saml2")

	res, err := client.Token().
		Request().
		Form(form).
		Post(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to post form for token: %w", err)
	}

	log.Traceln("Exchanged SAML assertion response status: %d", res.Status())

	if res.Status() != http.StatusOK {
		if res.MediaType() != "" {
			var json map[string]interface{}
			err := res.ReadJson(&json)
			if err == nil {
				return "", fmt.Errorf("failed to exchange saml2 token, error: %s error_description: %s",
					json["error"], json["error_description"])
			}
		}
		return "", fmt.Errorf("failed to exchange saml2 token, statusCode: %d", res.Status())
	}

	var saml2TokenResponse *types.TokenResponse
	err = res.ReadJson(&saml2TokenResponse)
	if err != nil {
		return "", fmt.Errorf("failed to parse token exchange response: %w", err)
	}

	log.Traceln("SAML2 Assertion: %s", saml2TokenResponse.AccessToken)

	// TODO: Validation
	return saml2TokenResponse.AccessToken, nil
}

func createSAMLResponse(samlAssertion string) (string, error) {
	s, err := base64.RawURLEncoding.DecodeString(samlAssertion)
	if err != nil {
		return "", fmt.Errorf("failed to decode SAML2 assertion: %w", err)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(s); err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}

	assertionElement := doc.FindElement(".//Assertion")
	if assertionElement == nil {
		return "", fmt.Errorf("no Assertion element")
	}

	issuerElement := assertionElement.FindElement("./Issuer")
	if issuerElement == nil {
		return "", fmt.Errorf("no Issuer element")
	}

	subjectConfirmationDataElement := doc.FindElement(".//SubjectConfirmationData")
	if subjectConfirmationDataElement == nil {
		return "", fmt.Errorf("no SubjectConfirmationData element")
	}

	recipient := subjectConfirmationDataElement.SelectAttr("Recipient")
	if recipient == nil {
		return "", fmt.Errorf("no Recipient attribute")
	}

	issueInstant := assertionElement.SelectAttr("IssueInstant")
	if issueInstant == nil {
		return "", fmt.Errorf("no IssueInstant attribute")
	}

	newDoc := etree.NewDocument()

	samlp := newDoc.CreateElement("samlp:Response")
	samlp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	if assertionElement.Space != "" {
		samlp.CreateAttr("xmlns:"+assertionElement.Space, "urn:oasis:names:tc:SAML:2.0:assertion")
	}
	samlp.CreateAttr("Destination", recipient.Value)
	samlp.CreateAttr("Version", "2.0")
	samlp.CreateAttr("IssueInstant", issueInstant.Value)
	samlp.AddChild(issuerElement.Copy())

	status := samlp.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	assertionElement.RemoveAttr("xmlns:saml")
	samlp.AddChild(assertionElement)

	samlResponse, err := newDoc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("failed to write samlResponse: %w", err)
	}

	return samlResponse, nil
}

func doLogin(ctx context.Context, client *OIDCClient) (*types.TokenResponse, error) {
	// TODO: make ip address configurable
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:", LocalhostIPAddress))
	if err != nil {
		return nil, fmt.Errorf("cannot start local http server to handle login redirect: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	clientId := client.config.GetString(config.CLIENT_ID)
	redirect := fmt.Sprintf("http://%s:%d", LocalhostIPAddress, port)

	v, err := pkce.CreateCodeVerifierWithLength(pkce.MaxLength)
	if err != nil {
		return nil, fmt.Errorf("cannot generate OAuth2 PKCE code_challenge: %w", err)
	}
	challenge := v.CodeChallengeS256()
	verifier := v.String()

	authReq := client.Authorization().
		QueryParam("response_type", "code").
		QueryParam("client_id", clientId).
		QueryParam("redirect_uri", redirect).
		QueryParam("code_challenge", challenge).
		QueryParam("code_challenge_method", "S256").
		QueryParam("scope", "openid")

	additionalQuery := client.config.GetString(config.OIDC_AUTHENTICATION_REQUEST_ADDITIONAL_QUERY)

	// TODO: move additionalQuery validation somewhere else
	u, err := url.ParseQuery(additionalQuery)
	if err != nil {
		return nil, fmt.Errorf("invalid additional query: %s : %w", additionalQuery, err)
	}
	for k, vals := range u {
		for _, v := range vals {
			authReq.QueryParam(k, v)
		}
	}

	launchUrl := authReq.Url()

	code, err := launch(ctx, client, launchUrl.String(), listener)
	if err != nil {
		return nil, fmt.Errorf("login failed, can't retrieve authorization code: %w", err)
	}

	return codeToToken(ctx, client, verifier, code, redirect)
}

var m sync.Once

func buildHandler(client *OIDCClient, c codeChan, err errChan) func(res http.ResponseWriter, req *http.Request) {
	return func(res http.ResponseWriter, req *http.Request) {
		// we ensure this handler is only ever called once
		m.Do(func() {
			q := req.URL.Query()
			code := q.Get("code")

			res.Header().Set(ContentType, "text/html")

			// Redirect to user-defined successful/failure page
			successful := client.RedirectToSuccessfulPage()
			if successful != nil && code != "" {
				url := successful.Url()
				res.Header().Set("Location", url.String())
				res.WriteHeader(http.StatusFound)
			}
			failure := client.RedirectToFailurePage()
			if failure != nil && code == "" {
				url := failure.Url()
				res.Header().Set("Location", url.String())
				res.WriteHeader(http.StatusFound)
			}

			message := "Login "
			if code != "" {
				message += "successful"
			} else {
				message += "failed"
			}
			res.Header().Set("Cache-Control", "no-store")
			res.Header().Set("Pragma", "no-cache")
			res.WriteHeader(http.StatusOK)
			_, e := res.Write([]byte(fmt.Sprintf("<!DOCTYPE html><body>%s</body></html>", message)))
			if e != nil {
				err <- e
			}

			if f, ok := res.(http.Flusher); ok {
				f.Flush()
			}

			if code == "" {
				err <- fmt.Errorf("failed to get code")
			} else {
				c <- code
			}
		})
	}
}

type codeChan chan string
type errChan chan error

func launch(ctx context.Context, client *OIDCClient, url string, listener net.Listener) (string, error) {
	loginCtx, loginCancel := context.WithTimeout(ctx, 3*time.Minute) // TODO: make login timeout configurable
	defer loginCancel()

	c := make(chan string)
	e := make(chan error, 2) // could get errors from handler and/or http server

	srv := &http.Server{}
	http.HandleFunc("/", buildHandler(client, c, e))

	go func() {
		defer func() {
			close(c)
			close(e)
		}()
		if err := srv.Serve(listener); err != nil {
			e <- fmt.Errorf("failed to start local http server: %w", err)
		}
	}()

	err := browser.OpenURL(url)
	if err != nil {
		return "", fmt.Errorf("failed to openurl: %w", err)
	}

	var code string
	var handlerErr error

	select {
	case <-loginCtx.Done():
		return "", fmt.Errorf("login timed out: %w", loginCtx.Err())
	case code = <-c:
	case handlerErr = <-e:
	}

	// no need to shutdown cleanly; just quickly
	if err := srv.Close(); err != nil {
		return "", fmt.Errorf("failed to shutdown server: %w", err)
	}

	return code, handlerErr

}

func codeToToken(ctx context.Context, client *OIDCClient, verifier string, code string, redirect string) (*types.TokenResponse, error) {
	form := client.ClientForm()
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", redirect)

	log.Traceln("code2token params: %v", form)

	res, err := client.Token().Request().Form(form).Post(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to turn code into token: %w", err)
	}

	if res.Status() != http.StatusOK {
		if res.MediaType() != "" {
			var json map[string]interface{}
			err := res.ReadJson(&json)
			if err == nil {
				return nil, fmt.Errorf("failed to turn code into token, error: %s error_description: %s",
					json["error"], json["error_description"])
			}
		}
		return nil, fmt.Errorf("failed to turn code into token")
	}

	var tokenResponse types.TokenResponse
	if err := res.ReadJson(&tokenResponse); err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}
