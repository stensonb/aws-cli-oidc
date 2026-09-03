package lib

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsCfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stensonb/aws-cli-oidc/lib/config"
	"github.com/stensonb/aws-cli-oidc/lib/log"
	"github.com/stensonb/aws-cli-oidc/lib/types"
)

// newSTSConfig builds an AWS config for STS calls, honoring an optionally
// configured sts_endpoint/aws_region so this tool can target an
// AWS-API-compatible service (e.g. VAST Data) instead of the real AWS STS
// endpoint.
func newSTSConfig(ctx context.Context, client *OIDCClient) (aws.Config, error) {
	var opts []func(*awsCfg.LoadOptions) error

	region := client.config.GetString(config.AWS_REGION)
	endpoint := client.config.GetString(config.STS_ENDPOINT)

	if region != "" {
		opts = append(opts, awsCfg.WithRegion(region))
	} else if endpoint != "" {
		// The SDK still needs a region to sign requests even when the
		// endpoint is overridden, but VAST Data doesn't have real AWS regions.
		opts = append(opts, awsCfg.WithRegion("us-east-1"))
	} else {
		opts = append(opts, awsCfg.WithRegion("aws-global")) // TODO: make configurable
	}

	if endpoint != "" {
		opts = append(opts, awsCfg.WithBaseEndpoint(endpoint))

		// Only ever relax TLS verification for a custom (non-AWS) endpoint,
		// never for real AWS STS.
		insecure, err := strconv.ParseBool(client.config.GetString(config.INSECURE_SKIP_VERIFY))
		if err != nil {
			insecure = false
		}
		opts = append(opts, awsCfg.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			},
		}))
	}

	if log.IsTraceEnabled {
		opts = append(opts, awsCfg.WithClientLogMode(aws.LogRequestWithBody|aws.LogResponseWithBody))
		opts = append(opts, awsCfg.WithLogger(logging.LoggerFunc(func(_ logging.Classification, format string, v ...interface{}) {
			log.Traceln("%s", strings.TrimRight(fmt.Sprintf(format, v...), "\n"))
		})))
	}

	return awsCfg.LoadDefaultConfig(ctx, opts...)
}

// traceSTSError logs the full detail of an STS error (API code, message, and
// HTTP status) in trace mode, since the default Error() string can collapse
// useful detail into one hard-to-read line.
func traceSTSError(err error) {
	if !log.IsTraceEnabled || err == nil {
		return
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		log.Traceln("STS error: code=%s message=%s fault=%s", apiErr.ErrorCode(), apiErr.ErrorMessage(), apiErr.ErrorFault())
	}
	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		log.Traceln("STS error HTTP status: %d", respErr.HTTPStatusCode())
	}
}

func GetCredentialsWithOIDC(ctx context.Context, client *OIDCClient, idToken, iamRoleArn string, durationInSeconds int32) (*types.AWSCredentials, error) {
	return loginToStsUsingIDToken(ctx, client, idToken, iamRoleArn, durationInSeconds)
}

func loginToStsUsingIDToken(ctx context.Context, client *OIDCClient, idToken, iamRoleArn string, durationInSeconds int32) (*types.AWSCredentials, error) {
	// TODO make timeout configurable
	loginCtx, loginCancel := context.WithTimeout(ctx, 10*time.Second)
	defer loginCancel()

	roleSessionName := client.config.GetString(config.AWS_FEDERATION_ROLE_SESSION_NAME)

	cfg, err := newSTSConfig(loginCtx, client)

	if err != nil {
		log.Writeln("Failed to load credentials")
	}

	svc := sts.NewFromConfig(cfg)

	params := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &iamRoleArn,
		RoleSessionName:  &roleSessionName,
		WebIdentityToken: &idToken,
		DurationSeconds:  aws.Int32(durationInSeconds),
	}

	log.Writeln("Requesting AWS credentials using ID Token")

	resp, err := svc.AssumeRoleWithWebIdentity(loginCtx, params)
	if err != nil {
		traceSTSError(err)
		return nil, fmt.Errorf("error retrieving STS credentials using ID Token: %w", err)
	}

	return &types.AWSCredentials{
		AWSAccessKey:    *resp.Credentials.AccessKeyId,
		AWSSecretKey:    *resp.Credentials.SecretAccessKey,
		AWSSessionToken: *resp.Credentials.SessionToken,
		PrincipalARN:    *resp.AssumedRoleUser.Arn,
		Expires:         resp.Credentials.Expiration.Local(),
	}, nil
}
