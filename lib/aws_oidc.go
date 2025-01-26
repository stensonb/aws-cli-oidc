package lib

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsCfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stensonb/aws-cli-oidc/lib/config"
	"github.com/stensonb/aws-cli-oidc/lib/log"
	"github.com/stensonb/aws-cli-oidc/lib/types"
)

func GetCredentialsWithOIDC(ctx context.Context, client *OIDCClient, idToken, iamRoleArn string, durationInSeconds int32) (*types.AWSCredentials, error) {
	return loginToStsUsingIDToken(ctx, client, idToken, iamRoleArn, durationInSeconds)
}

func loginToStsUsingIDToken(ctx context.Context, client *OIDCClient, idToken, iamRoleArn string, durationInSeconds int32) (*types.AWSCredentials, error) {
	// TODO make timeout configurable
	loginCtx, loginCancel := context.WithTimeout(ctx, 10*time.Second)
	defer loginCancel()

	roleSessionName := client.config.GetString(config.AWS_FEDERATION_ROLE_SESSION_NAME)

	cfg, err := awsCfg.LoadDefaultConfig(loginCtx, awsCfg.WithRegion("aws-global")) // TODO: make configurable

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
