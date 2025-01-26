package lib

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	input "github.com/natsukagami/go-input"
	"github.com/stensonb/aws-cli-oidc/lib/log"
	"github.com/stensonb/aws-cli-oidc/lib/types"
	"github.com/versent/saml2aws"
)

func GetCredentialsWithSAML(ctx context.Context, samlResponse string, durationSeconds int32, iamRoleArn string) (*types.AWSCredentials, error) {
	role, err := selectAwsRole(samlResponse, iamRoleArn)
	if err != nil {
		return nil, fmt.Errorf("failed to assume role, please check you are permitted to assume the given role for the AWS service: %w", err)
	}

	log.Writeln("Selected role: %s", role.RoleARN)
	log.Writeln("Max Session Duration: %d seconds", durationSeconds)

	return loginToStsUsingRole(ctx, role, samlResponse, durationSeconds)
}

func selectAwsRole(samlResponse, iamRoleArn string) (*saml2aws.AWSRole, error) {
	roles, err := saml2aws.ExtractAwsRoles([]byte(samlResponse))
	if err != nil {
		return nil, fmt.Errorf("failed to extract AWS roles from SAML Assertion: %w", err)
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("no roles to assume, check you are permitted to assume roles for the AWS service: %w", err)
	}

	awsRoles, err := saml2aws.ParseAWSRoles(roles)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AWS roles: %w", err)
	}

	return resolveRole(awsRoles, iamRoleArn)
}

func resolveRole(awsRoles []*saml2aws.AWSRole, iamRoleArn string) (*saml2aws.AWSRole, error) {
	var role = new(saml2aws.AWSRole)

	if len(awsRoles) == 1 {
		return awsRoles[0], nil
	} else if len(awsRoles) == 0 {
		return nil, fmt.Errorf("no roles available")
	}

	log.Writeln("")

	for {
		var err error
		role, err = promptForAWSRoleSelection(awsRoles, iamRoleArn)
		if err == nil {
			break
		}
		log.Writeln("Selecting role, try again. Error: %v", err)
	}

	return role, nil
}

func promptForAWSRoleSelection(awsRoles []*saml2aws.AWSRole, iamRoleArn string) (*saml2aws.AWSRole, error) {
	roles := map[string]*saml2aws.AWSRole{}
	var roleOptions []string

	for _, role := range awsRoles {
		if iamRoleArn == role.RoleARN {
			log.Writeln("Selected default role: %s", iamRoleArn)
			return role, nil
		}
		roles[role.RoleARN] = role
		roleOptions = append(roleOptions, role.RoleARN)
	}

	if iamRoleArn != "" {
		log.Writeln("Warning: You don't have the default role: %s", iamRoleArn)
	}

	sort.Strings(roleOptions)
	var showList string
	for i, role := range roleOptions {
		showList = showList + fmt.Sprintf("  %d. %s\n", i+1, role)
	}

	ui := &input.UI{
		Writer: os.Stderr,
		Reader: os.Stdin,
	}

	answer, err := ui.Ask(fmt.Sprintf("Please choose the role [1-%d]:\n\n%s", len(awsRoles), showList), &input.Options{
		Required: true,
		Loop:     true,
		ValidateFunc: func(s string) error {
			i, err := strconv.Atoi(s)
			if err != nil || i < 1 || i > len(awsRoles) {
				return fmt.Errorf("please choose the role [1-%d]", len(awsRoles))
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}

	i, err := strconv.Atoi(answer)
	if err != nil {
		return nil, err
	}

	return roles[roleOptions[i-1]], nil
}

func loginToStsUsingRole(ctx context.Context, role *saml2aws.AWSRole, samlResponse string, durationSeconds int32) (*types.AWSCredentials, error) {
	log.Traceln("SAMLReponse: %s", samlResponse)

	b := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	// TODO make timeout configurable
	loginCtx, loginCancel := context.WithTimeout(ctx, 10*time.Second)
	defer loginCancel()

	cfg, err := config.LoadDefaultConfig(loginCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}

	svc := sts.NewFromConfig(cfg)

	log.Traceln("PrincipalARN: %s", role.PrincipalARN)
	log.Traceln("RoleARN: %s", role.RoleARN)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(b),                 // Required
		DurationSeconds: aws.Int32(durationSeconds),
	}

	log.Writeln("Requesting AWS credentials using SAML assertion")

	resp, err := svc.AssumeRoleWithSAML(loginCtx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve STS credentials using SAML: %w", err)
	}

	log.Traceln("Got AWS credentials using SAML assertion")

	return &types.AWSCredentials{
		AWSAccessKey:    *resp.Credentials.AccessKeyId,
		AWSSecretKey:    *resp.Credentials.SecretAccessKey,
		AWSSessionToken: *resp.Credentials.SessionToken,
		PrincipalARN:    *resp.AssumedRoleUser.Arn,
		Expires:         resp.Credentials.Expiration.Local(),
	}, nil
}
