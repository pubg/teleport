/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package secrets

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/google/uuid"
	"github.com/gravitational/trace"

	libcloud "github.com/gravitational/teleport/lib/cloud"
	libaws "github.com/gravitational/teleport/lib/cloud/aws"
)

// AWSSecretsManager is a Secrets store implementation using AWS Secrets
// Manager.
type AWSSecretsManager struct {
	client secretsmanageriface.SecretsManagerAPI
	cfg    Config
}

// NewAWSSecretsManager creates a new Secrets using AWS Secrets Manager.
func NewAWSSecretsManager(cfg Config) (*AWSSecretsManager, error) {
	session, err := libaws.SharedSessions().Get(cfg.Region)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &AWSSecretsManager{
		client: secretsmanager.New(session),
		cfg:    cfg,
	}, nil
}

// Delete deletes the secret for the provided path. Implements Secrets.
func (s *AWSSecretsManager) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteSecretWithContext(ctx, &secretsmanager.DeleteSecretInput{
		SecretId: s.secretID(key),

		// Remove secret immediately. If flag is not set, secret will be hidden
		// and effective for 7 days before it's actually removed.
		ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	if err != nil {
		return convertSecretsManagerError(err)
	}
	return nil
}

// GetValue returns the secret value for provided version. Implements Secrets.
func (s *AWSSecretsManager) GetValue(ctx context.Context, key string, version string) (*SecretValue, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: s.secretID(key),
	}

	if version == "" {
		version = CurrentVersion
	}
	switch version {
	case CurrentVersion:
		input.VersionStage = aws.String("AWSCURRENT")

	case PreviousVersion:
		input.VersionStage = aws.String("AWSPREVIOUS")

	default:
		input.VersionId = aws.String(version)
	}

	output, err := s.client.GetSecretValueWithContext(ctx, input)
	if err != nil {
		return nil, convertSecretsManagerError(err)
	}

	return &SecretValue{
		Key:       aws.StringValue(output.Name),
		Value:     string(output.SecretBinary),
		Version:   aws.StringValue(output.VersionId),
		CreatedAt: aws.TimeValue(output.CreatedDate),
	}, nil
}

// PutValue creates a new secret version for the secret. Implements Secrets.
func (s *AWSSecretsManager) PutValue(ctx context.Context, key, value, currentVersion string) error {
	input := &secretsmanager.PutSecretValueInput{
		SecretId:     s.secretID(key),
		SecretBinary: []byte(value),
	}

	// Create a new version ID based on current version and use it as
	// ClientRequestToken. This ensures ONLY ONE caller succeeds if multiple
	// calls to PutValue of the same current version are made to AWS. See go
	// doc on ClientRequestToken for more details.
	if currentVersion != "" {
		input.ClientRequestToken = aws.String(uuid.NewMD5(uuid.Nil, []byte(currentVersion)).String())
	} else {
		input.ClientRequestToken = aws.String(uuid.New().String())
	}

	if _, err := s.client.PutSecretValueWithContext(ctx, input); err != nil {
		return convertSecretsManagerError(err)
	}
	return nil
}

// Create creates a new secret. Implements Secrets.
func (s *AWSSecretsManager) Create(ctx context.Context, key string, value string) error {
	input := &secretsmanager.CreateSecretInput{
		Name:               s.secretID(key),
		Description:        aws.String("Created by Teleport."),
		ClientRequestToken: aws.String(uuid.New().String()),
		SecretBinary:       []byte(value),

		// Add tags to make it is easier to search Teleport resources.
		Tags: []*secretsmanager.Tag{
			{
				Key:   aws.String(libcloud.TagKeyTeleportCreated),
				Value: aws.String(libcloud.TagValueTrue),
			},
		},
	}
	if s.cfg.KMSKeyID != "" {
		input.KmsKeyId = aws.String(s.cfg.KMSKeyID)
	}

	if _, err := s.client.CreateSecretWithContext(ctx, input); err != nil {
		err = convertSecretsManagerError(err)

		// If already exists, try to update its settings.
		if trace.IsAlreadyExists(err) {
			if updateErr := s.update(ctx, key); updateErr != nil {
				return trace.Wrap(updateErr)
			}
			return trace.Wrap(err)
		}
		return trace.Wrap(err)
	}
	return nil
}

// update updates secret settings for provided key path.
func (s *AWSSecretsManager) update(ctx context.Context, key string) error {
	secret, err := s.client.DescribeSecretWithContext(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: s.secretID(key),
	})
	if err != nil {
		return convertSecretsManagerError(err)
	}

	expectedKMSKeyID := s.cfg.KMSKeyID
	if expectedKMSKeyID == "" {
		if expectedKMSKeyID, err = defaultKMSKeyID(aws.StringValue(secret.ARN)); err != nil {
			return trace.Wrap(err)
		}
	}

	if expectedKMSKeyID == aws.StringValue(secret.KmsKeyId) {
		return nil
	}

	_, err = s.client.UpdateSecretWithContext(ctx, &secretsmanager.UpdateSecretInput{
		SecretId: s.secretID(key),
		KmsKeyId: aws.String(expectedKMSKeyID),
	})
	return convertSecretsManagerError(err)
}

// secretID returns the secret id in AWS string format.
func (s *AWSSecretsManager) secretID(key string) *string {
	return aws.String(Key(s.cfg.KeyPrefix, key))
}

// defaultKMSKeyID returns the default KMS Key ID for provided secret.
func defaultKMSKeyID(secretARN string) (string, error) {
	parsed, err := arn.Parse(secretARN)
	if err != nil {
		return "", trace.Wrap(err)
	}

	// Secrets manager default KMS alias looks like this.
	// arn:aws:kms:us-east-1:1234567890:alias/aws/secretsmanager
	return fmt.Sprintf("arn:%s:%s:%s:%s:alias/aws/secretsmanager",
		parsed.Partition,
		kms.ServiceName,
		parsed.Region,
		parsed.AccountID,
	), nil
}

// convertSecretsManagerError converts AWS Secrets Manager errors to trace
// errors.
func convertSecretsManagerError(err error) error {
	if err == nil {
		return nil
	}

	requestErr, ok := err.(awserr.RequestFailure)
	if !ok {
		return trace.Wrap(err)
	}

	// Match by exception code as many errors are sharing the same status code.
	switch requestErr.Code() {
	case secretsmanager.ErrCodeResourceExistsException:
		return trace.AlreadyExists(requestErr.Error())
	case secretsmanager.ErrCodeResourceNotFoundException:
		return trace.NotFound(requestErr.Error())
	}

	// Match by status code.
	return trace.Wrap(libaws.ConvertRequestFailureError(err))
}
