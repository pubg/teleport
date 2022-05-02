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
	"path"
	"time"

	"github.com/gravitational/trace"
)

const (
	// PreviousVersion is a special version string that indicates the current
	// version of the secret.
	CurrentVersion = "CURRENT"

	// PreviousVersion is a special version string that indicates the previous
	// version of the secret.
	PreviousVersion = "PREVIOUS"
)

// Secrets defines an interface for managing secrets. A secret consists of a
// key path and a list of versions that hold copies of current or past secret
// values.
type Secrets interface {
	// Create creates the secret for the provided path.
	Create(ctx context.Context, key, value string) error

	// Delete deletes the secret for the provided path. All versions of the
	// secret are deleted at the same time.
	Delete(ctx context.Context, key string) error

	// PutValue creates a new secret version for the secret. CurrentVersion can
	// be provided to perform a test-and-set operation, and an error will be
	// returned if the test fails.
	PutValue(ctx context.Context, key, value, currentVersion string) error

	// GetValue returns the secret value for provided version. Besides version
	// string returned from PutValue, two specials versions "CURRENT" and
	// "PREVIOUS" can also be used to retrieve the current and previous
	// versions respectively. If the version is empty, "CURRENT" is used.
	GetValue(ctx context.Context, key, version string) (*SecretValue, error)
}

// SecretValue is the secret value.
type SecretValue struct {
	// Key is the key path of the secret.
	Key string
	// Value is the value of the secret.
	Value string
	// Version is the version of the secret value.
	Version string
	// CreatedAt is the creation time of this version.
	CreatedAt time.Time
}

// Config is the config for creating Secrets.
type Config struct {
	// Type is the Secrets store type. Currently only AWS Secrets Manager is supported.
	// Type string `yaml:"type,omitempty"`

	// KeyPrefix is the key path prefix for all keys used by Secrets.
	KeyPrefix string `yaml:"key_prefix,omitempty"`

	// Region is the AWS region for AWS Secrets Manager and KMS keys.
	Region string `yaml:"region,omitempty"`

	// KMSKeyID is the AWS KMS key that Secrets Manager uses to encrypt the
	// secret value.
	KMSKeyID string `yaml:"kms_key_id,omitempty"`
}

// CheckAndSetDefaults validates the config and sets defaults.
func (c *Config) CheckAndSetDefaults() (err error) {
	if c.KeyPrefix == "" {
		c.KeyPrefix = DefaultKeyPrefix
	}
	return nil
}

// DefaultKeyPrefix is the default key prefix.
const DefaultKeyPrefix = "teleport/"

// New creates new Secrets.
func New(config Config) (Secrets, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	// Currently only AWS Secrets Manager is supported.
	return NewAWSSecretsManager(config)
}

// Key creates a key path with provided parts.
func Key(parts ...string) string {
	return path.Join(parts...)
}
