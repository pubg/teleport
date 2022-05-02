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
	"strconv"
	"sync"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

// Memory is a Secrets implementation using system memory.
//
// Used mainly for testing.
type Memory struct {
	secretsByKey map[string][]*SecretValue
	mu           sync.RWMutex
	clock        clockwork.Clock
}

// NewMemory creates a new Secrets using memory.
func NewMemory(clock clockwork.Clock) *Memory {
	if clock == nil {
		clock = clockwork.NewRealClock()
	}
	return &Memory{
		secretsByKey: make(map[string][]*SecretValue),
		clock:        clock,
	}
}

// Create creates a new secret. Implements Secrets.
func (s *Memory) Create(ctx context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, found := s.secretsByKey[key]; found {
		return trace.AlreadyExists("%v already exists", key)
	}

	return s.putValue(key, value)
}

// Delete deletes the secret for the provided path. Implements Secrets.
func (s *Memory) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, found := s.secretsByKey[key]; !found {
		return trace.NotFound("%v not found", key)
	}

	delete(s.secretsByKey, key)
	return nil
}

// GetValue returns the secret value for provided version. Implements Secrets.
func (s *Memory) GetValue(ctx context.Context, key string, version string) (*SecretValue, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions := s.secretsByKey[key]
	if len(versions) == 0 {
		return nil, trace.NotFound("%v not found", key)
	}

	var index int
	switch version {
	case "", CurrentVersion:
		index = len(versions) - 1

	case PreviousVersion:
		index = len(versions) - 2

	default:
		var err error
		if index, err = strconv.Atoi(version); err != nil {
			return nil, trace.BadParameter("invalid version %v", version)
		}
	}

	if index < 0 || index >= len(versions) {
		return nil, trace.NotFound("version %v not found for key %v", version, key)
	}
	return versions[index], nil
}

// PutValue creates a new secret version for the secret. Implements Secrets.
func (s *Memory) PutValue(ctx context.Context, key, value, currentVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	versions := s.secretsByKey[key]
	if len(versions) == 0 {
		return trace.NotFound("%v not found", key)
	}

	// Test current version before putting new value.
	if currentVersion != "" {
		currentIndex, err := strconv.Atoi(currentVersion)
		if err != nil {
			return trace.BadParameter("invalid version %v", currentVersion)
		}
		if currentIndex != (len(versions) - 1) {
			return trace.BadParameter("version %v is not the latest version", currentVersion)
		}
	}

	return s.putValue(key, value)
}

// putValue creates a new version of the secret.
func (s *Memory) putValue(key, value string) error {
	version := strconv.Itoa(len(s.secretsByKey[key]))
	s.secretsByKey[key] = append(s.secretsByKey[key], &SecretValue{
		Key:       key,
		Value:     value,
		Version:   version,
		CreatedAt: s.clock.Now(),
	})
	return nil
}
