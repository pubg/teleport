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

package users

import (
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/secrets"
	"github.com/gravitational/teleport/lib/utils"
)

// usersMap owns a collection of database users.
type usersMap struct {
	byID map[string]User
	mu   sync.RWMutex
}

// newUsersMap creates a new users map.
func newUsersMap() *usersMap {
	return &usersMap{
		byID: make(map[string]User),
	}
}

// addUser adds a user to collection.
func (m *usersMap) addUser(user User) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.byID[user.GetID()] = user
}

// findUser finds a user by user ID.
func (m *usersMap) findUser(userID string) (User, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, found := m.byID[userID]
	return user, found
}

// removeUnused remove unused users by comparing with provided map of active
// users.
func (m *usersMap) removeUnused(activeUsersByID map[string]User) (removed []User) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for userID, user := range m.byID {
		if _, found := activeUsersByID[userID]; !found {
			removed = append(removed, user)
			delete(m.byID, userID)
		}
	}
	return
}

// len returns the size of the map.
func (m *usersMap) len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.byID)
}

// lookupMap is a mapping of database objects to their managed users.
type lookupMap struct {
	byDatabase map[types.Database][]User
	mu         sync.RWMutex
}

// newLookupMap creates a new lookup map.
func newLookupMap() *lookupMap {
	return &lookupMap{
		byDatabase: make(map[types.Database][]User),
	}
}

// getDatabaseUser finds a database user by database username.
func (m *lookupMap) getDatabaseUser(database types.Database, username string) (User, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, user := range m.byDatabase[database] {
		if user.GetInDatabaseName() == username {
			return user, true
		}
	}
	return nil, false
}

// setDatabaseUsers sets the database users for future lookups.
func (m *lookupMap) setDatabaseUsers(database types.Database, users []User, updateDatabaseResource bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(users) > 0 {
		m.byDatabase[database] = users
	} else {
		delete(m.byDatabase, database)
	}

	if updateDatabaseResource {
		database.SetManagedUsers(getUsernames(users))
	}
}

// swap swaps collection with another lookup map.
func (m *lookupMap) swap(other *lookupMap, updateDatabaseResource bool) {
	m.mu.Lock()
	other.mu.Lock()
	defer m.mu.Unlock()
	defer other.mu.Unlock()

	m.byDatabase, other.byDatabase = other.byDatabase, m.byDatabase

	if updateDatabaseResource {
		for database, users := range m.byDatabase {
			database.SetManagedUsers(getUsernames(users))
		}
	}
}

// usersByID returns a map of users by their IDs.
func (m *lookupMap) usersByID() map[string]User {
	m.mu.RLock()
	defer m.mu.RUnlock()

	usersByID := make(map[string]User)
	for _, users := range m.byDatabase {
		for _, user := range users {
			usersByID[user.GetID()] = user
		}
	}
	return usersByID
}

// getUsernames returns a list of in-database user names.
func getUsernames(users []User) (usernames []string) {
	for _, user := range users {
		usernames = append(usernames, user.GetInDatabaseName())
	}
	return
}

// secretKeyFromAWSARN creates a secret key with provided ARN.
func secretKeyFromAWSARN(inputARN string) (string, error) {
	// Example ElastiCache User ARN looks like this:
	// arn:aws:elasticache:<region>:<account-id>:user:<user-id>
	//
	// Make an unique secret key like this:
	// elasticache/<region>/<account-id>/user/<user-id>
	parsed, err := arn.Parse(inputARN)
	if err != nil {
		return "", trace.BadParameter(err.Error())
	}
	return secrets.Key(
		parsed.Service,
		parsed.Region,
		parsed.AccountID,
		strings.ReplaceAll(parsed.Resource, ":", "/"),
	), nil
}

// genRandomPassword generate a random password with provided length.
func genRandomPassword(length int) (string, error) {
	if length <= 0 {
		return "", trace.BadParameter("invalid random value length")
	}

	// Hex generated from CryptoRandomHex is twice of the input.
	hex, err := utils.CryptoRandomHex((length + 1) / 2)
	if err != nil {
		return "", trace.Wrap(err)
	} else if len(hex) < length {
		return "", trace.CompareFailed("generated hex is too short")
	}
	return hex[:length], nil
}

// newDatabaseSecretsStore creates a secret store for provided database.
func newDatabaseSecretsStore(database types.Database) (secrets.Secrets, error) {
	secretStoreConfig := database.GetSecretStore()
	return secrets.New(secrets.Config{
		Region:    secretStoreConfig.Region,
		KeyPrefix: secretStoreConfig.KeyPrefix,
		KMSKeyID:  secretStoreConfig.KMSKeyID,
	})
}
