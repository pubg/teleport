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
	"context"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/interval"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

// Config is the config for users service.
type Config struct {
	// Clients is an interface for retrieving cloud clients.
	Clients common.CloudClients
	// Clock is used to control time.
	Clock clockwork.Clock
	// Interval is the interval between user updates. Interval is also used as
	// the minimum password expiration duration.
	Interval time.Duration
	// Log is the logrus field logger.
	Log logrus.FieldLogger
}

// CheckAndSetDefaults validates the config and set defaults.
func (c *Config) CheckAndSetDefaults() (err error) {
	if c.Clients == nil {
		c.Clients = common.NewCloudClients()
	}
	if c.Clock == nil {
		c.Clock = clockwork.NewRealClock()
	}
	if c.Interval == 0 {
		// AWS Secrets Manager can have at most 100 versions per day (about one
		// new version per 15 minutes).
		//
		// https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html
		//
		// Note that currently all database types are sharing the same interval
		// for password rotations.
		c.Interval = 15 * time.Minute
	}
	if c.Log == nil {
		c.Log = logrus.WithField(trace.Component, "cloudusers")
	}
	return nil
}

// Users manages database users for cloud databases.
type Users struct {
	cfg            Config
	fetchersByType map[string]Fetcher
	usersMap       *usersMap
	lookupMap      *lookupMap
}

// GetDatabasesFunc defines a function that fetches all currently active
// databases.
type GetDatabasesFunc func() types.Databases

// Fetcher fetches database users for a particular database type.
type Fetcher interface {
	// GetType returns the database type of the fetcher.
	GetType() string

	// FetchDatabaseUsers fetches users for provided database.
	FetchDatabaseUsers(ctx context.Context, database types.Database) ([]User, error)
}

// NewUsers returns a new instance of users service.
func NewUsers(cfg Config) (*Users, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	fetchersByType := make(map[string]Fetcher)
	for _, newFetcherFunc := range []func(Config) (Fetcher, error){
		newElastiCacheFetcher,
	} {
		fetcher, err := newFetcherFunc(cfg)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		fetchersByType[fetcher.GetType()] = fetcher
	}

	return &Users{
		cfg:            cfg,
		usersMap:       newUsersMap(),
		lookupMap:      newLookupMap(),
		fetchersByType: fetchersByType,
	}, nil
}

// GetPassword returns the password for database login.
func (u *Users) GetPassword(ctx context.Context, database types.Database, username string) (string, error) {
	user, found := u.lookupMap.getDatabaseUser(database, username)
	if !found {
		return "", trace.NotFound("database user %s is not managed", username)
	}

	return user.GetPassword(ctx)
}

// Start starts users service to manage cloud database users.
func (u *Users) Start(ctx context.Context, getDatabases GetDatabasesFunc) {
	u.cfg.Log.Debug("Starting cloud users service.")
	defer u.cfg.Log.Debug("Cloud users service done.")

	ticker := interval.New(interval.Config{
		Jitter:   utils.NewSeventhOutboundJitter(),
		Duration: u.cfg.Interval,
	})
	for {
		select {
		case <-ticker.Next():
			u.setupAllDatabases(ctx, getDatabases())

		case <-ctx.Done():
			return
		}
	}
}

// SetupDatabase starts to manage any discovered users for provided database.
//
// SetupDatabase allows managed database users to become available as soon as
// new database is registered instead of waiting for the periodic setup
// goroutine. Note that there is no corresponding "TeardownDatabase" as cleanup
// will eventually happen in the periodic setup.
func (u *Users) SetupDatabase(ctx context.Context, database types.Database) error {
	fetcher, found := u.fetchersByType[database.GetType()]
	if !found {
		return nil
	}

	// Fetch managed users from cloud.
	fetchedUsers, err := u.fetchDatabaseUsers(ctx, fetcher, database)
	if err != nil {
		return trace.Wrap(err)
	}

	// Setup users. The error returned here can be a partial error, so lookup
	// map and database resource is updated regardless of the error.
	users, err := u.setupUsers(ctx, fetchedUsers)
	u.lookupMap.setDatabaseUsers(database, users, true)
	return trace.Wrap(err)
}

// setupUsers performs setup and one password rotation for each user.
func (u *Users) setupUsers(ctx context.Context, fetchedUsers []User) ([]User, error) {
	var errs []error
	var users []User

	for _, fetchedUser := range fetchedUsers {
		// Check if the user is already managed and tracked.
		existingUser, found := u.usersMap.findUser(fetchedUser.GetID())
		if found {
			// TODO(greedy52) may want to compare secret store setting in case
			// they are different.
			users = append(users, existingUser)
			continue
		}

		// Setup the user if new.
		if err := fetchedUser.Setup(ctx); err != nil {
			errs = append(errs, err)
			continue
		}

		u.usersMap.addUser(fetchedUser)
		users = append(users, fetchedUser)
	}

	// Rotate the password.
	for _, user := range users {
		errs = append(errs, user.RotatePassword(ctx))
	}
	return users, trace.NewAggregate(errs...)
}

// setupAllDatabases performs setup for all active databases.
func (u *Users) setupAllDatabases(ctx context.Context, allDatabases types.Databases) {
	// Discover users and save lookup in a new map.
	lookupMap := newLookupMap()
	for _, database := range allDatabases {
		fetcher, found := u.fetchersByType[database.GetType()]
		if !found {
			continue
		}

		fetchedUsers, err := u.fetchDatabaseUsers(ctx, fetcher, database)
		if err != nil {
			u.cfg.Log.WithError(err).Errorf("Failed to fetch users for database %v.", database)
			continue
		}

		users, err := u.setupUsers(ctx, fetchedUsers)
		if err != nil {
			u.cfg.Log.WithError(err).Errorf("Failed to setup users for database %v.", database)
		}

		// Update new lookup map, but do not update the database resource yet.
		lookupMap.setDatabaseUsers(database, users, false)
	}

	// Swap lookup maps and update all database resources.
	u.lookupMap.swap(lookupMap, true)

	// Teardown users that are no longer used.
	for _, user := range u.usersMap.removeUnused(u.lookupMap.usersByID()) {
		if err := user.Teardown(ctx); err != nil {
			u.cfg.Log.WithError(err).Errorf("Failed to tear down user %v.", user)
		}
	}
}

// fetchDatabaseUsers discovers cloud database users for provided database.
func (u *Users) fetchDatabaseUsers(ctx context.Context, fetcher Fetcher, database types.Database) ([]User, error) {
	if fetcher == nil { // Should never happen.
		return nil, trace.BadParameter("missing fetcher")
	}

	fetchedUsers, err := fetcher.FetchDatabaseUsers(ctx, database)
	if err != nil {
		if trace.IsAccessDenied(err) { // Permission errors are expected.
			u.cfg.Log.WithError(err).Debugf("No permissions to fetch users for %q.", database)
			return nil, nil
		}
		return nil, trace.Wrap(err)
	}
	return fetchedUsers, nil
}
