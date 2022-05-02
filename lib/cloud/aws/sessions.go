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

package aws

import (
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// Sessions provides an interface for obtaining AWS sessions.
type Sessions interface {
	// Get returns AWS session for the specified region.
	Get(region string) (*session.Session, error)
}

var (
	// sharedSessionsOnce is a sync.Once for creating sharedSessions.
	sharedSessionsOnce sync.Once
	// sharedSessions is the singleton of Sessions.
	sharedSessions Sessions
)

// SharedSessions returns a shared instance of Sessions.
func SharedSessions() Sessions {
	sharedSessionsOnce.Do(func() {
		sharedSessions = NewSessions()
	})
	return sharedSessions
}

// NewSessions returns a new instance of Sessions.
func NewSessions() Sessions {
	return &sessions{
		awsSessions: make(map[string]*session.Session),
	}
}

// sessions is the implemention of Sessions.
type sessions struct {
	// awsSessions is a map of cached AWS sessions per region.
	awsSessions map[string]*session.Session
	// mtx is used for locking.
	mtx sync.RWMutex
}

// Get returns AWS session for the specified region.
func (s *sessions) Get(region string) (*session.Session, error) {
	s.mtx.RLock()
	if session, ok := s.awsSessions[region]; ok {
		s.mtx.RUnlock()
		return session, nil
	}
	s.mtx.RUnlock()
	return s.initAWSSession(region)
}

// initAWSSession creates a new AWS session for the specified region.
func (s *sessions) initAWSSession(region string) (*session.Session, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// If some other thead already got here first.
	if session, ok := s.awsSessions[region]; ok {
		return session, nil
	}

	logrus.Debugf("Initializing AWS session for region %v.", region)
	session, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config: aws.Config{
			Region: aws.String(region),
		},
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s.awsSessions[region] = session
	return session, nil
}
