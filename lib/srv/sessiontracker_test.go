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

package srv

import (
	"context"
	"testing"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

func TestSessionTracker(t *testing.T) {
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	mockService := &mockSessiontrackerService{
		trackers: make(map[string]types.SessionTracker),
	}

	sessID := "sessionID"
	trackerSpec := types.SessionTrackerSpecV1{
		Created:   clock.Now(),
		SessionID: sessID,
		State:     types.SessionState_SessionStatePending,
	}

	// Create a new session tracker
	tracker, err := NewSessionTracker(ctx, trackerSpec, mockService)
	require.NoError(t, err)
	require.NotNil(t, tracker)
	require.Equal(t, tracker.tracker, mockService.trackers[sessID])

	t.Run("UpdateExpirationLoop", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})

		// Test update expiration loop
		go func() {
			tracker.UpdateExpirationLoop(cancelCtx, clock)
			close(done)
		}()

		// Wait for goroutine to wait on clock.After
		clock.BlockUntil(1)
		expectedExpiry := tracker.tracker.Expiry().Add(sessionTrackerExpirationUpdateInterval)
		clock.Advance(sessionTrackerExpirationUpdateInterval)

		// expiration should be updated by the next time we wait on clock.After
		clock.BlockUntil(1)
		require.Equal(t, expectedExpiry, tracker.tracker.Expiry())
		require.Equal(t, tracker.tracker, mockService.trackers[sessID])

		// cancelling the goroutine's ctx should halt the update loop
		cancel()
		_, ok := <-done
		require.False(t, ok)
	})

	t.Run("UpdateState", func(t *testing.T) {
		err = tracker.UpdateState(ctx, types.SessionState_SessionStateRunning)
		require.NoError(t, err)
		require.Equal(t, types.SessionState_SessionStateRunning, tracker.GetState())
		require.Equal(t, tracker.tracker, mockService.trackers[sessID])
	})

	participantID := "userID"
	t.Run("AddParticipant", func(t *testing.T) {
		p := &types.Participant{ID: participantID}
		err = tracker.AddParticipant(ctx, p)
		require.NoError(t, err)
		require.Equal(t, []types.Participant{*p}, tracker.GetParticipants())
		require.Equal(t, tracker.tracker, mockService.trackers[sessID])
	})

	t.Run("RemoveParticipant", func(t *testing.T) {
		err = tracker.RemoveParticipant(ctx, participantID)
		require.NoError(t, err)
		require.Empty(t, tracker.GetParticipants())
		require.Equal(t, tracker.tracker, mockService.trackers[sessID])
	})

	t.Run("Close", func(t *testing.T) {
		// Closing the tracker should update the state to terminated
		err = tracker.Close(ctx)
		require.NoError(t, err)
		require.Equal(t, types.SessionState_SessionStateTerminated, tracker.GetState())
		require.Equal(t, tracker.tracker, mockService.trackers[sessID])
	})
}

type mockSessiontrackerService struct {
	trackers map[string]types.SessionTracker
}

func (m *mockSessiontrackerService) GetActiveSessionTrackers(ctx context.Context) ([]types.SessionTracker, error) {
	return nil, trace.NotImplemented("")
}

func (m *mockSessiontrackerService) GetSessionTracker(ctx context.Context, sessionID string) (types.SessionTracker, error) {
	return nil, trace.NotImplemented("")
}

func (m *mockSessiontrackerService) UpdateSessionTracker(ctx context.Context, req *proto.UpdateSessionTrackerRequest) error {
	// m.trackers[req.SessionID] will be updated as a pointer reference
	return nil
}

func (m *mockSessiontrackerService) RemoveSessionTracker(ctx context.Context, sessionID string) error {
	return trace.NotImplemented("")
}

func (m *mockSessiontrackerService) UpdatePresence(ctx context.Context, sessionID, user string) error {
	return trace.NotImplemented("")
}

func (m *mockSessiontrackerService) CreateSessionTracker(ctx context.Context, tracker types.SessionTracker) (types.SessionTracker, error) {
	m.trackers[tracker.GetSessionID()] = tracker
	return tracker, nil
}
