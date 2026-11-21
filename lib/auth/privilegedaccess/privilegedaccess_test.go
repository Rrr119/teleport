/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package privilegedaccess

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
)

// adminRole requires approval with two approvers, strict session recording
// and tight session limits.
func adminRole(t *testing.T) types.Role {
	role, err := types.NewRole("admin", types.RoleSpecV6{
		Options: types.RoleOptions{
			RequestAccess:     types.RequestStrategyAlways,
			RecordSession:     &types.RecordSession{SSH: constants.SessionRecordingModeStrict},
			ClientIdleTimeout: types.NewDuration(30 * time.Minute),
			MaxSessionTTL:     types.NewDuration(time.Hour),
		},
		Allow: types.RoleConditions{
			Request: &types.AccessRequestConditions{
				Roles:              []string{"admin"},
				Thresholds:         []types.AccessReviewThreshold{{Name: "default", Approve: 2, Deny: 1}},
				SuggestedReviewers: []string{"security@example.com", "ops@example.com"},
			},
		},
	})
	require.NoError(t, err)
	return role
}

// devRole does not require approval and records on a best-effort basis.
func devRole(t *testing.T) types.Role {
	role, err := types.NewRole("dev", types.RoleSpecV6{
		Options: types.RoleOptions{
			RequestAccess:     types.RequestStrategyOptional,
			RecordSession:     &types.RecordSession{SSH: constants.SessionRecordingModeBestEffort},
			ClientIdleTimeout: types.NewDuration(8 * time.Hour),
			MaxSessionTTL:     types.NewDuration(12 * time.Hour),
		},
	})
	require.NoError(t, err)
	return role
}

// contractorRole requires approval, strict recording and very short session
// limits.
func contractorRole(t *testing.T) types.Role {
	role, err := types.NewRole("contractor", types.RoleSpecV6{
		Options: types.RoleOptions{
			RequestAccess:     types.RequestStrategyAlways,
			RecordSession:     &types.RecordSession{SSH: constants.SessionRecordingModeStrict},
			ClientIdleTimeout: types.NewDuration(5 * time.Minute),
			MaxSessionTTL:     types.NewDuration(15 * time.Minute),
		},
		Allow: types.RoleConditions{
			Request: &types.AccessRequestConditions{
				Roles:              []string{"contractor"},
				SuggestedReviewers: []string{"ops@example.com"},
			},
		},
	})
	require.NoError(t, err)
	return role
}

func TestEvaluatePolicy(t *testing.T) {
	tests := []struct {
		name     string
		roles    []types.Role
		expected Policy
	}{
		{
			name:  "admin requires approval, strict recording, bounded sessions",
			roles: []types.Role{adminRole(t)},
			expected: Policy{
				ApprovalRequired:   true,
				MinApprovals:       2,
				SuggestedReviewers: []string{"ops@example.com", "security@example.com"},
				RecordingMode:      constants.SessionRecordingModeStrict,
				IdleTimeout:        30 * time.Minute,
				MaxSessionDuration: time.Hour,
			},
		},
		{
			name:  "dev needs no approval and records best-effort",
			roles: []types.Role{devRole(t)},
			expected: Policy{
				ApprovalRequired:   false,
				RecordingMode:      constants.SessionRecordingModeBestEffort,
				IdleTimeout:        8 * time.Hour,
				MaxSessionDuration: 12 * time.Hour,
			},
		},
		{
			name:  "contractor requires approval with default threshold",
			roles: []types.Role{contractorRole(t)},
			expected: Policy{
				ApprovalRequired:   true,
				MinApprovals:       1,
				SuggestedReviewers: []string{"ops@example.com"},
				RecordingMode:      constants.SessionRecordingModeStrict,
				IdleTimeout:        5 * time.Minute,
				MaxSessionDuration: 15 * time.Minute,
			},
		},
		{
			name:  "combined roles pick the most restrictive options",
			roles: []types.Role{adminRole(t), devRole(t), contractorRole(t)},
			expected: Policy{
				ApprovalRequired:   true,
				MinApprovals:       2,
				SuggestedReviewers: []string{"ops@example.com", "security@example.com"},
				RecordingMode:      constants.SessionRecordingModeStrict,
				IdleTimeout:        5 * time.Minute,
				MaxSessionDuration: 15 * time.Minute,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := EvaluatePolicy(services.RoleSet(tc.roles))
			require.Equal(t, tc.expected, policy)
		})
	}
}

func newTracker(t *testing.T, user string, created time.Time, expires time.Time) types.SessionTracker {
	tracker, err := types.NewSessionTracker(types.SessionTrackerSpecV1{
		SessionID:   uuid.NewString(),
		Kind:        string(types.KindSSHSession),
		Hostname:    "node",
		ClusterName: "cluster",
		Login:       "root",
		HostUser:    user,
		Created:     created,
		Participants: []types.Participant{{
			ID:         uuid.NewString(),
			User:       user,
			Mode:       string(types.SessionPeerMode),
			LastActive: created,
		}},
		Expires: expires,
	})
	require.NoError(t, err)
	require.NoError(t, tracker.SetState(types.SessionState_SessionStateRunning))
	return tracker
}

// TestDenialMonitorTerminatesSessions verifies that once an access request
// is denied, the requester's active sessions are terminated within
// DenialDisconnectTimeout while other users' sessions stay up.
func TestDenialMonitorTerminatesSessions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bk, err := memory.New(memory.Config{})
	require.NoError(t, err)
	defer bk.Close()

	sessions, err := local.NewSessionTrackerService(bk)
	require.NoError(t, err)
	access := local.NewDynamicAccessService(bk)

	monitor, err := NewDenialMonitor(DenialMonitorConfig{
		Events:   local.NewEventsService(bk),
		Sessions: sessions,
	})
	require.NoError(t, err)
	go func() {
		_ = monitor.Run(ctx)
	}()

	now := time.Now().UTC()
	aliceSession1 := newTracker(t, "alice", now, now.Add(time.Hour))
	aliceSession2 := newTracker(t, "alice", now, now.Add(time.Hour))
	bobSession := newTracker(t, "bob", now, now.Add(time.Hour))
	for _, tracker := range []types.SessionTracker{aliceSession1, aliceSession2, bobSession} {
		_, err := sessions.CreateSessionTracker(ctx, tracker)
		require.NoError(t, err)
	}

	request, err := types.NewAccessRequest(uuid.NewString(), "alice", "admin")
	require.NoError(t, err)
	_, err = access.CreateAccessRequestV2(ctx, request)
	require.NoError(t, err)

	start := time.Now()
	_, err = access.SetAccessRequestState(ctx, types.AccessRequestUpdate{
		RequestID: request.GetName(),
		State:     types.RequestState_DENIED,
	})
	require.NoError(t, err)

	// Alice's sessions must be terminated within DenialDisconnectTimeout.
	require.Eventually(t, func() bool {
		for _, id := range []string{aliceSession1.GetSessionID(), aliceSession2.GetSessionID()} {
			tracker, err := sessions.GetSessionTracker(ctx, id)
			if err != nil || tracker.GetState() != types.SessionState_SessionStateTerminated {
				return false
			}
		}
		return true
	}, DenialDisconnectTimeout, 10*time.Millisecond)
	require.Less(t, time.Since(start), DenialDisconnectTimeout,
		"sessions must be disconnected within 5 seconds of denial")

	// Bob's session must remain active.
	tracker, err := sessions.GetSessionTracker(ctx, bobSession.GetSessionID())
	require.NoError(t, err)
	require.NotEqual(t, types.SessionState_SessionStateTerminated, tracker.GetState())
}

// TestSessionReaper verifies timeout reclamation for sessions that expire,
// exceed their maximum duration, or idle out, using per-role policies.
func TestSessionReaper(t *testing.T) {
	ctx := context.Background()

	bk, err := memory.New(memory.Config{})
	require.NoError(t, err)
	defer bk.Close()

	sessions, err := local.NewSessionTrackerService(bk)
	require.NoError(t, err)

	clock := clockwork.NewFakeClock()
	start := clock.Now().UTC()

	policies := map[string]Policy{
		// admin: 1h max session duration, 30m idle timeout.
		"admin": {MaxSessionDuration: time.Hour, IdleTimeout: 30 * time.Minute},
		// dev: 12h max session duration, 8h idle timeout.
		"dev": {MaxSessionDuration: 12 * time.Hour, IdleTimeout: 8 * time.Hour},
		// contractor: 15m max session duration, 5m idle timeout.
		"contractor": {MaxSessionDuration: 15 * time.Minute, IdleTimeout: 5 * time.Minute},
	}

	reaper, err := NewSessionReaper(SessionReaperConfig{
		Sessions: sessions,
		ResolvePolicy: func(_ context.Context, user string) (Policy, error) {
			return policies[user], nil
		},
		Clock: clock,
	})
	require.NoError(t, err)

	adminSession := newTracker(t, "admin", start, start.Add(2*time.Hour))
	devSession := newTracker(t, "dev", start, start.Add(24*time.Hour))
	contractorSession := newTracker(t, "contractor", start, start.Add(2*time.Hour))
	expiredSession := newTracker(t, "dev", start, start.Add(time.Minute))
	for _, tracker := range []types.SessionTracker{adminSession, devSession, contractorSession, expiredSession} {
		_, err := sessions.CreateSessionTracker(ctx, tracker)
		require.NoError(t, err)
	}

	// Advance 20 minutes: the contractor session exceeded both its 15m max
	// duration and its 5m idle timeout, and the expired session is past its
	// expiry. Admin and dev sessions are within their limits.
	clock.Advance(20 * time.Minute)
	require.NoError(t, reaper.Reap(ctx))

	assertState := func(tracker types.SessionTracker, expected types.SessionState) {
		t.Helper()
		got, err := sessions.GetSessionTracker(ctx, tracker.GetSessionID())
		require.NoError(t, err)
		require.Equal(t, expected, got.GetState(), "session owned by %q", tracker.GetHostUser())
	}

	assertState(contractorSession, types.SessionState_SessionStateTerminated)
	assertState(expiredSession, types.SessionState_SessionStateTerminated)
	assertState(adminSession, types.SessionState_SessionStateRunning)
	assertState(devSession, types.SessionState_SessionStateRunning)

	// Advance past the admin idle timeout (30m) but not the dev one (8h).
	clock.Advance(15 * time.Minute)
	require.NoError(t, reaper.Reap(ctx))

	assertState(adminSession, types.SessionState_SessionStateTerminated)
	assertState(devSession, types.SessionState_SessionStateRunning)

	// Advance past the admin max duration already handled; jump to the dev
	// limits (12h max duration, 8h idle).
	clock.Advance(9 * time.Hour)
	require.NoError(t, reaper.Reap(ctx))

	assertState(devSession, types.SessionState_SessionStateTerminated)
}
