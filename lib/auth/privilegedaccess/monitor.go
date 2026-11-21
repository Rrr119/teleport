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
	"log/slog"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
)

// DenialDisconnectTimeout is the maximum amount of time allowed between an
// access request being denied and the requester's active sessions being
// terminated.
const DenialDisconnectTimeout = 5 * time.Second

// watchRetryInterval is how long the monitor waits before re-establishing a
// failed access request watcher.
const watchRetryInterval = 5 * time.Second

// DenialMonitorConfig configures a DenialMonitor.
type DenialMonitorConfig struct {
	// Events is used to watch access request state transitions.
	Events types.Events
	// Sessions is used to find and terminate active sessions.
	Sessions services.SessionTrackerService
	// Logger is the monitor's logger.
	Logger *slog.Logger
	// DisconnectTimeout bounds how long session termination may take after
	// a denial. Defaults to DenialDisconnectTimeout.
	DisconnectTimeout time.Duration
}

// DenialMonitor watches access requests and terminates all active sessions
// of a user whose access request transitions to the denied state.
type DenialMonitor struct {
	cfg DenialMonitorConfig
}

// NewDenialMonitor creates a new DenialMonitor.
func NewDenialMonitor(cfg DenialMonitorConfig) (*DenialMonitor, error) {
	if cfg.Events == nil {
		return nil, trace.BadParameter("missing required parameter Events")
	}
	if cfg.Sessions == nil {
		return nil, trace.BadParameter("missing required parameter Sessions")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DisconnectTimeout <= 0 {
		cfg.DisconnectTimeout = DenialDisconnectTimeout
	}
	return &DenialMonitor{cfg: cfg}, nil
}

// Run starts the monitor and blocks until ctx is canceled. The watcher is
// re-established if the event stream fails.
func (m *DenialMonitor) Run(ctx context.Context) error {
	for {
		if err := m.watch(ctx); err != nil && ctx.Err() == nil {
			m.cfg.Logger.WarnContext(ctx, "Access request watcher failed, re-establishing.",
				"error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(watchRetryInterval):
		}
	}
}

func (m *DenialMonitor) watch(ctx context.Context) error {
	watcher, err := m.cfg.Events.NewWatcher(ctx, types.Watch{
		Kinds: []types.WatchKind{{Kind: types.KindAccessRequest}},
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer watcher.Close()

	for {
		select {
		case <-ctx.Done():
			return trace.Wrap(ctx.Err())
		case <-watcher.Done():
			return trace.Wrap(watcher.Error())
		case event := <-watcher.Events():
			if event.Type != types.OpPut {
				continue
			}
			req, ok := event.Resource.(types.AccessRequest)
			if !ok {
				m.cfg.Logger.WarnContext(ctx, "Unexpected resource type in access request event.",
					"resource_type", event.Resource.GetKind())
				continue
			}
			if !req.GetState().IsDenied() {
				continue
			}
			m.terminateUserSessions(ctx, req.GetUser(), req.GetName())
		}
	}
}

// terminateUserSessions terminates all active sessions owned by user. The
// operation is bounded by the configured disconnect timeout so that denied
// users are disconnected within DenialDisconnectTimeout.
func (m *DenialMonitor) terminateUserSessions(ctx context.Context, user, requestID string) {
	ctx, cancel := context.WithTimeout(ctx, m.cfg.DisconnectTimeout)
	defer cancel()

	trackers, err := m.cfg.Sessions.GetActiveSessionTrackers(ctx)
	if err != nil {
		m.cfg.Logger.ErrorContext(ctx, "Failed to list active sessions after access request denial.",
			"user", user, "request", requestID, "error", err)
		return
	}

	for _, tracker := range trackers {
		if tracker.GetHostUser() != user {
			continue
		}
		if tracker.GetState() == types.SessionState_SessionStateTerminated {
			continue
		}
		err := m.cfg.Sessions.UpdateSessionTracker(ctx, &proto.UpdateSessionTrackerRequest{
			SessionID: tracker.GetSessionID(),
			Update: &proto.UpdateSessionTrackerRequest_UpdateState{
				UpdateState: &proto.SessionTrackerUpdateState{
					State: types.SessionState_SessionStateTerminated,
				},
			},
		})
		if err != nil {
			m.cfg.Logger.ErrorContext(ctx, "Failed to terminate session after access request denial.",
				"user", user, "session", tracker.GetSessionID(),
				"request", requestID, "error", err)
			continue
		}
		m.cfg.Logger.InfoContext(ctx, "Terminated session after access request denial.",
			"user", user, "session", tracker.GetSessionID(), "request", requestID)
	}
}
