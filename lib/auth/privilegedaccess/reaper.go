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
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
)

// defaultReapInterval is how often the reaper scans for expired sessions.
const defaultReapInterval = time.Minute

// PolicyResolver resolves the effective privileged-access policy for a
// teleport user.
type PolicyResolver func(ctx context.Context, user string) (Policy, error)

// SessionReaperConfig configures a SessionReaper.
type SessionReaperConfig struct {
	// Sessions is used to find and terminate active sessions.
	Sessions services.SessionTrackerService
	// ResolvePolicy optionally resolves per-user policies. When nil, the
	// fallback limits below apply to all sessions.
	ResolvePolicy PolicyResolver
	// MaxSessionDuration is the fallback maximum session lifetime used when
	// no policy resolver is configured or the resolved policy does not set
	// a limit. Zero disables duration-based reclamation.
	MaxSessionDuration time.Duration
	// IdleTimeout is the fallback idle timeout used when no policy resolver
	// is configured or the resolved policy does not set one. Zero disables
	// idle-based reclamation.
	IdleTimeout time.Duration
	// Interval is how often active sessions are scanned. Defaults to
	// defaultReapInterval.
	Interval time.Duration
	// Clock is used for time-based decisions. Defaults to a real clock.
	Clock clockwork.Clock
	// Logger is the reaper's logger.
	Logger *slog.Logger
}

// SessionReaper reclaims sessions that have expired, exceeded their maximum
// duration, or been idle for longer than the applicable policy allows.
type SessionReaper struct {
	cfg SessionReaperConfig
}

// NewSessionReaper creates a new SessionReaper.
func NewSessionReaper(cfg SessionReaperConfig) (*SessionReaper, error) {
	if cfg.Sessions == nil {
		return nil, trace.BadParameter("missing required parameter Sessions")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultReapInterval
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &SessionReaper{cfg: cfg}, nil
}

// Run starts the reaper and blocks until ctx is canceled.
func (r *SessionReaper) Run(ctx context.Context) error {
	ticker := r.cfg.Clock.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.Chan():
			if err := r.Reap(ctx); err != nil {
				r.cfg.Logger.WarnContext(ctx, "Session reclamation pass failed.", "error", err)
			}
		}
	}
}

// Reap performs a single reclamation pass over all active sessions.
func (r *SessionReaper) Reap(ctx context.Context) error {
	trackers, err := r.cfg.Sessions.GetActiveSessionTrackers(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	now := r.cfg.Clock.Now()
	for _, tracker := range trackers {
		if tracker.GetState() == types.SessionState_SessionStateTerminated {
			continue
		}

		policy := Policy{
			IdleTimeout:        r.cfg.IdleTimeout,
			MaxSessionDuration: r.cfg.MaxSessionDuration,
		}
		if r.cfg.ResolvePolicy != nil {
			resolved, err := r.cfg.ResolvePolicy(ctx, tracker.GetHostUser())
			if err != nil {
				// Fail closed on the limits we do have: keep the fallback
				// policy rather than skipping reclamation entirely.
				r.cfg.Logger.WarnContext(ctx, "Failed to resolve session policy, using fallback limits.",
					"user", tracker.GetHostUser(), "error", err)
			} else {
				policy = resolved
			}
		}

		expires := tracker.GetExpires()
		var reason string
		switch {
		case !expires.IsZero() && now.After(expires):
			reason = "session expired"
		case policy.MaxSessionDuration > 0 &&
			now.After(tracker.GetCreated().Add(policy.MaxSessionDuration)):
			reason = "session exceeded maximum duration"
		case policy.IdleTimeout > 0 && now.After(lastActive(tracker).Add(policy.IdleTimeout)):
			reason = "session idle timeout exceeded"
		default:
			continue
		}

		if err := r.terminate(ctx, tracker, reason); err != nil {
			r.cfg.Logger.ErrorContext(ctx, "Failed to reclaim session.",
				"session", tracker.GetSessionID(), "reason", reason, "error", err)
		}
	}
	return nil
}

func (r *SessionReaper) terminate(ctx context.Context, tracker types.SessionTracker, reason string) error {
	err := r.cfg.Sessions.UpdateSessionTracker(ctx, &proto.UpdateSessionTrackerRequest{
		SessionID: tracker.GetSessionID(),
		Update: &proto.UpdateSessionTrackerRequest_UpdateState{
			UpdateState: &proto.SessionTrackerUpdateState{
				State: types.SessionState_SessionStateTerminated,
			},
		},
	})
	if err != nil {
		return trace.Wrap(err)
	}
	r.cfg.Logger.InfoContext(ctx, "Reclaimed session.",
		"session", tracker.GetSessionID(), "user", tracker.GetHostUser(), "reason", reason)
	return nil
}

// lastActive returns the most recent activity timestamp across all session
// participants, falling back to the session creation time.
func lastActive(tracker types.SessionTracker) time.Time {
	last := tracker.GetCreated()
	for _, participant := range tracker.GetParticipants() {
		if participant.LastActive.After(last) {
			last = participant.LastActive
		}
	}
	return last
}
