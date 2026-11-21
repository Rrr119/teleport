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

// Package privilegedaccess implements privileged access controls derived
// from a user's role set: role-based approval flows, session recording
// requirements and session timeout reclamation.
package privilegedaccess

import (
	"sort"
	"time"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
)

// Policy describes the privileged-access controls that apply to a set of
// roles. It is the most restrictive combination of the individual role
// options.
type Policy struct {
	// ApprovalRequired indicates that access must go through an access
	// request approval flow.
	ApprovalRequired bool
	// MinApprovals is the minimum number of approvals required before
	// access is granted. Only meaningful when ApprovalRequired is set.
	MinApprovals int
	// SuggestedReviewers is the union of reviewers suggested by the roles.
	SuggestedReviewers []string
	// RecordingMode is the session recording mode required for SSH sessions.
	RecordingMode constants.SessionRecordingMode
	// IdleTimeout is the maximum amount of time a session may remain idle
	// before it is reclaimed. Zero means no idle timeout.
	IdleTimeout time.Duration
	// MaxSessionDuration is the maximum lifetime of a session before it is
	// reclaimed. Zero means sessions are not bounded by duration.
	MaxSessionDuration time.Duration
}

// EvaluatePolicy computes the effective privileged-access Policy for a set
// of roles.
func EvaluatePolicy(roles services.RoleSet) Policy {
	var policy Policy
	reviewers := make(map[string]struct{})

	for _, role := range roles {
		opts := role.GetOptions()
		if opts.RequestAccess == types.RequestStrategyAlways {
			policy.ApprovalRequired = true
		}

		request := role.GetAccessRequestConditions(types.Allow)
		for _, threshold := range request.Thresholds {
			if approve := int(threshold.Approve); approve > policy.MinApprovals {
				policy.MinApprovals = approve
			}
		}
		for _, reviewer := range request.SuggestedReviewers {
			reviewers[reviewer] = struct{}{}
		}

		// The most restrictive (smallest) non-zero session TTL wins.
		if ttl := opts.MaxSessionTTL.Value(); ttl > 0 &&
			(policy.MaxSessionDuration == 0 || ttl < policy.MaxSessionDuration) {
			policy.MaxSessionDuration = ttl
		}
	}

	if policy.ApprovalRequired && policy.MinApprovals == 0 {
		// Mirror the access request default of a single approval.
		policy.MinApprovals = 1
	}

	policy.RecordingMode = roles.SessionRecordingMode(constants.SessionRecordingServiceSSH)
	policy.IdleTimeout = roles.AdjustClientIdleTimeout(0)

	for reviewer := range reviewers {
		policy.SuggestedReviewers = append(policy.SuggestedReviewers, reviewer)
	}
	sort.Strings(policy.SuggestedReviewers)

	return policy
}
