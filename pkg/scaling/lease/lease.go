/*
Copyright 2026 The KEDA Authors

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

// Package lease provides an in-memory lease planner that guards scale
// submissions for ScaledObjects while the operator leadership changes.
//
// The planner never calls the Kubernetes API: every decision is a pure
// in-process state transition guarded by a mutex and driven by an injectable
// Clock. Its guarantees are:
//
//   - A ScaledObject can be held by at most one leader (Holder) at any time.
//     A new leader can take over only after the previous lease has expired.
//   - Every granted lease gets a monotonically increasing fencing token.
//     Renewals, releases and acknowledgments presented with a stale token
//     are rejected, so a deposed leader cannot mutate a lease it no longer owns.
//   - Scale submissions are idempotent per request ID: a submission that is
//     still pending must not be submitted again, and an acknowledged result is
//     replayed instead of recomputed. Pending submissions of an expired epoch
//     are fenced before a takeover and can never be re-submitted.
//   - Wall-clock rollbacks cannot extend or shorten a lease: expiry is computed
//     against an internal monotonic time base that clamps negative deltas to
//     zero while counting the rollback.
package lease

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Sentinel errors returned by the Manager. Callers must inspect them with
// errors.Is rather than matching on message text.
var (
	// ErrInvalidTTL is returned when neither the explicit TTL nor the
	// manager default TTL is positive.
	ErrInvalidTTL = errors.New("lease TTL must be greater than zero")
	// ErrEmptyObjectID is returned when the ScaledObject identifier is blank.
	ErrEmptyObjectID = errors.New("scaled object id must not be empty")
	// ErrEmptyHolder is returned when the holder identity is blank.
	ErrEmptyHolder = errors.New("holder must not be empty")
	// ErrEmptyRequestID is returned when the submission request ID is blank.
	ErrEmptyRequestID = errors.New("request id must not be empty")
	// ErrLeaseHeld is returned when an acquire targets a lease that is still
	// actively held by a different holder.
	ErrLeaseHeld = errors.New("lease is held by another holder and has not expired")
	// ErrLeaseNotHeld is returned when the referenced lease no longer exists.
	ErrLeaseNotHeld = errors.New("lease is not held")
	// ErrLeaseExpired is returned when an operation requires an active lease
	// but its TTL has already elapsed. The caller must acquire the lease again.
	ErrLeaseExpired = errors.New("lease has expired")
	// ErrFencingToken is returned when the handle does not match the current
	// lease epoch, i.e. the caller was deposed by a newer leader.
	ErrFencingToken = errors.New("stale fencing token: lease epoch changed")
	// ErrSubmissionInFlight is returned when the same request ID is started
	// again before its previous submission is acknowledged. The caller must
	// not submit the scale decision a second time.
	ErrSubmissionInFlight = errors.New("scale submission is still in flight")
	// ErrSubmissionFenced is returned when a submission belongs to an expired
	// lease epoch and was fenced during takeover. It can never be submitted.
	ErrSubmissionFenced = errors.New("scale submission was fenced during lease takeover")
	// ErrSubmissionNotFound is returned when acknowledging a request ID the
	// manager does not know about.
	ErrSubmissionNotFound = errors.New("scale submission not found")
	// ErrSubmissionAlreadyAcked is returned when an acknowledgment conflicts
	// with the result already recorded for the request ID.
	ErrSubmissionAlreadyAcked = errors.New("scale submission was already acknowledged with a different result")
)

// Holder identifies the leader that owns a lease, typically the operator pod
// name backed by the controller-runtime leader election.
type Holder string

// ObjectID is the per-ScaledObject lease key, using the same
// "kind.namespace.name" identifier the scale handler generates.
type ObjectID string

// SubmissionState is the lifecycle state of a single scale submission.
type SubmissionState string

const (
	// SubmissionPending means the scale decision has been started but not yet
	// acknowledged. A pending request ID cannot be started again.
	SubmissionPending SubmissionState = "Pending"
	// SubmissionAcknowledged means the scale result was recorded. Repeating the
	// same request ID replays this submission instead of submitting again.
	SubmissionAcknowledged SubmissionState = "Acknowledged"
	// SubmissionFenced means the owning lease epoch ended before
	// acknowledgment. The submission is permanently rejected.
	SubmissionFenced SubmissionState = "Fenced"
)

// Handle is an immutable snapshot of a granted lease. It is the fencing
// credential callers present for renew, release and submission operations.
type Handle struct {
	// Object is the leased ScaledObject identifier.
	Object ObjectID
	// Holder is the leader identity that owns this lease epoch.
	Holder Holder
	// FencingToken increases by one on every grant; it stays stable across
	// renewals and changes when a lease is granted after expiry.
	FencingToken uint64
	// AcquiredAt is the wall-clock time at which the epoch was granted.
	AcquiredAt time.Time
	// ExpiresAt is the wall-clock projection of the mono deadline, for
	// observability only. Expiry decisions use the internal monotonic base.
	ExpiresAt time.Time
}

// Submission describes one idempotent scale submission within a lease epoch.
type Submission struct {
	// RequestID is the caller-supplied idempotency key.
	RequestID string
	// State is the current lifecycle state.
	State SubmissionState
	// FencingToken records the lease epoch that owns the submission.
	FencingToken uint64
	// StartedAt is when the submission entered SubmissionPending.
	StartedAt time.Time
	// AcknowledgedAt is when the result was recorded, zero while pending.
	AcknowledgedAt time.Time
	// AckErr is the error carried by the acknowledgment, nil on success.
	AckErr error
}

// Manager maintains one scaler lease per ScaledObject. It is safe for
// concurrent use and performs no I/O of any kind.
type Manager struct {
	mu sync.Mutex

	clock      Clock
	defaultTTL time.Duration

	// mono is the accumulated monotonic time base. Every observed clock
	// reading contributes max(0, now-lastNow), so a backwards jump freezes
	// the base instead of rewinding it.
	mono      time.Duration
	lastNow   time.Time
	rollbacks uint64

	nextToken uint64
	leases    map[ObjectID]*scalerLease
}

// scalerLease is the mutable internal state of one lease epoch.
type scalerLease struct {
	holder            Holder
	token             uint64
	acquiredMono      time.Duration
	deadlineMono      time.Duration
	acquiredAt        time.Time
	expiresAt         time.Time
	acquireRequestID  string
	nextSubmissionSeq uint64
	// submissions is carried over an expiry/takeover boundary so that old
	// request IDs remain recognizable (fenced or acknowledged) and can never
	// be turned into a fresh submission by the new leader.
	submissions map[string]*Submission
}

// NewManager creates a Manager using defaultTTL whenever an operation does
// not specify an explicit TTL. A nil clock falls back to the system clock.
func NewManager(defaultTTL time.Duration, clock Clock) (*Manager, error) {
	if defaultTTL <= 0 {
		return nil, ErrInvalidTTL
	}
	if clock == nil {
		clock = SystemClock{}
	}
	return &Manager{
		clock:      clock,
		defaultTTL: defaultTTL,
		leases:     make(map[ObjectID]*scalerLease),
	}, nil
}

// Acquire returns a lease for object on behalf of holder.
//
//   - With no lease, or with an expired lease, a new epoch (with a new fencing
//     token) is granted. Pending submissions of the previous epoch are fenced.
//   - An active lease held by holder is returned unchanged: re-entrant and
//     retried acquires are idempotent and never extend the deadline.
//   - An active lease held by another holder is rejected with ErrLeaseHeld;
//     takeover is possible only after expiry.
//
// requestID is recorded for audit; it may be empty for non-idempotent callers.
// A ttl of zero selects the manager default TTL.
func (m *Manager) Acquire(object ObjectID, holder Holder, ttl time.Duration, requestID string) (Handle, error) {
	if object == "" {
		return Handle{}, ErrEmptyObjectID
	}
	if holder == "" {
		return Handle{}, ErrEmptyHolder
	}
	effectiveTTL, err := m.ttlOrDefault(ttl)
	if err != nil {
		return Handle{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now, mono := m.tickLocked()
	if active, ok := m.leases[object]; ok && mono < active.deadlineMono {
		if active.holder != holder {
			return Handle{}, fmt.Errorf("%w: object %q held by %q until %s", ErrLeaseHeld, object, active.holder, active.expiresAt.Format(time.RFC3339Nano))
		}
		return m.handleLocked(object, active), nil
	}

	return m.grantLocked(object, holder, effectiveTTL, now, mono, requestID), nil
}

// Renew extends the lease referenced by handle. The new deadline is measured
// from the current time (now + ttl), never from the previous deadline, so
// repeated renewals cannot accumulate lease time. Renewals keep the same
// fencing token. Stale handles are rejected with ErrFencingToken and expired
// leases with ErrLeaseExpired.
func (m *Manager) Renew(handle Handle, ttl time.Duration) (Handle, error) {
	effectiveTTL, err := m.ttlOrDefault(ttl)
	if err != nil {
		return Handle{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now, mono := m.tickLocked()
	active, err := m.validateHandleLocked(handle)
	if err != nil {
		return Handle{}, err
	}
	if mono >= active.deadlineMono {
		return Handle{}, ErrLeaseExpired
	}

	active.deadlineMono = mono + effectiveTTL
	active.expiresAt = now.Add(effectiveTTL)
	return m.handleLocked(handle.Object, active), nil
}

// Release surrenders an active lease. Pending submissions are fenced and the
// lease is removed, so a later acquire starts a fresh epoch. A stale handle
// (the lease was already taken over) is rejected with ErrFencingToken and
// leaves the new epoch untouched.
func (m *Manager) Release(handle Handle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tickLocked()
	active, err := m.validateHandleLocked(handle)
	if err != nil {
		return err
	}
	m.fencePendingLocked(active)
	delete(m.leases, handle.Object)
	return nil
}

// Remove deletes every lease state for object regardless of holder or epoch.
// It is intended for ScaledObject deletion, where no successor epoch exists.
// It is a no-op when the object is unknown.
func (m *Manager) Remove(object ObjectID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tickLocked()
	delete(m.leases, object)
}

// NewRequestID mints the idempotency key for one scale submission within the
// lease epoch of handle. The key embeds the fencing token and a per-epoch
// sequence, so it is unique across epochs and stable when the caller retries
// with the same value.
func (m *Manager) NewRequestID(handle Handle) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, mono := m.tickLocked()
	active, err := m.validateHandleLocked(handle)
	if err != nil {
		return "", err
	}
	if mono >= active.deadlineMono {
		return "", ErrLeaseExpired
	}

	active.nextSubmissionSeq++
	return fmt.Sprintf("%s#%d-%d", handle.Object, active.token, active.nextSubmissionSeq), nil
}

// BeginSubmission registers a scale submission for requestID and returns its
// recorded state.
//
//   - Unknown request ID on an active handle: a new Pending submission is
//     returned and the caller is allowed to submit the scale decision once.
//   - Pending request ID: ErrSubmissionInFlight, the caller must skip.
//   - Acknowledged request ID: the stored submission is returned and the
//     caller must reuse its result instead of resubmitting.
//   - Fenced request ID (owned by a dead epoch): ErrSubmissionFenced.
//
// Stale handles are rejected with ErrFencingToken and expired leases with
// ErrLeaseExpired.
func (m *Manager) BeginSubmission(handle Handle, requestID string) (Submission, error) {
	if requestID == "" {
		return Submission{}, ErrEmptyRequestID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now, mono := m.tickLocked()
	active, err := m.validateHandleLocked(handle)
	if err != nil {
		return Submission{}, err
	}
	if mono >= active.deadlineMono {
		return Submission{}, ErrLeaseExpired
	}

	if existing, ok := active.submissions[requestID]; ok {
		switch existing.State {
		case SubmissionPending:
			return Submission{}, ErrSubmissionInFlight
		case SubmissionFenced:
			return Submission{}, ErrSubmissionFenced
		default:
			return *existing, nil
		}
	}

	submission := &Submission{
		RequestID:    requestID,
		State:        SubmissionPending,
		FencingToken: active.token,
		StartedAt:    now,
	}
	active.submissions[requestID] = submission
	return *submission, nil
}

// AckSubmission records the result of a previously started submission. An
// acknowledgment presented with a stale fencing token (the leader was deposed
// and the lease was taken over) fences the pending entry and returns
// ErrFencingToken: the late result is discarded rather than applied to the
// new leader's epoch. Re-acknowledging with the same result is a no-op.
func (m *Manager) AckSubmission(handle Handle, requestID string, ackErr error) error {
	if requestID == "" {
		return ErrEmptyRequestID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	active, err := m.validateHandleLocked(handle)
	if err != nil {
		if current, ok := m.leases[handle.Object]; ok {
			if submission, exists := current.submissions[requestID]; exists && submission.State == SubmissionPending {
				submission.State = SubmissionFenced
			}
		}
		return err
	}

	submission, ok := active.submissions[requestID]
	if !ok {
		return ErrSubmissionNotFound
	}
	switch submission.State {
	case SubmissionFenced:
		return ErrSubmissionFenced
	case SubmissionAcknowledged:
		if !sameAckError(submission.AckErr, ackErr) {
			return ErrSubmissionAlreadyAcked
		}
		return nil
	default:
		submission.State = SubmissionAcknowledged
		submission.AcknowledgedAt = m.clock.Now()
		submission.AckErr = ackErr
		return nil
	}
}

// Get returns a snapshot of the lease for object together with whether it
// exists. The snapshot may describe an expired lease; combine with IsActive
// when liveness matters.
func (m *Manager) Get(object ObjectID) (Handle, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tickLocked()
	active, ok := m.leases[object]
	if !ok {
		return Handle{}, false
	}
	return m.handleLocked(object, active), true
}

// IsActive reports whether object currently has a non-expired lease.
func (m *Manager) IsActive(object ObjectID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, mono := m.tickLocked()
	active, ok := m.leases[object]
	return ok && mono < active.deadlineMono
}

// Len returns the number of currently tracked leases, including expired ones
// that have not been released or taken over yet.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.leases)
}

// RollbackCount reports how many backwards clock jumps have been observed.
func (m *Manager) RollbackCount() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.rollbacks
}

// GetSubmission returns the recorded submission state for requestID.
func (m *Manager) GetSubmission(object ObjectID, requestID string) (Submission, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	active, ok := m.leases[object]
	if !ok {
		return Submission{}, false
	}
	submission, ok := active.submissions[requestID]
	if !ok {
		return Submission{}, false
	}
	return *submission, true
}

// ttlOrDefault resolves the effective TTL and validates it while holding no
// lock, so the check itself cannot block other operations.
func (m *Manager) ttlOrDefault(ttl time.Duration) (time.Duration, error) {
	if ttl == 0 {
		ttl = m.defaultTTL
	}
	if ttl <= 0 {
		return 0, ErrInvalidTTL
	}
	return ttl, nil
}

// tickLocked advances the internal monotonic base. Negative deltas (wall-clock
// rollback) contribute zero time and increment the rollback counter, ensuring
// expiry can neither be skipped nor postponed by a clock change.
func (m *Manager) tickLocked() (time.Time, time.Duration) {
	now := m.clock.Now()
	if !m.lastNow.IsZero() {
		delta := now.Sub(m.lastNow)
		if delta < 0 {
			delta = 0
			m.rollbacks++
		}
		m.mono += delta
	}
	m.lastNow = now
	return now, m.mono
}

// grantLocked starts a new lease epoch, carrying over the submission history
// of any previous epoch so stale request IDs stay fenced or replayable.
func (m *Manager) grantLocked(object ObjectID, holder Holder, ttl time.Duration, now time.Time, mono time.Duration, requestID string) Handle {
	carriedSubmissions := map[string]*Submission{}
	if previous, ok := m.leases[object]; ok {
		m.fencePendingLocked(previous)
		carriedSubmissions = previous.submissions
	}

	m.nextToken++
	active := &scalerLease{
		holder:           holder,
		token:            m.nextToken,
		acquiredMono:     mono,
		deadlineMono:     mono + ttl,
		acquiredAt:       now,
		expiresAt:        now.Add(ttl),
		acquireRequestID: requestID,
		submissions:      carriedSubmissions,
	}
	m.leases[object] = active
	return m.handleLocked(object, active)
}

// validateHandleLocked verifies that handle still describes the current epoch.
func (m *Manager) validateHandleLocked(handle Handle) (*scalerLease, error) {
	active, ok := m.leases[handle.Object]
	if !ok {
		return nil, fmt.Errorf("%w: object %q", ErrLeaseNotHeld, handle.Object)
	}
	if active.holder != handle.Holder || active.token != handle.FencingToken {
		return nil, fmt.Errorf("%w: object %q is held by %q at epoch %d", ErrFencingToken, handle.Object, active.holder, active.token)
	}
	return active, nil
}

// handleLocked snapshots an internal lease into the exported Handle type.
func (m *Manager) handleLocked(object ObjectID, active *scalerLease) Handle {
	return Handle{
		Object:       object,
		Holder:       active.holder,
		FencingToken: active.token,
		AcquiredAt:   active.acquiredAt,
		ExpiresAt:    active.expiresAt,
	}
}

// fencePendingLocked marks every unacknowledged submission of a dead epoch as
// fenced so it can never be submitted or acknowledged afterward.
func (m *Manager) fencePendingLocked(active *scalerLease) {
	for _, submission := range active.submissions {
		if submission.State == SubmissionPending {
			submission.State = SubmissionFenced
		}
	}
}

// sameAckError compares two acknowledgment errors, treating nil and wrapped
// sentinel errors consistently.
func sameAckError(left, right error) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return errors.Is(left, right) && errors.Is(right, left)
}
