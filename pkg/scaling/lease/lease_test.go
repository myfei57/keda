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

package lease

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testObject     ObjectID = "scaledobject.test-ns.test-so"
	testHolderA    Holder   = "operator-a"
	testHolderB    Holder   = "operator-b"
	testTTL                 = 10 * time.Second
	testRequestID           = "scaledobject.test-ns.test-so#1-1"
	otherRequestID          = "scaledobject.test-ns.test-so#1-2"
)

// fakeClock is a wall-clock-only time source (no monotonic reading), so a
// backwards Set/Advance is visible to the manager as a negative delta and the
// rollback clamping logic is actually exercised.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func newTestManager(t *testing.T, ttl time.Duration) (*Manager, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	manager, err := NewManager(ttl, clock)
	require.NoError(t, err)
	return manager, clock
}

func TestNewManager_InvalidTTL(t *testing.T) {
	_, err := NewManager(0, newFakeClock())
	require.ErrorIs(t, err, ErrInvalidTTL)

	_, err = NewManager(-time.Second, newFakeClock())
	require.ErrorIs(t, err, ErrInvalidTTL)
}

func TestNewManager_DefaultsToSystemClock(t *testing.T) {
	manager, err := NewManager(testTTL, nil)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), manager.RollbackCount())

	handle, err := manager.Acquire(testObject, testHolderA, 0, "")
	require.NoError(t, err)
	assert.True(t, manager.IsActive(testObject))
	assert.Equal(t, testHolderA, handle.Holder)
}

func TestAcquire_ValidatesInputs(t *testing.T) {
	manager, _ := newTestManager(t, testTTL)

	_, err := manager.Acquire("", testHolderA, testTTL, "")
	require.ErrorIs(t, err, ErrEmptyObjectID)

	_, err = manager.Acquire(testObject, "", testTTL, "")
	require.ErrorIs(t, err, ErrEmptyHolder)

	_, err = manager.Acquire(testObject, testHolderA, -time.Second, "")
	require.ErrorIs(t, err, ErrInvalidTTL)
}

func TestAcquire_GrantsLeaseWithFencingToken(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, testRequestID)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), handle.FencingToken)
	assert.Equal(t, testHolderA, handle.Holder)
	assert.Equal(t, testObject, handle.Object)
	assert.True(t, manager.IsActive(testObject))
	assert.Equal(t, clock.Now().Add(testTTL), handle.ExpiresAt)
}

func TestAcquire_DeniesOtherHolderWhileActive(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	assert.Equal(t, uint64(1), handle.FencingToken)

	_, err = manager.Acquire(testObject, testHolderB, testTTL, "")
	require.ErrorIs(t, err, ErrLeaseHeld)
	assert.True(t, manager.IsActive(testObject))

	// the rejected takeover must not have changed the current epoch
	current, ok := manager.Get(testObject)
	require.True(t, ok)
	assert.Equal(t, handle.FencingToken, current.FencingToken)
	assert.Equal(t, testHolderA, current.Holder)

	clock.Advance(testTTL)
	assert.False(t, manager.IsActive(testObject))
}

func TestAcquire_TakeoverOnlyAfterExpiry(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	oldHandle, err := manager.Acquire(testObject, testHolderA, testTTL, testRequestID)
	require.NoError(t, err)
	require.Equal(t, uint64(1), oldHandle.FencingToken)

	// one second before expiry the new leader is still rejected
	clock.Advance(testTTL - time.Second)
	_, err = manager.Acquire(testObject, testHolderB, testTTL, "")
	require.ErrorIs(t, err, ErrLeaseHeld)

	clock.Advance(time.Second)
	newHandle, err := manager.Acquire(testObject, testHolderB, testTTL, "")
	require.NoError(t, err)
	assert.Equal(t, uint64(2), newHandle.FencingToken)
	assert.Equal(t, testHolderB, newHandle.Holder)
	assert.True(t, manager.IsActive(testObject))

	// the deposed leader's handle is now a stale fencing credential
	_, err = manager.Renew(oldHandle, testTTL)
	require.ErrorIs(t, err, ErrFencingToken)
}

func TestAcquire_IdempotentForSameHolder(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	first, err := manager.Acquire(testObject, testHolderA, testTTL, testRequestID)
	require.NoError(t, err)

	clock.Advance(5 * time.Second)

	// retried and re-entrant acquires return the identical epoch and must not
	// extend the deadline: renewal is an explicit Renew call only.
	retry, err := manager.Acquire(testObject, testHolderA, testTTL, testRequestID)
	require.NoError(t, err)
	assert.Equal(t, first, retry)

	reentrant, err := manager.Acquire(testObject, testHolderA, testTTL, otherRequestID)
	require.NoError(t, err)
	assert.Equal(t, first.FencingToken, reentrant.FencingToken)
	assert.Equal(t, first.ExpiresAt, reentrant.ExpiresAt)
}

func TestAcquire_SameHolderAfterExpiryStartsNewEpoch(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	oldHandle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	clock.Advance(testTTL)
	newHandle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	assert.Greater(t, newHandle.FencingToken, oldHandle.FencingToken)
}

func TestRenew_ResetsDeadlineFromNowWithoutAccumulation(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	clock.Advance(6 * time.Second)
	renewed, err := manager.Renew(handle, testTTL)
	require.NoError(t, err)
	assert.Equal(t, handle.FencingToken, renewed.FencingToken)
	assert.Equal(t, clock.Now().Add(testTTL), renewed.ExpiresAt)

	// original deadline would be mono=10s; the renewed deadline is mono=16s.
	clock.Advance(9 * time.Second) // mono=15s: original lease would be expired
	assert.True(t, manager.IsActive(testObject))

	clock.Advance(time.Second) // mono=16s: renewed lease expires exactly here
	assert.False(t, manager.IsActive(testObject))
}

func TestRenew_RejectsStaleAndExpiredLeases(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	wrongHolder := handle
	wrongHolder.Holder = testHolderB
	_, err = manager.Renew(wrongHolder, testTTL)
	require.ErrorIs(t, err, ErrFencingToken)

	wrongToken := handle
	wrongToken.FencingToken++
	_, err = manager.Renew(wrongToken, testTTL)
	require.ErrorIs(t, err, ErrFencingToken)

	clock.Advance(testTTL)
	_, err = manager.Renew(handle, testTTL)
	require.ErrorIs(t, err, ErrLeaseExpired)
}

func TestRelease_RemovesLeaseAndFencesPendingWork(t *testing.T) {
	manager, _ := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	_, err = manager.BeginSubmission(handle, testRequestID)
	require.NoError(t, err)

	require.NoError(t, manager.Release(handle))
	assert.Equal(t, 0, manager.Len())
	_, ok := manager.GetSubmission(testObject, testRequestID)
	assert.False(t, ok)

	// releasing an unknown lease is a not-held error
	err = manager.Release(handle)
	require.ErrorIs(t, err, ErrLeaseNotHeld)
}

func TestRelease_StaleHandleCannotTouchNewEpoch(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	oldHandle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	clock.Advance(testTTL)
	newHandle, err := manager.Acquire(testObject, testHolderB, testTTL, "")
	require.NoError(t, err)

	err = manager.Release(oldHandle)
	require.ErrorIs(t, err, ErrFencingToken)
	current, ok := manager.Get(testObject)
	require.True(t, ok)
	assert.Equal(t, newHandle.FencingToken, current.FencingToken)
}

func TestRemove_IsIdempotentAndIgnoresEpoch(t *testing.T) {
	manager, _ := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	manager.Remove(testObject)
	manager.Remove(testObject) // unknown object: no-op, no error
	assert.Equal(t, 0, manager.Len())

	// a fresh acquire after removal starts a new epoch
	newHandle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	assert.Greater(t, newHandle.FencingToken, handle.FencingToken)
}

func TestNewRequestID_UniqueWithinAndAcrossEpochs(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	first, err := manager.NewRequestID(handle)
	require.NoError(t, err)
	second, err := manager.NewRequestID(handle)
	require.NoError(t, err)
	assert.NotEqual(t, first, second)
	assert.Contains(t, first, "#1-1")
	assert.Contains(t, second, "#1-2")

	clock.Advance(testTTL)
	newHandle, err := manager.Acquire(testObject, testHolderB, testTTL, "")
	require.NoError(t, err)
	third, err := manager.NewRequestID(newHandle)
	require.NoError(t, err)
	assert.Contains(t, third, "#2-1")

	_, err = manager.NewRequestID(handle)
	require.ErrorIs(t, err, ErrFencingToken)
}

func TestBeginSubmission_DuplicatePendingIsRejected(t *testing.T) {
	manager, _ := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	submission, err := manager.BeginSubmission(handle, testRequestID)
	require.NoError(t, err)
	assert.Equal(t, SubmissionPending, submission.State)
	assert.Equal(t, handle.FencingToken, submission.FencingToken)

	_, err = manager.BeginSubmission(handle, testRequestID)
	require.ErrorIs(t, err, ErrSubmissionInFlight)

	_, err = manager.BeginSubmission(handle, "")
	require.ErrorIs(t, err, ErrEmptyRequestID)
}

func TestSubmission_AcknowledgedResultIsReplayedNotResubmitted(t *testing.T) {
	manager, _ := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	_, err = manager.BeginSubmission(handle, testRequestID)
	require.NoError(t, err)

	ackErr := errors.New("scale target unavailable")
	require.NoError(t, manager.AckSubmission(handle, testRequestID, ackErr))

	recorded, ok := manager.GetSubmission(testObject, testRequestID)
	require.True(t, ok)
	assert.Equal(t, SubmissionAcknowledged, recorded.State)
	assert.Equal(t, ackErr, recorded.AckErr)
	assert.False(t, recorded.AcknowledgedAt.IsZero())

	// repeating the same request ID returns the stored submission instead of
	// creating a second pending submission
	replay, err := manager.BeginSubmission(handle, testRequestID)
	require.NoError(t, err)
	assert.Equal(t, SubmissionAcknowledged, replay.State)
	assert.Equal(t, ackErr, replay.AckErr)

	// idempotent re-ack with the same result succeeds, a conflicting one fails
	require.NoError(t, manager.AckSubmission(handle, testRequestID, ackErr))
	err = manager.AckSubmission(handle, testRequestID, errors.New("different result"))
	require.ErrorIs(t, err, ErrSubmissionAlreadyAcked)

	// unknown request IDs cannot be acknowledged
	err = manager.AckSubmission(handle, otherRequestID, nil)
	require.ErrorIs(t, err, ErrSubmissionNotFound)
}

func TestTakeover_FencesUnacknowledgedSubmissions(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	oldHandle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	_, err = manager.BeginSubmission(oldHandle, testRequestID)
	require.NoError(t, err)

	clock.Advance(testTTL)
	newHandle, err := manager.Acquire(testObject, testHolderB, testTTL, "")
	require.NoError(t, err)

	// the old pending submission is fenced and can never be (re)submitted
	recorded, ok := manager.GetSubmission(testObject, testRequestID)
	require.True(t, ok)
	assert.Equal(t, SubmissionFenced, recorded.State)

	_, err = manager.BeginSubmission(newHandle, testRequestID)
	require.ErrorIs(t, err, ErrSubmissionFenced)

	// the deposed leader's late acknowledgment is rejected and discarded
	err = manager.AckSubmission(oldHandle, testRequestID, nil)
	require.ErrorIs(t, err, ErrFencingToken)
	recorded, ok = manager.GetSubmission(testObject, testRequestID)
	require.True(t, ok)
	assert.Equal(t, SubmissionFenced, recorded.State)
}

func TestTakeover_KeepsAcknowledgedHistoryReplayable(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	oldHandle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	_, err = manager.BeginSubmission(oldHandle, testRequestID)
	require.NoError(t, err)
	require.NoError(t, manager.AckSubmission(oldHandle, testRequestID, nil))

	clock.Advance(testTTL)
	newHandle, err := manager.Acquire(testObject, testHolderB, testTTL, "")
	require.NoError(t, err)

	// acknowledged history survives the epoch boundary: the new leader replays
	// it instead of issuing a duplicate submission for the same request ID
	replay, err := manager.BeginSubmission(newHandle, testRequestID)
	require.NoError(t, err)
	assert.Equal(t, SubmissionAcknowledged, replay.State)
	assert.Equal(t, oldHandle.FencingToken, replay.FencingToken)
}

func TestBeginSubmission_RejectsExpiredLease(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	clock.Advance(testTTL)

	_, err = manager.BeginSubmission(handle, testRequestID)
	require.ErrorIs(t, err, ErrLeaseExpired)
}

func TestClockRollback_NeverExtendsOrShortensLease(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)
	start := clock.Now()

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	// 6s of effective time pass and are sampled, then the wall clock jumps
	// back 5s: the mono base stays at 6s and the rollback is counted.
	clock.Advance(6 * time.Second)
	require.True(t, manager.IsActive(testObject))
	clock.Set(start.Add(time.Second))
	assert.True(t, manager.IsActive(testObject))
	assert.Equal(t, uint64(1), manager.RollbackCount())

	// 3s of forward progress after the rollback -> mono=9s, still active
	clock.Advance(3 * time.Second)
	assert.True(t, manager.IsActive(testObject))

	// another backwards jump must freeze the base again, not rewind it
	clock.Set(start.Add(2 * time.Second))
	assert.True(t, manager.IsActive(testObject))
	assert.Equal(t, uint64(2), manager.RollbackCount())

	// mono reaches the original 10s TTL only through real forward progress
	clock.Advance(2 * time.Second)
	assert.False(t, manager.IsActive(testObject))

	// takeover remains gated on expiry even after the rollback
	newHandle, err := manager.Acquire(testObject, testHolderB, testTTL, "")
	require.NoError(t, err)
	assert.Greater(t, newHandle.FencingToken, handle.FencingToken)
}

func TestClockRollback_RenewalStillBasedOnMonotonicTime(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)
	start := clock.Now()

	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	// sample t+4s first, then roll the wall clock fully back to the grant
	// instant: mono stays at 4s and the rollback is counted on the next tick
	clock.Advance(4 * time.Second)
	require.True(t, manager.IsActive(testObject))
	clock.Set(start)

	renewed, err := manager.Renew(handle, testTTL)
	require.NoError(t, err)
	require.Equal(t, uint64(1), manager.RollbackCount())
	assert.Equal(t, clock.Now().Add(testTTL), renewed.ExpiresAt)

	// renewed deadline is at mono=14s; 9s of forward progress keeps it alive
	// (mono=13s), one more second expires the lease (mono=14s)
	clock.Advance(9 * time.Second)
	assert.True(t, manager.IsActive(testObject))
	clock.Advance(time.Second)
	assert.False(t, manager.IsActive(testObject))
}

func TestConcurrentAcquire_OnlyOneHolderWins(t *testing.T) {
	manager, _ := newTestManager(t, testTTL)

	const contenders = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, contenders)
	for i := range contenders {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			holder := Holder("operator-" + string(rune('A'+n)))
			_, err := manager.Acquire(testObject, holder, testTTL, "")
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	granted, denied := 0, 0
	for err := range results {
		switch {
		case err == nil:
			granted++
		case errors.Is(err, ErrLeaseHeld):
			denied++
		default:
			t.Fatalf("unexpected acquire error: %v", err)
		}
	}
	assert.Equal(t, 1, granted)
	assert.Equal(t, contenders-1, denied)
	assert.Equal(t, 1, manager.Len())
}

func TestConcurrentTakeoverAfterExpiry_SingleNewEpoch(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)

	oldHandle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)
	clock.Advance(testTTL)

	const contenders = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, contenders)
	for i := range contenders {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			// each contender is a distinct candidate leader, so exactly one
			// can acquire the expired lease while all others are denied
			holder := Holder("operator-takeover-" + string(rune('A'+n)))
			_, err := manager.Acquire(testObject, holder, testTTL, "")
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	granted, denied := 0, 0
	for err := range results {
		switch {
		case err == nil:
			granted++
		case errors.Is(err, ErrLeaseHeld):
			denied++
		default:
			t.Fatalf("unexpected takeover error: %v", err)
		}
	}
	assert.Equal(t, 1, granted)
	assert.Equal(t, contenders-1, denied)

	current, ok := manager.Get(testObject)
	require.True(t, ok)
	assert.NotEqual(t, testHolderA, current.Holder)
	assert.Equal(t, oldHandle.FencingToken+1, current.FencingToken)
}

func TestConcurrentBeginSubmission_SinglePendingPerRequestID(t *testing.T) {
	manager, _ := newTestManager(t, testTTL)
	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	const contenders = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, contenders)
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := manager.BeginSubmission(handle, testRequestID)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	started, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			started++
		case errors.Is(err, ErrSubmissionInFlight):
			rejected++
		default:
			t.Fatalf("unexpected begin error: %v", err)
		}
	}
	assert.Equal(t, 1, started)
	assert.Equal(t, contenders-1, rejected)
}

func TestConcurrentRenew_LeaseNeverAccumulatesLeaseTime(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)
	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	clock.Advance(2 * time.Second)

	const contenders = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := manager.Renew(handle, testTTL)
			assert.NoError(t, err)
		}()
	}
	close(start)
	wg.Wait()

	// all renewals reset the deadline to now+ttl: at mono=2s the deadline must
	// be mono=12s, regardless of how many renewals raced.
	clock.Advance(9 * time.Second) // mono=11s
	assert.True(t, manager.IsActive(testObject))
	clock.Advance(time.Second) // mono=12s
	assert.False(t, manager.IsActive(testObject))
}

func TestConcurrentMixedOperations_AreRaceFree(t *testing.T) {
	manager, clock := newTestManager(t, testTTL)
	handle, err := manager.Acquire(testObject, testHolderA, testTTL, "")
	require.NoError(t, err)

	const rounds = 100
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range rounds {
				switch i % 4 {
				case 0:
					_, _ = manager.Acquire(testObject, testHolderA, testTTL, "")
				case 1:
					_, _ = manager.Renew(handle, testTTL)
				case 2:
					requestID, idErr := manager.NewRequestID(handle)
					if idErr == nil {
						_, _ = manager.BeginSubmission(handle, requestID)
						_ = manager.AckSubmission(handle, requestID, nil)
					}
				default:
					_ = manager.RollbackCount()
					_ = manager.IsActive(testObject)
				}
			}
		}()
	}
	wg.Wait()

	clock.Advance(testTTL)
	assert.False(t, manager.IsActive(testObject))
}
