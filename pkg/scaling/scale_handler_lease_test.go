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

package scaling

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kedav1alpha1 "github.com/kedacore/keda/v2/apis/keda/v1alpha1"
	"github.com/kedacore/keda/v2/pkg/scaling/executor"
	"github.com/kedacore/keda/v2/pkg/scaling/lease"
)

func newLeasedScaledObject() *kedav1alpha1.ScaledObject {
	return &kedav1alpha1.ScaledObject{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "leased-so",
			Namespace: "leased-ns",
		},
	}
}

func TestBeginScalerLease_DisabledManagerAllowsSubmission(t *testing.T) {
	handler := &scaleHandler{}
	scaledObject := newLeasedScaledObject()

	handle, requestID, proceed := handler.beginScalerLease(scaledObject)
	require.True(t, proceed)
	assert.Empty(t, requestID)
	assert.Equal(t, lease.Handle{}, handle)

	// the disabled path must be a safe no-op instead of panicking
	assert.NotPanics(t, func() {
		handler.endScalerLease(handle, requestID, executor.ScaleResult{})
	})
}

func TestScalerLease_BeginEndRoundTrip(t *testing.T) {
	manager, err := lease.NewManager(time.Minute, nil)
	require.NoError(t, err)
	handler := &scaleHandler{leaseManager: manager, leaseHolder: lease.Holder("operator-a")}
	scaledObject := newLeasedScaledObject()
	objectID := lease.ObjectID(scaledObject.GenerateIdentifier())

	handle, requestID, proceed := handler.beginScalerLease(scaledObject)
	require.True(t, proceed)
	require.NotEmpty(t, requestID)
	assert.True(t, manager.IsActive(objectID))

	pending, ok := manager.GetSubmission(objectID, requestID)
	require.True(t, ok)
	assert.Equal(t, lease.SubmissionPending, pending.State)

	// acknowledging records the result and renews the lease for the next tick
	handler.endScalerLease(handle, requestID, executor.ScaleResult{})
	acknowledged, ok := manager.GetSubmission(objectID, requestID)
	require.True(t, ok)
	assert.Equal(t, lease.SubmissionAcknowledged, acknowledged.State)
	assert.NoError(t, acknowledged.AckErr)
	assert.True(t, manager.IsActive(objectID))

	// the next tick gets a distinct request ID, never reusing the prior one
	nextHandle, nextRequestID, nextProceed := handler.beginScalerLease(scaledObject)
	require.True(t, nextProceed)
	assert.NotEqual(t, requestID, nextRequestID)
	assert.Equal(t, handle.FencingToken, nextHandle.FencingToken)

	scaleErr := errors.New("scale target unavailable")
	handler.endScalerLease(nextHandle, nextRequestID, executor.ScaleResult{Error: scaleErr})
	failed, ok := manager.GetSubmission(objectID, nextRequestID)
	require.True(t, ok)
	assert.Equal(t, lease.SubmissionAcknowledged, failed.State)
	assert.Equal(t, scaleErr, failed.AckErr)
}

func TestBeginScalerLease_SkipsWhileAnotherLeaderHoldsIt(t *testing.T) {
	manager, err := lease.NewManager(time.Minute, nil)
	require.NoError(t, err)
	scaledObject := newLeasedScaledObject()
	objectID := lease.ObjectID(scaledObject.GenerateIdentifier())

	// another leader acquired the lease first and still holds it actively
	_, err = manager.Acquire(objectID, lease.Holder("operator-b"), time.Minute, "")
	require.NoError(t, err)

	handler := &scaleHandler{leaseManager: manager, leaseHolder: lease.Holder("operator-a")}
	_, requestID, proceed := handler.beginScalerLease(scaledObject)
	assert.False(t, proceed)
	assert.Empty(t, requestID)

	// the rejected leader must not have created any lease or submission state
	assert.Equal(t, 1, manager.Len())
	current, ok := manager.Get(objectID)
	require.True(t, ok)
	assert.Equal(t, lease.Holder("operator-b"), current.Holder)
}

func TestEndScalerLease_StaleHandleIsSwallowed(t *testing.T) {
	manager, err := lease.NewManager(time.Minute, nil)
	require.NoError(t, err)
	handler := &scaleHandler{leaseManager: manager, leaseHolder: lease.Holder("operator-a")}
	scaledObject := newLeasedScaledObject()

	handle, requestID, proceed := handler.beginScalerLease(scaledObject)
	require.True(t, proceed)

	// the object is deleted before the result is acknowledged; ending the
	// lease with the stale handle must only log, never panic or resubmit
	manager.Remove(lease.ObjectID(scaledObject.GenerateIdentifier()))
	assert.NotPanics(t, func() {
		handler.endScalerLease(handle, requestID, executor.ScaleResult{})
	})
	_, ok := manager.GetSubmission(lease.ObjectID(scaledObject.GenerateIdentifier()), requestID)
	assert.False(t, ok)
}
