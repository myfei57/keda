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

package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	kedav1alpha1 "github.com/kedacore/keda/v2/apis/keda/v1alpha1"
	"github.com/kedacore/keda/v2/pkg/mock/mock_client"
)

const (
	testScaledJobName      = "test-sj"
	testScaledJobNamespace = "test-ns"
	testScaledJobUID       = types.UID("scaledjob-current-uid")
	testStaleOwnerUID      = types.UID("scaledjob-old-uid")
)

func newPlanTestScaledJob() *kedav1alpha1.ScaledJob {
	maxReplicaCount := int32(10)
	successfulJobsHistoryLimit := int32(2)
	failedJobsHistoryLimit := int32(2)
	return &kedav1alpha1.ScaledJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testScaledJobName,
			Namespace:  testScaledJobNamespace,
			UID:        testScaledJobUID,
			Generation: 1,
			Labels:     map[string]string{"team": "platform"},
		},
		Spec: kedav1alpha1.ScaledJobSpec{
			JobTargetRef:               &batchv1.JobSpec{},
			MaxReplicaCount:            &maxReplicaCount,
			SuccessfulJobsHistoryLimit: &successfulJobsHistoryLimit,
			FailedJobsHistoryLimit:     &failedJobsHistoryLimit,
		},
	}
}

func planTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(kedav1alpha1.AddToScheme(scheme))
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	return scheme
}

// plannedTestJob builds an informer-cached Job labeled for the ScaledJob. When
// ownerUID is empty the current ScaledJob UID is used; pass a different UID to
// simulate an orphan from an old owner.
func plannedTestJob(name string, sj *kedav1alpha1.ScaledJob, ownerUID types.UID, condition batchv1.JobConditionType, completion time.Time) *batchv1.Job {
	if ownerUID == "" {
		ownerUID = sj.UID
	}
	controller := true
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: sj.Namespace,
			Labels:    map[string]string{scaledJobNameLabel: sj.Name},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: kedav1alpha1.GroupVersion.String(),
				Kind:       "ScaledJob",
				Name:       sj.Name,
				UID:        ownerUID,
				Controller: &controller,
			}},
		},
	}
	if condition != "" {
		job.Status.Conditions = []batchv1.JobCondition{{Type: condition, Status: corev1.ConditionTrue}}
		completionTime := metav1.NewTime(completion)
		job.Status.CompletionTime = &completionTime
	}
	return job
}

func unownedTestJob(name string, sj *kedav1alpha1.ScaledJob) *batchv1.Job {
	job := plannedTestJob(name, sj, sj.UID, "", time.Time{})
	job.OwnerReferences = nil
	return job
}

func planConflictReasons(conflicts []PlanConflict) map[PlanConflictReason]int {
	reasons := make(map[PlanConflictReason]int, len(conflicts))
	for _, conflict := range conflicts {
		reasons[conflict.Reason]++
	}
	return reasons
}

func TestBuildJobBatchPlan_CreatesBatchFromQueueLength(t *testing.T) {
	sj := newPlanTestScaledJob()
	scheme := planTestScheme()

	plan := buildJobBatchPlan(logf.Log.WithName("test"), sj, 3, 3, nil, scheme)

	require.Len(t, plan.JobsToCreate, 3)
	assert.Equal(t, testScaledJobUID, plan.ScaledJobUID)
	assert.Equal(t, int64(3), plan.QueueLength)
	assert.Equal(t, int64(10), plan.MaxReplicaCount)
	assert.Equal(t, int64(0), plan.RunningJobCount)
	assert.Empty(t, plan.JobsToRecycle)
	assert.Empty(t, plan.Conflicts)

	for _, job := range plan.JobsToCreate {
		assert.Equal(t, testScaledJobName+"-", job.GenerateName)
		assert.Equal(t, testScaledJobNamespace, job.Namespace)
		assert.Equal(t, testScaledJobName, job.Labels[scaledJobNameLabel])
		assert.Equal(t, "platform", job.Labels["team"])
		assert.Equal(t, "1", job.Annotations["scaledjob.keda.sh/generation"])
		assert.Equal(t, corev1.RestartPolicyOnFailure, job.Spec.Template.Spec.RestartPolicy)
		owner := metav1.GetControllerOf(job)
		require.NotNil(t, owner)
		assert.Equal(t, testScaledJobUID, owner.UID)
	}
}

func TestBuildJobBatchPlan_DuplicateReconcileIsIdempotent(t *testing.T) {
	sj := newPlanTestScaledJob()
	scheme := planTestScheme()
	logger := logf.Log.WithName("test")

	// First reconcile: the informer has not observed any Job yet, so the full
	// queue length must be planned for creation.
	firstPlan := buildJobBatchPlan(logger, sj, 3, 3, nil, scheme)
	require.Len(t, firstPlan.JobsToCreate, 3)

	// After the batch is created the informer observes three owned running Jobs.
	observed := []batchv1.Job{
		*plannedTestJob("job-1", sj, "", "", time.Time{}),
		*plannedTestJob("job-2", sj, "", "", time.Time{}),
		*plannedTestJob("job-3", sj, "", "", time.Time{}),
	}
	secondPlan := buildJobBatchPlan(logger, sj, 3, 3, observed, scheme)

	assert.Empty(t, secondPlan.JobsToCreate, "already observed Jobs must not be created again")
	assert.Equal(t, int64(3), secondPlan.RunningJobCount)
	assert.Empty(t, secondPlan.Conflicts)

	// A duplicate reconcile against the identical informer state must produce
	// the exact same plan.
	thirdPlan := buildJobBatchPlan(logger, sj, 3, 3, observed, scheme)
	assert.Equal(t, secondPlan, thirdPlan)
}

func TestBuildJobBatchPlan_StaleOwnerUIDIsNotAdopted(t *testing.T) {
	sj := newPlanTestScaledJob()
	scheme := planTestScheme()

	staleRunning := plannedTestJob("stale-running", sj, testStaleOwnerUID, "", time.Time{})
	staleFinished := plannedTestJob("stale-finished", sj, testStaleOwnerUID, batchv1.JobComplete, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	plan := buildJobBatchPlan(logf.Log.WithName("test"), sj, 2, 2, []batchv1.Job{*staleRunning, *staleFinished}, scheme)

	// Orphans from the old owner neither consume capacity nor get recycled.
	assert.Equal(t, int64(0), plan.RunningJobCount)
	assert.Empty(t, plan.JobsToRecycle)
	require.Len(t, plan.JobsToCreate, 2, "demand must still be satisfied with fresh Jobs")
	for _, job := range plan.JobsToCreate {
		assert.Equal(t, testScaledJobUID, metav1.GetControllerOf(job).UID)
	}

	reasons := planConflictReasons(plan.Conflicts)
	assert.Equal(t, 2, reasons[PlanConflictOwnerUIDMismatch])
	for _, conflict := range plan.Conflicts {
		assert.Equal(t, PlanConflictOwnerUIDMismatch, conflict.Reason)
		assert.Contains(t, conflict.Message, string(testStaleOwnerUID))
		assert.Contains(t, conflict.Message, string(testScaledJobUID))
	}
}

func TestBuildJobBatchPlan_MissingControllerOwnerConflict(t *testing.T) {
	sj := newPlanTestScaledJob()
	scheme := planTestScheme()

	orphan := unownedTestJob("no-owner", sj)
	plan := buildJobBatchPlan(logf.Log.WithName("test"), sj, 1, 1, []batchv1.Job{*orphan}, scheme)

	assert.Equal(t, int64(0), plan.RunningJobCount)
	require.Len(t, plan.JobsToCreate, 1)
	reasons := planConflictReasons(plan.Conflicts)
	assert.Equal(t, 1, reasons[PlanConflictMissingControllerOwner])
	assert.Equal(t, "no-owner", plan.Conflicts[0].JobName)
}

func TestBuildJobBatchPlan_RecycleOverflowByHistoryLimit(t *testing.T) {
	sj := newPlanTestScaledJob()
	scheme := planTestScheme()

	observed := []batchv1.Job{
		*plannedTestJob("running", sj, "", "", time.Time{}),
		*plannedTestJob("complete-old", sj, "", batchv1.JobComplete, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		*plannedTestJob("complete-mid", sj, "", batchv1.JobComplete, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)),
		*plannedTestJob("complete-new", sj, "", batchv1.JobComplete, time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)),
		*plannedTestJob("failed-old", sj, "", batchv1.JobFailed, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		*plannedTestJob("failed-mid", sj, "", batchv1.JobFailed, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)),
		*plannedTestJob("failed-new", sj, "", batchv1.JobFailed, time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)),
	}

	plan := buildJobBatchPlan(logf.Log.WithName("test"), sj, 0, 0, observed, scheme)

	assert.Equal(t, int64(1), plan.RunningJobCount)
	assert.Empty(t, plan.JobsToCreate)
	require.Len(t, plan.JobsToRecycle, 2, "one oldest completed and one oldest failed Job overflow the limit of 2")
	recycledNames := []string{plan.JobsToRecycle[0].Name, plan.JobsToRecycle[1].Name}
	assert.Contains(t, recycledNames, "complete-old")
	assert.Contains(t, recycledNames, "failed-old")
	assert.Empty(t, plan.Conflicts)
}

func TestBuildJobBatchPlan_MaxReplicaCountReached(t *testing.T) {
	sj := newPlanTestScaledJob()
	maxReplicaCount := int32(2)
	sj.Spec.MaxReplicaCount = &maxReplicaCount
	scheme := planTestScheme()

	observed := []batchv1.Job{
		*plannedTestJob("running-1", sj, "", "", time.Time{}),
		*plannedTestJob("running-2", sj, "", "", time.Time{}),
	}

	plan := buildJobBatchPlan(logf.Log.WithName("test"), sj, 5, 0, observed, scheme)

	assert.Empty(t, plan.JobsToCreate)
	assert.Equal(t, int64(2), plan.RunningJobCount)
	reasons := planConflictReasons(plan.Conflicts)
	assert.Equal(t, 1, reasons[PlanConflictMaxReplicaCountReached])
	assert.Contains(t, plan.Conflicts[0].Message, "maxReplicaCount 2")
}

func TestBuildJobBatchPlan_RemainingCapacityClampsCreation(t *testing.T) {
	sj := newPlanTestScaledJob()
	maxReplicaCount := int32(2)
	sj.Spec.MaxReplicaCount = &maxReplicaCount
	scheme := planTestScheme()

	observed := []batchv1.Job{
		*plannedTestJob("running-1", sj, "", "", time.Time{}),
	}

	plan := buildJobBatchPlan(logf.Log.WithName("test"), sj, 5, 5, observed, scheme)

	require.Len(t, plan.JobsToCreate, 1, "only one slot remains until maxReplicaCount")
	assert.Equal(t, int64(1), plan.RunningJobCount)
	assert.Empty(t, plan.Conflicts, "the cap is not reached yet, so no conflict is reported")
}

func TestBuildJobBatchPlan_EffectiveMaxScaleCapsTheBatch(t *testing.T) {
	sj := newPlanTestScaledJob()
	scheme := planTestScheme()

	plan := buildJobBatchPlan(logf.Log.WithName("test"), sj, 5, 1, nil, scheme)

	require.Len(t, plan.JobsToCreate, 1, "the scaling strategy decision caps how many Jobs are added this round")
	assert.Empty(t, plan.Conflicts)
}

func TestBuildJobBatchPlan_NegativeEffectiveMaxScaleCreatesNothing(t *testing.T) {
	sj := newPlanTestScaledJob()
	scheme := planTestScheme()

	plan := buildJobBatchPlan(logf.Log.WithName("test"), sj, 3, -1, nil, scheme)

	assert.Empty(t, plan.JobsToCreate)
	assert.Empty(t, plan.Conflicts)
}

func TestBuildJobBatchPlan_DuplicateJobNames(t *testing.T) {
	sj := newPlanTestScaledJob()
	scheme := planTestScheme()

	observed := []batchv1.Job{
		*plannedTestJob("dup", sj, "", "", time.Time{}),
		*plannedTestJob("dup", sj, "", "", time.Time{}),
	}

	plan := buildJobBatchPlan(logf.Log.WithName("test"), sj, 0, 0, observed, scheme)

	reasons := planConflictReasons(plan.Conflicts)
	assert.Equal(t, 1, reasons[PlanConflictDuplicateJobName])
	assert.Equal(t, "dup", plan.Conflicts[0].JobName)
}

func TestBuildJobBatchPlan_DoesNotMutateScaledJob(t *testing.T) {
	sj := newPlanTestScaledJob()
	before := sj.DeepCopy()
	scheme := planTestScheme()

	_ = buildJobBatchPlan(logf.Log.WithName("test"), sj, 2, 2, nil, scheme)

	assert.Equal(t, before, sj)
	assert.Empty(t, sj.Spec.JobTargetRef.Template.GenerateName, "the planner must not mutate the Job template")
}

func TestPlanJobBatches_ReadsInformerCacheOnly(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	client := mock_client.NewMockClient(ctrl)
	sj := newPlanTestScaledJob()

	// gomock fails the test on any unregistered call, so no Create/Update/Delete
	// may happen while building the plan.
	client.EXPECT().
		List(gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(_ context.Context, list runtime.Object, _ ...runtimeclient.ListOption) {
			jobList, ok := list.(*batchv1.JobList)
			require.True(t, ok)
			jobList.Items = append(jobList.Items, *plannedTestJob("cached-running", sj, "", "", time.Time{}))
		}).
		Return(nil)

	executor := getMockScaleExecutor(client)
	plan, err := executor.PlanJobBatches(ctx, logf.Log.WithName("test"), sj, 2, 2)

	require.NoError(t, err)
	require.NotNil(t, plan)
	assert.Equal(t, int64(1), plan.RunningJobCount)
	require.Len(t, plan.JobsToCreate, 1, "one cached running Job already covers one of the two demanded slots")
	assert.Empty(t, plan.Conflicts)
}

func TestPlanJobBatches_ListErrorIsPropagated(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	client := mock_client.NewMockClient(ctrl)
	listErr := errors.New("informer cache unavailable")
	client.EXPECT().List(gomock.Any(), gomock.Any(), gomock.Any()).Return(listErr)

	executor := getMockScaleExecutor(client)
	plan, err := executor.PlanJobBatches(ctx, logf.Log.WithName("test"), newPlanTestScaledJob(), 1, 1)

	assert.ErrorIs(t, err, listErr)
	assert.Nil(t, plan)
}
