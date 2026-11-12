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
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	kedav1alpha1 "github.com/kedacore/keda/v2/apis/keda/v1alpha1"
	version "github.com/kedacore/keda/v2/version"
)

const scaledJobNameLabel = "scaledjob.keda.sh/name"

// PlanConflictReason explains why an observed Job cannot be reconciled by the
// batch plan. Conflicts are never resolved silently, the planner only records
// the explanation and leaves the conflicting object untouched.
type PlanConflictReason string

const (
	// PlanConflictOwnerUIDMismatch means a Job carries the ScaledJob name label
	// but its controller owner has a different UID, i.e. it was created by a
	// previous ScaledJob instance that shared the same name. The Job is neither
	// counted towards capacity nor recycled, so an old owner UID can never
	// trigger duplicate Job creation.
	PlanConflictOwnerUIDMismatch PlanConflictReason = "OwnerUIDMismatch"
	// PlanConflictMissingControllerOwner means a labeled Job has no controller
	// owner reference and therefore cannot be owned by the current ScaledJob.
	PlanConflictMissingControllerOwner PlanConflictReason = "MissingControllerOwner"
	// PlanConflictDuplicateJobName means the informer cache currently reports
	// multiple Jobs with the same name. The duplicate entries are reported
	// instead of being acted upon.
	PlanConflictDuplicateJobName PlanConflictReason = "DuplicateJobName"
	// PlanConflictMaxReplicaCountReached means creation is suppressed because
	// Jobs owned by the current ScaledJob already reach maxReplicaCount.
	PlanConflictMaxReplicaCountReached PlanConflictReason = "MaxReplicaCountReached"
)

// PlanConflict describes a single discrepancy between the observed cluster
// state and the desired ScaledJob state.
type PlanConflict struct {
	Reason  PlanConflictReason
	JobName string
	Message string
}

// JobBatchPlan is the idempotent, read-only outcome of planning one ScaledJob
// reconcile round. It is a pure function of the ScaledJob spec and the Jobs
// observed in the informer cache: identical inputs always produce an identical
// plan, therefore repeated reconciles cannot create duplicate Jobs.
type JobBatchPlan struct {
	// ScaledJobUID is the UID of the ScaledJob that owns this plan.
	ScaledJobUID types.UID
	// QueueLength is the total number of Jobs requested by the queue length metric.
	QueueLength int64
	// EffectiveMaxScale is the maximum number of additional Jobs the scaling
	// strategy allows to be created this round. A value <= 0 suppresses creation.
	EffectiveMaxScale int64
	// MaxReplicaCount is the effective maxReplicaCount from the ScaledJob spec.
	MaxReplicaCount int64
	// RunningJobCount is the number of not-finished Jobs owned by the current
	// ScaledJob UID observed in the informer cache.
	RunningJobCount int64
	// JobsToCreate are the Job objects that should be created to satisfy the
	// queue length while respecting maxReplicaCount.
	JobsToCreate []*batchv1.Job
	// JobsToRecycle are finished Jobs (oldest first) that exceed the configured
	// successful/failed jobs history limits.
	JobsToRecycle []batchv1.Job
	// Conflicts explains every observed object that the planner deliberately
	// did not manage (stale owner UID, missing owner, duplicate names, etc.).
	Conflicts []PlanConflict
}

// jobBatchReader is the only informer-backed surface the planner depends on.
// It exposes read operations exclusively, so building a plan can never mutate
// cluster state. The controller-runtime cached client satisfies this interface.
type jobBatchReader interface {
	List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error
}

// Compile-time guarantee that the controller-runtime client (the informer-backed
// cached client in production) only has to satisfy the read-only planner surface.
var _ jobBatchReader = (client.Client)(nil)

// PlanJobBatches computes the idempotent create/recycle batch plan for a
// ScaledJob based on the queue length, maxReplicaCount, history limits and the
// Job template.
//
// The method is strictly read-only: it lists Jobs through the informer-backed
// client and never creates, updates or deletes anything. It also never mutates
// the passed ScaledJob. Calling it repeatedly with the same observed state
// yields the exact same plan, so duplicate reconciles cannot create duplicate
// Jobs. Jobs whose controller owner UID differs from the current ScaledJob UID
// are reported as conflicts instead of being counted or recycled.
func (e *scaleExecutor) PlanJobBatches(ctx context.Context, logger logr.Logger, scaledJob *kedav1alpha1.ScaledJob, queueLength, effectiveMaxScale int64) (*JobBatchPlan, error) {
	jobs := &batchv1.JobList{}
	err := e.client.List(ctx, jobs,
		client.InNamespace(scaledJob.GetNamespace()),
		client.MatchingLabels(map[string]string{scaledJobNameLabel: scaledJob.GetName()}),
	)
	if err != nil {
		return nil, err
	}
	return buildJobBatchPlan(logger, scaledJob, queueLength, effectiveMaxScale, jobs.Items, e.reconcilerScheme), nil
}

// buildJobBatchPlan is the pure planning function. It does not perform any I/O
// and does not mutate the ScaledJob or the observed Jobs; all decisions are
// derived from the arguments, which makes the plan deterministic and the
// reconcile idempotent.
func buildJobBatchPlan(logger logr.Logger, scaledJob *kedav1alpha1.ScaledJob, queueLength, effectiveMaxScale int64, observedJobs []batchv1.Job, scheme *runtime.Scheme) *JobBatchPlan {
	plan := &JobBatchPlan{
		ScaledJobUID:      scaledJob.UID,
		QueueLength:       queueLength,
		EffectiveMaxScale: effectiveMaxScale,
		MaxReplicaCount:   scaledJob.MaxReplicaCount(),
		JobsToCreate:      []*batchv1.Job{},
		JobsToRecycle:     []batchv1.Job{},
		Conflicts:         []PlanConflict{},
	}

	completedJobs, failedJobs := classifyObservedJobs(scaledJob, observedJobs, plan)
	plan.Conflicts = append(plan.Conflicts, findDuplicateJobNames(observedJobs)...)
	plan.JobsToRecycle = append(plan.JobsToRecycle, jobsBeyondHistoryLimit(completedJobs, successfulJobsHistoryLimitOf(scaledJob))...)
	plan.JobsToRecycle = append(plan.JobsToRecycle, jobsBeyondHistoryLimit(failedJobs, failedJobsHistoryLimitOf(scaledJob))...)

	desiredCreation := planCreationCount(plan)
	plan.JobsToCreate = buildPlannedJobs(logger, scaledJob, desiredCreation, scheme)

	sortPlanConflicts(plan.Conflicts)
	return plan
}

// classifyObservedJobs partitions the observed Jobs into owned finished Jobs
// (completed/failed, candidates for history-limit recycling) and counts the
// owned running Jobs. Jobs not owned by the current ScaledJob UID are recorded
// as conflicts and excluded from every bucket.
func classifyObservedJobs(scaledJob *kedav1alpha1.ScaledJob, observedJobs []batchv1.Job, plan *JobBatchPlan) (completedJobs, failedJobs []batchv1.Job) {
	for i := range observedJobs {
		job := &observedJobs[i]
		// The list selector already filters by this label, the check is kept
		// defensive in case callers pass unfiltered informer objects.
		if job.Labels[scaledJobNameLabel] != scaledJob.GetName() {
			continue
		}

		owner := metav1.GetControllerOf(job)
		switch {
		case owner == nil:
			plan.Conflicts = append(plan.Conflicts, PlanConflict{
				Reason:  PlanConflictMissingControllerOwner,
				JobName: job.Name,
				Message: fmt.Sprintf("job %q carries the %q label but has no controller owner reference, it is not managed by ScaledJob %s/%s (UID %s) and is left untouched",
					job.Name, scaledJobNameLabel, scaledJob.GetNamespace(), scaledJob.GetName(), scaledJob.UID),
			})
		case owner.UID != scaledJob.UID:
			plan.Conflicts = append(plan.Conflicts, PlanConflict{
				Reason:  PlanConflictOwnerUIDMismatch,
				JobName: job.Name,
				Message: fmt.Sprintf("job %q is owned by UID %s but the current ScaledJob %s/%s has UID %s, it is treated as an orphan from an old owner and is neither counted nor recycled",
					job.Name, owner.UID, scaledJob.GetNamespace(), scaledJob.GetName(), scaledJob.UID),
			})
		default:
			switch getFinishedJobConditionType(job) {
			case batchv1.JobComplete:
				completedJobs = append(completedJobs, *job)
			case batchv1.JobFailed:
				failedJobs = append(failedJobs, *job)
			default:
				plan.RunningJobCount++
			}
		}
	}
	return completedJobs, failedJobs
}

// findDuplicateJobNames reports informer entries that share the same Job name.
// The output is sorted by Job name so the plan stays deterministic.
func findDuplicateJobNames(observedJobs []batchv1.Job) []PlanConflict {
	nameCount := make(map[string]int, len(observedJobs))
	for _, job := range observedJobs {
		if job.Name != "" {
			nameCount[job.Name]++
		}
	}

	duplicateNames := make([]string, 0, len(nameCount))
	for name, count := range nameCount {
		if count > 1 {
			duplicateNames = append(duplicateNames, name)
		}
	}
	sort.Strings(duplicateNames)

	conflicts := make([]PlanConflict, 0, len(duplicateNames))
	for _, name := range duplicateNames {
		conflicts = append(conflicts, PlanConflict{
			Reason:  PlanConflictDuplicateJobName,
			JobName: name,
			Message: fmt.Sprintf("informer cache reports %d jobs with the same name %q, the duplicates are left untouched until the cache converges",
				nameCount[name], name),
		})
	}
	return conflicts
}

// jobsBeyondHistoryLimit returns the finished Jobs that overflow the configured
// history limit, ordered from the oldest completion time first, mirroring the
// existing cleanUp semantics.
func jobsBeyondHistoryLimit(jobs []batchv1.Job, historyLimit int32) []batchv1.Job {
	if len(jobs) <= int(historyLimit) {
		return nil
	}
	sort.Sort(byCompletedTime(jobs))
	return jobs[:len(jobs)-int(historyLimit)]
}

// planCreationCount computes how many additional Jobs are required. The queue
// length is the total desired count, so the Jobs already observed as running in
// the informer cache are subtracted first; the result is then bounded by the
// remaining maxReplicaCount capacity and by the scaling strategy decision. It
// is zero whenever the observed owned Jobs already satisfy the demand, which
// makes duplicate reconciles idempotent even if the caller repeats the same
// inputs.
func planCreationCount(plan *JobBatchPlan) int64 {
	desiredTotal := min(max(0, plan.QueueLength), plan.MaxReplicaCount)
	additional := max(0, desiredTotal-plan.RunningJobCount)

	if plan.EffectiveMaxScale <= 0 {
		additional = 0
	} else if additional > plan.EffectiveMaxScale {
		additional = plan.EffectiveMaxScale
	}

	if plan.QueueLength > 0 && additional == 0 && plan.RunningJobCount >= plan.MaxReplicaCount {
		plan.Conflicts = append(plan.Conflicts, PlanConflict{
			Reason: PlanConflictMaxReplicaCountReached,
			Message: fmt.Sprintf("queue length %d requests more jobs but %d running jobs already reach maxReplicaCount %d, job creation is suppressed",
				plan.QueueLength, plan.RunningJobCount, plan.MaxReplicaCount),
		})
	}
	return additional
}

// buildPlannedJobs materializes the Job objects to create from the ScaledJob
// template. Every Job is built from deep copies, the ScaledJob itself is never
// mutated, and the controller owner reference always points at the current
// ScaledJob UID.
func buildPlannedJobs(logger logr.Logger, scaledJob *kedav1alpha1.ScaledJob, count int64, scheme *runtime.Scheme) []*batchv1.Job {
	if count <= 0 {
		return []*batchv1.Job{}
	}

	labels := plannedJobLabels(scaledJob)
	annotations := plannedJobAnnotations(scaledJob)
	jobs := make([]*batchv1.Job, 0, count)
	for range count {
		job := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: scaledJob.GetName() + "-",
				Namespace:    scaledJob.GetNamespace(),
				Labels:       maps.Clone(labels),
				Annotations:  maps.Clone(annotations),
			},
			Spec: *scaledJob.Spec.JobTargetRef.DeepCopy(),
		}

		// Job doesn't allow RestartPolicyAlways, it seems like this value is set by the client as a default one,
		// we should set this property to allowed value in that case
		if job.Spec.Template.Spec.RestartPolicy == "" {
			logger.V(1).Info("Job RestartPolicy is not set, setting it to 'OnFailure', to avoid setting it to the client's default value 'Always'")
			job.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
		}

		if err := controllerutil.SetControllerReference(scaledJob, job, scheme); err != nil {
			logger.Error(err, "Failed to set ScaledJob as the owner of the planned Job")
		}
		jobs = append(jobs, job)
	}
	return jobs
}

// plannedJobLabels builds the labels applied to every planned Job, honoring the
// optional excluded-labels annotation.
func plannedJobLabels(scaledJob *kedav1alpha1.ScaledJob) map[string]string {
	labels := map[string]string{
		"app.kubernetes.io/name":       scaledJob.GetName(),
		"app.kubernetes.io/version":    version.Version,
		"app.kubernetes.io/part-of":    scaledJob.GetName(),
		"app.kubernetes.io/managed-by": "keda-operator",
		scaledJobNameLabel:             scaledJob.GetName(),
	}

	excludedLabels := map[string]struct{}{}
	if raw, ok := scaledJob.Annotations[kedav1alpha1.ScaledJobExcludedLabelsAnnotation]; ok {
		for excludedLabel := range strings.SplitSeq(raw, ",") {
			excludedLabels[excludedLabel] = struct{}{}
		}
	}

	for key, value := range scaledJob.Labels {
		if _, ok := excludedLabels[key]; ok {
			continue
		}
		labels[key] = value
	}
	return labels
}

// plannedJobAnnotations builds the annotations applied to every planned Job.
func plannedJobAnnotations(scaledJob *kedav1alpha1.ScaledJob) map[string]string {
	annotations := map[string]string{
		"scaledjob.keda.sh/generation": strconv.FormatInt(scaledJob.Generation, 10),
	}
	maps.Copy(annotations, scaledJob.Annotations)
	return annotations
}

func successfulJobsHistoryLimitOf(scaledJob *kedav1alpha1.ScaledJob) int32 {
	if scaledJob.Spec.SuccessfulJobsHistoryLimit != nil {
		return *scaledJob.Spec.SuccessfulJobsHistoryLimit
	}
	return defaultSuccessfulJobsHistoryLimit
}

func failedJobsHistoryLimitOf(scaledJob *kedav1alpha1.ScaledJob) int32 {
	if scaledJob.Spec.FailedJobsHistoryLimit != nil {
		return *scaledJob.Spec.FailedJobsHistoryLimit
	}
	return defaultFailedJobsHistoryLimit
}

func sortPlanConflicts(conflicts []PlanConflict) {
	sort.SliceStable(conflicts, func(i, j int) bool {
		if conflicts[i].JobName != conflicts[j].JobName {
			return conflicts[i].JobName < conflicts[j].JobName
		}
		return conflicts[i].Reason < conflicts[j].Reason
	})
}
