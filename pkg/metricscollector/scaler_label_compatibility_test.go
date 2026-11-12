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

package metricscollector

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/kedacore/keda/v2/pkg/scalers/scalersconfig"
)

func sampleScaledObjectInput() ScalerLabelInput {
	return ScalerLabelInput{
		ScalerType:     "prometheus",
		Namespace:      "production",
		Name:           "worker-scaler",
		TriggerIndex:   2,
		IsScaledObject: true,
		TriggerName:    "queue-length",
	}
}

func labelsAsMap(labels []StableScalerLabel) map[string]string {
	result := make(map[string]string, len(labels))
	for _, label := range labels {
		result[label.Key] = label.Value
	}
	return result
}

func TestBuildStableScalerLabels_ScaledObjectConvention(t *testing.T) {
	labels, findings := BuildStableScalerLabels(sampleScaledObjectInput())

	assert.Empty(t, findings)
	require.Len(t, labels, 4)

	// labels must be sorted by key so the set is deterministic
	for i := 1; i < len(labels); i++ {
		assert.Less(t, labels[i-1].Key, labels[i].Key)
	}

	values := labelsAsMap(labels)
	assert.Equal(t, "prometheus", values["scaler"])
	assert.Equal(t, "production", values["namespace"])
	assert.Equal(t, "worker-scaler", values["scaledObject"])
	assert.Equal(t, "2", values["scalerIndex"])
	_, hasJobKey := values["scaledJob"]
	assert.False(t, hasJobKey)
	_, hasTriggerIndexKey := values["triggerIndex"]
	assert.False(t, hasTriggerIndexKey)
}

func TestBuildStableScalerLabels_ScaledJobConvention(t *testing.T) {
	input := sampleScaledObjectInput()
	input.IsScaledObject = false

	labels, findings := BuildStableScalerLabels(input)
	assert.Empty(t, findings)

	values := labelsAsMap(labels)
	assert.Equal(t, "worker-scaler", values["scaledJob"])
	assert.Equal(t, "2", values["triggerIndex"])
	_, hasObjectKey := values["scaledObject"]
	assert.False(t, hasObjectKey)
	_, hasScalerIndexKey := values["scalerIndex"]
	assert.False(t, hasScalerIndexKey)
}

func TestBuildStableScalerLabels_Deterministic(t *testing.T) {
	input := sampleScaledObjectInput()

	first, firstFindings := BuildStableScalerLabels(input)
	second, secondFindings := BuildStableScalerLabels(input)

	assert.Equal(t, first, second)
	assert.Equal(t, firstFindings, secondFindings)
	assert.Equal(t, "scaledobject/production/worker-scaler[prometheus]/2", ScalerTriggerIdentity(input))
}

func TestBuildStableScalerLabels_EmptyAndAbnormalTriggerIsDiagnosable(t *testing.T) {
	input := ScalerLabelInput{IsScaledObject: true, TriggerIndex: -1}

	labels, findings := BuildStableScalerLabels(input)
	values := labelsAsMap(labels)

	// empty values are kept in the set so the label set stays complete
	require.Contains(t, values, "scaler")
	require.Contains(t, values, "namespace")
	require.Contains(t, values, "scaledObject")
	assert.Equal(t, "-1", values["scalerIndex"])

	codes := make(map[LabelFindingCode]LabelFinding)
	for _, finding := range findings {
		codes[finding.Code] = finding
	}
	require.Contains(t, codes, FindingEmptyScalerType)
	require.Contains(t, codes, FindingEmptyNamespace)
	require.Contains(t, codes, FindingEmptyName)
	require.Contains(t, codes, FindingNegativeTriggerIndex)
	assert.Equal(t, LabelFindingSeverityError, codes[FindingNegativeTriggerIndex].Severity)
	assert.Equal(t, LabelFindingSeverityWarning, codes[FindingEmptyScalerType].Severity)

	// every finding keeps the trigger reference for diagnosis
	for _, finding := range findings {
		assert.Equal(t, -1, finding.TriggerIndex)
		assert.NotEmpty(t, finding.Identity)
		assert.NotEmpty(t, finding.Message)
	}
}

func TestNewScalerLabelInput_FromScalerConfig(t *testing.T) {
	config := scalersconfig.ScalerConfig{
		TriggerType:             "kafka",
		ScalableObjectNamespace: "messaging",
		ScalableObjectName:      "kafka-consumer",
		TriggerIndex:            1,
		ScalableObjectType:      "ScaledObject",
		TriggerName:             "lag",
	}
	input := NewScalerLabelInput(config)
	assert.Equal(t, "kafka", input.ScalerType)
	assert.Equal(t, "messaging", input.Namespace)
	assert.Equal(t, "kafka-consumer", input.Name)
	assert.Equal(t, 1, input.TriggerIndex)
	assert.True(t, input.IsScaledObject)
	assert.Equal(t, "lag", input.TriggerName)

	config.ScalableObjectType = "ScaledJob"
	input = NewScalerLabelInput(config)
	assert.False(t, input.IsScaledObject)
}

func TestReport_HighCardinalityThreshold(t *testing.T) {
	inputs := make([]ScalerLabelInput, 0, DefaultHighCardinalityThreshold+5)
	for i := 0; i < DefaultHighCardinalityThreshold+5; i++ {
		inputs = append(inputs, ScalerLabelInput{
			ScalerType:     "prometheus",
			Namespace:      "production",
			Name:           fmt.Sprintf("worker-%d", i),
			TriggerIndex:   0,
			IsScaledObject: true,
		})
	}

	report := NewScalerLabelCompatibilityReport(inputs)
	require.False(t, report.HasErrors())

	var nameCardinality *LabelCardinality
	for i := range report.Cardinality {
		if report.Cardinality[i].Key == scaledObjectLabelKey {
			nameCardinality = &report.Cardinality[i]
		}
	}
	require.NotNil(t, nameCardinality)
	assert.Equal(t, DefaultHighCardinalityThreshold+5, nameCardinality.DistinctValues)
	assert.True(t, nameCardinality.HighCardinality)

	highCardinality := report.FindingsByCode(FindingHighCardinalityLabel)
	require.Len(t, highCardinality, 1)
	assert.Equal(t, scaledObjectLabelKey, highCardinality[0].LabelKey)

	// bounded dimensions must never be flagged as high-cardinality sources
	for _, cardinality := range report.Cardinality {
		if cardinality.Key == scalerTypeLabelKey || cardinality.Key == namespaceLabelKey {
			assert.False(t, cardinality.HighCardinality, "key %s must stay bounded", cardinality.Key)
		}
	}
}

func TestReport_FullyUniqueValuesAreHighCardinalityBelowThreshold(t *testing.T) {
	uniqueInputs := make([]ScalerLabelInput, 0, fullyUniqueSampleSize)
	for i := 0; i < fullyUniqueSampleSize; i++ {
		uniqueInputs = append(uniqueInputs, ScalerLabelInput{
			ScalerType:     "prometheus",
			Namespace:      "production",
			Name:           fmt.Sprintf("worker-%d", i),
			TriggerIndex:   i,
			IsScaledObject: true,
		})
	}
	report := NewScalerLabelCompatibilityReport(uniqueInputs)
	require.NotEmpty(t, report.FindingsByCode(FindingHighCardinalityLabel))

	smallSample := uniqueInputs[:fullyUniqueSampleSize-1]
	report = NewScalerLabelCompatibilityReport(smallSample)
	assert.Empty(t, report.FindingsByCode(FindingHighCardinalityLabel))
}

func TestReport_UnstableLabelValues(t *testing.T) {
	unstableNames := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"10.0.0.1",
		"2001:db8::1",
		"abcdef0123456789abcdef0123456789",
		"1700000000",
		"my-app-7d8f9b6c4-x2v9k",
	}
	for _, name := range unstableNames {
		t.Run(name, func(t *testing.T) {
			input := sampleScaledObjectInput()
			input.Name = name
			report := NewScalerLabelCompatibilityReport([]ScalerLabelInput{input})
			findings := report.FindingsByCode(FindingUnstableLabelValue)
			require.Len(t, findings, 1)
			assert.Equal(t, scaledObjectLabelKey, findings[0].LabelKey)
			assert.Equal(t, name, findings[0].LabelValue)
		})
	}

	t.Run("stable names are not flagged", func(t *testing.T) {
		input := sampleScaledObjectInput()
		report := NewScalerLabelCompatibilityReport([]ScalerLabelInput{input})
		assert.Empty(t, report.FindingsByCode(FindingUnstableLabelValue))
	})

	t.Run("bounded dimensions are not inspected", func(t *testing.T) {
		input := sampleScaledObjectInput()
		input.ScalerType = "abcdef0123456789abcdef0123456789"
		report := NewScalerLabelCompatibilityReport([]ScalerLabelInput{input})
		assert.Empty(t, report.FindingsByCode(FindingUnstableLabelValue))
	})
}

func TestReport_DuplicateTrigger(t *testing.T) {
	input := sampleScaledObjectInput()
	report := NewScalerLabelCompatibilityReport([]ScalerLabelInput{input, input})

	// every duplicate occurrence is flagged so each abnormal trigger is diagnosable
	findings := report.FindingsByCode(FindingDuplicateTrigger)
	require.Len(t, findings, 2)
	for _, finding := range findings {
		assert.Equal(t, LabelFindingSeverityError, finding.Severity)
		assert.Equal(t, input.TriggerIndex, finding.TriggerIndex)
		assert.Equal(t, ScalerTriggerIdentity(input), finding.Identity)
	}
	assert.True(t, report.HasErrors())
}

func TestReport_InconsistentIndexLabelKey(t *testing.T) {
	scaledObject := sampleScaledObjectInput()
	scaledJob := sampleScaledObjectInput()
	scaledJob.IsScaledObject = false

	mixed := NewScalerLabelCompatibilityReport([]ScalerLabelInput{scaledObject, scaledJob})
	findings := mixed.FindingsByCode(FindingInconsistentIndexLabelKey)
	require.Len(t, findings, 1)
	assert.Equal(t, LabelFindingSeverityWarning, findings[0].Severity)

	singleKind := NewScalerLabelCompatibilityReport([]ScalerLabelInput{scaledObject})
	assert.Empty(t, singleKind.FindingsByCode(FindingInconsistentIndexLabelKey))
}

func TestValidateScalerLabelKey(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		wantCodes []LabelFindingCode
		wantError bool
	}{
		{name: "valid key", key: "team", wantCodes: nil},
		{name: "prometheus metric name label", key: "__name__", wantCodes: []LabelFindingCode{FindingReservedLabelKey}, wantError: true},
		{name: "double underscore prefix", key: "__internal", wantCodes: []LabelFindingCode{FindingReservedLabelKey}, wantError: true},
		{name: "invalid characters", key: "bad-key!", wantCodes: []LabelFindingCode{FindingInvalidLabelKey}},
		{name: "occupied keda key", key: "namespace", wantCodes: []LabelFindingCode{FindingOccupiedLabelKey}, wantError: true},
		{name: "empty key", key: "", wantCodes: []LabelFindingCode{FindingInvalidLabelKey}, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ValidateScalerLabelKey(tt.key)
			codes := make(map[LabelFindingCode]bool)
			for _, finding := range findings {
				codes[finding.Code] = true
				assert.Equal(t, -1, finding.TriggerIndex)
			}
			for _, code := range tt.wantCodes {
				assert.True(t, codes[code], "expected finding %s for key %q", code, tt.key)
			}
			if tt.wantError {
				assert.True(t, containsErrorSeverity(findings))
			}
		})
	}
}

func containsErrorSeverity(findings []LabelFinding) bool {
	for _, finding := range findings {
		if finding.Severity == LabelFindingSeverityError {
			return true
		}
	}
	return false
}

func TestReport_ExtraLabelPrometheusCollisions(t *testing.T) {
	options := LabelReportOptions{
		ExtraLabels: []string{"a.b", "a_b", "trigger-name"},
	}
	report := NewScalerLabelCompatibilityReportWithOptions(nil, options)

	collisions := report.FindingsByCode(FindingPrometheusKeyCollision)
	require.Len(t, collisions, 2)
	for _, finding := range collisions {
		assert.Equal(t, LabelFindingSeverityError, finding.Severity)
	}

	// "a.b" and "a_b" sanitize to the same Prometheus label name, and
	// "trigger-name" sanitizes to the occupied "trigger_name" label
	assert.Equal(t, "a_b", prometheusSanitizeKey("a.b"))
	assert.Equal(t, "_1abc", prometheusSanitizeKey("1abc"))
	assert.Equal(t, "trigger_name", prometheusSanitizeKey("trigger-name"))
}

func TestReport_EmptyBatch(t *testing.T) {
	report := NewScalerLabelCompatibilityReport(nil)

	assert.NotPanics(t, func() {
		_ = NewScalerLabelCompatibilityReportWithOptions([]ScalerLabelInput{}, LabelReportOptions{})
	})
	assert.Empty(t, report.Triggers)
	assert.Empty(t, report.Findings)
	assert.Empty(t, report.Cardinality)
	assert.False(t, report.HasErrors())
	assert.Contains(t, report.String(), "triggers inspected: 0")
}

func TestReport_StringAndFindingsByCode(t *testing.T) {
	first := sampleScaledObjectInput()
	second := sampleScaledObjectInput()
	second.Namespace = ""
	second.TriggerIndex = 3

	report := NewScalerLabelCompatibilityReport([]ScalerLabelInput{first, second})
	rendered := report.String()

	assert.Contains(t, rendered, ScalerTriggerIdentity(first))
	assert.Contains(t, rendered, ScalerTriggerIdentity(second))
	assert.Contains(t, rendered, "scaler=")
	assert.Contains(t, rendered, string(FindingEmptyNamespace))
	assert.Contains(t, rendered, "cardinality")

	findings := report.FindingsByCode(FindingEmptyNamespace)
	require.Len(t, findings, 1)
	assert.Equal(t, second.TriggerIndex, findings[0].TriggerIndex)
	assert.Empty(t, report.FindingsByCode(FindingEmptyScalerType))
	assert.False(t, report.HasErrors())

	// rendering is deterministic for identical inputs
	assert.Equal(t, rendered, NewScalerLabelCompatibilityReport([]ScalerLabelInput{first, second}).String())
}

func TestCompatibilityReportEmitsNoMetrics(t *testing.T) {
	resetTestOtel(true)

	// drain the build.info gauge that NewOtelMetrics records on startup
	drain := metricdata.ResourceMetrics{}
	require.NoError(t, testReader.Collect(context.Background(), &drain))

	abnormal := ScalerLabelInput{TriggerIndex: -2}
	normal := sampleScaledObjectInput()
	report := NewScalerLabelCompatibilityReportWithOptions(
		[]ScalerLabelInput{abnormal, normal},
		LabelReportOptions{ExtraLabels: []string{"__reserved", "a.b", "a_b"}},
	)
	require.NotEmpty(t, report.Triggers)
	require.True(t, report.HasErrors())

	after := metricdata.ResourceMetrics{}
	require.NoError(t, testReader.Collect(context.Background(), &after))

	// building the report must not create any data points: it is a pure,
	// emission-free analysis and must not touch any instrument
	assert.Empty(t, countMetricDataPoints(&after))
}

func countMetricDataPoints(rm *metricdata.ResourceMetrics) map[string]int {
	counts := map[string]int{}
	for _, scopeMetrics := range rm.ScopeMetrics {
		for _, m := range scopeMetrics.Metrics {
			counts[m.Name] += dataPointCount(m.Data)
		}
	}
	return counts
}

func dataPointCount(data metricdata.Aggregation) int {
	switch d := data.(type) {
	case metricdata.Gauge[int64]:
		return len(d.DataPoints)
	case metricdata.Gauge[float64]:
		return len(d.DataPoints)
	case metricdata.Sum[int64]:
		return len(d.DataPoints)
	case metricdata.Sum[float64]:
		return len(d.DataPoints)
	case metricdata.Histogram[float64]:
		return len(d.DataPoints)
	case metricdata.Histogram[int64]:
		return len(d.DataPoints)
	case metricdata.ExponentialHistogram[float64]:
		return len(d.DataPoints)
	case metricdata.ExponentialHistogram[int64]:
		return len(d.DataPoints)
	default:
		return 0
	}
}
