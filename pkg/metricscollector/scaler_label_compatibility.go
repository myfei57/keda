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
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kedacore/keda/v2/pkg/scalers/scalersconfig"
)

// Label keys KEDA attaches to scaler metrics today. They mirror the keys used
// by getScalerMeasurementOption in opentelemetry.go and metricLabels in
// prommetrics.go so that the report describes the labels that are actually
// emitted, without emitting anything itself.
const (
	scalerTypeLabelKey   = "scaler"
	namespaceLabelKey    = "namespace"
	scaledObjectLabelKey = "scaledObject"
	scaledJobLabelKey    = "scaledJob"
	scalerIndexLabelKey  = "scalerIndex"
	triggerIndexLabelKey = "triggerIndex"

	scaledObjectKind = "ScaledObject"

	// DefaultHighCardinalityThreshold is the default number of distinct values
	// a label key has to reach across the inspected triggers before it is
	// reported as a high-cardinality source.
	DefaultHighCardinalityThreshold = 100

	// fullyUniqueSampleSize is the minimum sample size at which a label whose
	// value is unique on every inspected trigger is treated as a
	// high-cardinality source even below DefaultHighCardinalityThreshold.
	fullyUniqueSampleSize = 10
)

// LabelFindingSeverity classifies the operational impact of a LabelFinding.
type LabelFindingSeverity string

const (
	// LabelFindingSeverityError marks a finding that makes the label set
	// invalid or unsafe to attach (reserved words, collisions, abnormal input).
	LabelFindingSeverityError LabelFindingSeverity = "error"
	// LabelFindingSeverityWarning marks a finding that still emits but can
	// cause cardinality or compatibility problems.
	LabelFindingSeverityWarning LabelFindingSeverity = "warning"
)

// LabelFindingCode is the stable, machine-readable identifier of a finding.
type LabelFindingCode string

const (
	// FindingEmptyScalerType reports a trigger without a scaler type.
	FindingEmptyScalerType LabelFindingCode = "EmptyScalerType"
	// FindingEmptyNamespace reports a trigger without a namespace.
	FindingEmptyNamespace LabelFindingCode = "EmptyNamespace"
	// FindingEmptyName reports a trigger without a scalable resource name.
	FindingEmptyName LabelFindingCode = "EmptyName"
	// FindingNegativeTriggerIndex reports a trigger index below zero.
	FindingNegativeTriggerIndex LabelFindingCode = "NegativeTriggerIndex"
	// FindingReservedLabelKey reports a Prometheus reserved label key
	// ("__name__" or any key prefixed with "__").
	FindingReservedLabelKey LabelFindingCode = "ReservedLabelKey"
	// FindingInvalidLabelKey reports a key that is not a valid Prometheus
	// label name and would be rewritten by the OTel Prometheus exporter.
	FindingInvalidLabelKey LabelFindingCode = "InvalidLabelKey"
	// FindingOccupiedLabelKey reports a candidate key already used by a KEDA
	// metric label with different semantics.
	FindingOccupiedLabelKey LabelFindingCode = "OccupiedLabelKey"
	// FindingPrometheusKeyCollision reports distinct OTel keys that sanitize
	// to the same Prometheus label name.
	FindingPrometheusKeyCollision LabelFindingCode = "PrometheusKeyCollision"
	// FindingHighCardinalityLabel reports a label key whose value set grows
	// with the number of triggers instead of staying bounded.
	FindingHighCardinalityLabel LabelFindingCode = "HighCardinalityLabel"
	// FindingUnstableLabelValue reports a free-form label value that looks
	// generated (UUID, hash, IP address, timestamp, random pod suffix).
	FindingUnstableLabelValue LabelFindingCode = "UnstableLabelValue"
	// FindingDuplicateTrigger reports two triggers producing the same label
	// set and therefore collapsing onto one time series.
	FindingDuplicateTrigger LabelFindingCode = "DuplicateTrigger"
	// FindingInconsistentIndexLabelKey reports that the trigger index is
	// emitted as "scalerIndex" for ScaledObjects but "triggerIndex" for
	// ScaledJobs, which breaks label-based joins across resource kinds.
	FindingInconsistentIndexLabelKey LabelFindingCode = "InconsistentIndexLabelKey"
)

// ScalerLabelInput is the emission-free subset of a scaler trigger required to
// build and validate the stable scaler metric label set. It covers the four
// identifying dimensions: scaler type, namespace, scalable resource name and
// trigger index.
type ScalerLabelInput struct {
	// ScalerType is the trigger type / scaler name, e.g. "prometheus".
	ScalerType string
	// Namespace of the owning ScaledObject/ScaledJob.
	Namespace string
	// Name of the owning ScaledObject/ScaledJob.
	Name string
	// TriggerIndex is the zero-based position of the trigger in spec.triggers.
	TriggerIndex int
	// IsScaledObject selects the ScaledObject (true) or ScaledJob (false)
	// label naming convention used by KEDA today.
	IsScaledObject bool
	// TriggerName is optional and only used to make findings diagnosable.
	TriggerName string
}

// StableScalerLabel is one normalized key/value pair of a trigger's label set.
type StableScalerLabel struct {
	// Key is the label key using KEDA's existing naming convention.
	Key string
	// Value is the stringified label value. Empty values are kept so that
	// the set stays complete; empty inputs are reported as findings instead.
	Value string
}

// LabelFinding describes a single compatibility or cardinality problem.
type LabelFinding struct {
	// Severity classifies the operational impact of the finding.
	Severity LabelFindingSeverity
	// Code is the stable machine-readable identifier of the finding.
	Code LabelFindingCode
	// TriggerIndex references the offending trigger, or -1 for aggregate
	// findings that are not tied to a single trigger.
	TriggerIndex int
	// TriggerName carries the user-defined trigger name when available.
	TriggerName string
	// Identity is the stable "kind/namespace/name[type]/index" reference of
	// the trigger, empty for aggregate findings.
	Identity string
	// LabelKey is the affected label key, empty for trigger-level findings.
	LabelKey string
	// LabelValue is the offending label value when the finding is value-based.
	LabelValue string
	// Message is a human-readable explanation of the finding.
	Message string
}

// ScalerTriggerReport is the per-trigger section of a compatibility report.
type ScalerTriggerReport struct {
	// Trigger is the input the section was built from.
	Trigger ScalerLabelInput
	// Identity is the stable reference of the trigger.
	Identity string
	// Labels is the deterministic label set sorted by key.
	Labels []StableScalerLabel
	// Findings are the findings tied to this trigger.
	Findings []LabelFinding
}

// LabelCardinality summarizes the distinct-value growth of one label key
// across all inspected triggers.
type LabelCardinality struct {
	// Key is the label key.
	Key string
	// TriggerCount is the number of inspected triggers carrying the key.
	TriggerCount int
	// DistinctValues is the number of distinct non-empty values observed.
	DistinctValues int
	// HighCardinality is true when the key is a high-cardinality source.
	HighCardinality bool
}

// ScalerLabelCompatibilityReport is an emission-free compatibility analysis
// of the OpenTelemetry scaler metric labels. It never creates instruments or
// records measurements and it does not change any existing metric name.
type ScalerLabelCompatibilityReport struct {
	// Triggers holds one section per inspected trigger, in input order.
	Triggers []ScalerTriggerReport
	// Cardinality holds the per-key distinct-value summary sorted by key.
	Cardinality []LabelCardinality
	// Findings holds cross-trigger and candidate-key findings in a
	// deterministic order.
	Findings []LabelFinding
}

// LabelReportOptions customizes a compatibility report.
type LabelReportOptions struct {
	// HighCardinalityThreshold overrides DefaultHighCardinalityThreshold when
	// positive.
	HighCardinalityThreshold int
	// ExtraLabels are additional candidate label keys a caller considers
	// attaching. They are validated for reserved words, Prometheus syntax and
	// collisions without becoming part of the emitted label set.
	ExtraLabels []string
}

var (
	promLabelNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	uuidPattern          = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexHashPattern       = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	numericIDPattern     = regexp.MustCompile(`^[0-9]{10,}$`)
	randomSuffixPattern  = regexp.MustCompile(`-([a-z0-9]{5,10})$`)

	// occupiedScalerLabelKeys lists label keys already used by a KEDA metric.
	// Reusing them with different semantics would silently overwrite the
	// existing dimension.
	occupiedScalerLabelKeys = map[string]struct{}{
		"namespace":        {},
		"metric":           {},
		"scaledObject":     {},
		"scaledJob":        {},
		"scaler":           {},
		"scalerIndex":      {},
		"triggerIndex":     {},
		"type":             {},
		"scaled_resource":  {},
		"trigger_name":     {},
		"metric_name":      {},
		"status_code":      {},
		"scaledResource":   {},
		"triggerName":      {},
		"metricName":       {},
		"resourceType":     {},
		"ignoreNullValues": {},
		"version":          {},
		"git_commit":       {},
		"goversion":        {},
		"goos":             {},
		"goarch":           {},
		"cloudEventSource": {},
		"eventsink":        {},
		"state":            {},
	}
)

// NewScalerLabelInput converts a ScalerConfig into the emission-free label
// input. The four identifying dimensions are taken straight from the fields
// populated while building the scaler.
func NewScalerLabelInput(config scalersconfig.ScalerConfig) ScalerLabelInput {
	return ScalerLabelInput{
		ScalerType:     config.TriggerType,
		Namespace:      config.ScalableObjectNamespace,
		Name:           config.ScalableObjectName,
		TriggerIndex:   config.TriggerIndex,
		IsScaledObject: config.ScalableObjectType == scaledObjectKind,
		TriggerName:    config.TriggerName,
	}
}

// ScalerTriggerIdentity returns the stable "kind/namespace/name[type]/index"
// reference of a trigger. Empty fields remain visible (e.g. "//[-1]") so
// abnormal inputs stay diagnosable.
func ScalerTriggerIdentity(input ScalerLabelInput) string {
	kind := "scaledjob"
	if input.IsScaledObject {
		kind = "scaledobject"
	}
	return fmt.Sprintf("%s/%s/%s[%s]/%d", kind, input.Namespace, input.Name, input.ScalerType, input.TriggerIndex)
}

// BuildStableScalerLabels builds the deterministic label set of one trigger
// from its scaler type, namespace, name and trigger index, using the same
// label keys KEDA emits today. The set is sorted by key and never panics on
// empty or abnormal input; problems are returned as findings. No metric is
// emitted and no existing metric name is touched.
func BuildStableScalerLabels(input ScalerLabelInput) ([]StableScalerLabel, []LabelFinding) {
	resourceKey, indexKey := scaledJobLabelKey, triggerIndexLabelKey
	if input.IsScaledObject {
		resourceKey, indexKey = scaledObjectLabelKey, scalerIndexLabelKey
	}

	labels := []StableScalerLabel{
		{Key: scalerTypeLabelKey, Value: input.ScalerType},
		{Key: namespaceLabelKey, Value: input.Namespace},
		{Key: resourceKey, Value: input.Name},
		{Key: indexKey, Value: strconv.Itoa(input.TriggerIndex)},
	}
	sort.Slice(labels, func(i, j int) bool {
		return labels[i].Key < labels[j].Key
	})

	return labels, validateScalerLabelInput(input)
}

// NewScalerLabelCompatibilityReport inspects a batch of triggers (for example
// all triggers of one ScaledObject/ScaledJob, or a cluster-wide sample) and
// produces an emission-free compatibility report.
func NewScalerLabelCompatibilityReport(inputs []ScalerLabelInput) *ScalerLabelCompatibilityReport {
	return NewScalerLabelCompatibilityReportWithOptions(inputs, LabelReportOptions{})
}

// NewScalerLabelCompatibilityReportWithOptions is NewScalerLabelCompatibilityReport
// with explicit options.
func NewScalerLabelCompatibilityReportWithOptions(inputs []ScalerLabelInput, options LabelReportOptions) *ScalerLabelCompatibilityReport {
	threshold := options.HighCardinalityThreshold
	if threshold <= 0 {
		threshold = DefaultHighCardinalityThreshold
	}

	report := &ScalerLabelCompatibilityReport{
		Triggers: make([]ScalerTriggerReport, 0, len(inputs)),
	}
	analysis := newLabelAnalysis(threshold)

	for _, input := range inputs {
		analysis.triggerCount++
		report.Triggers = append(report.Triggers, report.buildTriggerSection(input, analysis))
	}
	analysis.detectDuplicateTriggers(report)
	analysis.detectIndexKeyConvention(report)
	analysis.appendCardinality(report)
	report.Findings = append(report.Findings, validateExtraLabelKeys(options.ExtraLabels)...)
	sortFindings(report.Findings)

	return report
}

// HasErrors reports whether the report contains any error-severity finding.
func (r *ScalerLabelCompatibilityReport) HasErrors() bool {
	for _, finding := range r.allFindings() {
		if finding.Severity == LabelFindingSeverityError {
			return true
		}
	}
	return false
}

// FindingsByCode returns the findings (per-trigger and aggregate) matching code.
func (r *ScalerLabelCompatibilityReport) FindingsByCode(code LabelFindingCode) []LabelFinding {
	var matched []LabelFinding
	for _, finding := range r.allFindings() {
		if finding.Code == code {
			matched = append(matched, finding)
		}
	}
	return matched
}

// String renders the report as deterministic, human-readable text.
func (r *ScalerLabelCompatibilityReport) String() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "OpenTelemetry scaler label compatibility report\n")
	fmt.Fprintf(&builder, "triggers inspected: %d\n", len(r.Triggers))

	for _, section := range r.Triggers {
		fmt.Fprintf(&builder, "\ntrigger %s\n", section.Identity)
		if section.Trigger.TriggerName != "" {
			fmt.Fprintf(&builder, "trigger name: %s\n", section.Trigger.TriggerName)
		}
		for _, label := range section.Labels {
			fmt.Fprintf(&builder, "  label %s=%q\n", label.Key, label.Value)
		}
		appendFindingMessages(&builder, section.Findings)
	}

	if len(r.Cardinality) > 0 {
		builder.WriteString("\ncardinality\n")
		for _, cardinality := range r.Cardinality {
			fmt.Fprintf(&builder, "  %s: distinct=%d triggers=%d high-cardinality=%t\n",
				cardinality.Key, cardinality.DistinctValues, cardinality.TriggerCount, cardinality.HighCardinality)
		}
	}

	appendFindingMessages(&builder, r.Findings)
	return builder.String()
}

func (r *ScalerLabelCompatibilityReport) allFindings() []LabelFinding {
	findings := make([]LabelFinding, 0, len(r.Findings))
	findings = append(findings, r.Findings...)
	for _, section := range r.Triggers {
		findings = append(findings, section.Findings...)
	}
	return findings
}

func appendFindingMessages(builder *strings.Builder, findings []LabelFinding) {
	for _, finding := range findings {
		fmt.Fprintf(builder, "  [%s] %s: %s\n", finding.Severity, finding.Code, finding.Message)
	}
}

// labelAnalysis holds the mutable cross-trigger state while a report is built.
type labelAnalysis struct {
	threshold           int
	triggerCount        int
	seenIdentities      map[string]int
	distinctValues      map[string]map[string]struct{}
	keyOrder            []string
	usesScalerIndexKey  bool
	usesTriggerIndexKey bool
}

func newLabelAnalysis(threshold int) *labelAnalysis {
	return &labelAnalysis{
		threshold:      threshold,
		seenIdentities: make(map[string]int),
		distinctValues: make(map[string]map[string]struct{}),
	}
}

func (r *ScalerLabelCompatibilityReport) buildTriggerSection(input ScalerLabelInput, analysis *labelAnalysis) ScalerTriggerReport {
	labels, inputFindings := BuildStableScalerLabels(input)
	identity := ScalerTriggerIdentity(input)
	findings := make([]LabelFinding, 0, len(inputFindings)+2)
	findings = append(findings, inputFindings...)

	for _, label := range labels {
		analysis.trackValue(label.Key, label.Value)
		if reason, unstable := unstableLabelValueReason(label.Key, label.Value); unstable {
			findings = append(findings, newTriggerFinding(
				LabelFindingSeverityWarning, FindingUnstableLabelValue, input, label.Key, label.Value, reason))
		}
	}

	analysis.trackIndexConvention(labels)
	analysis.seenIdentities[identity]++

	return ScalerTriggerReport{
		Trigger:  input,
		Identity: identity,
		Labels:   labels,
		Findings: findings,
	}
}

func (a *labelAnalysis) trackValue(key, value string) {
	values, ok := a.distinctValues[key]
	if !ok {
		values = make(map[string]struct{})
		a.distinctValues[key] = values
		a.keyOrder = append(a.keyOrder, key)
	}
	if value != "" {
		values[value] = struct{}{}
	}
}

func (a *labelAnalysis) trackIndexConvention(labels []StableScalerLabel) {
	for _, label := range labels {
		switch label.Key {
		case scalerIndexLabelKey:
			a.usesScalerIndexKey = true
		case triggerIndexLabelKey:
			a.usesTriggerIndexKey = true
		}
	}
}

func (a *labelAnalysis) detectDuplicateTriggers(report *ScalerLabelCompatibilityReport) {
	for i := range report.Triggers {
		if a.seenIdentities[report.Triggers[i].Identity] < 2 {
			continue
		}
		report.Triggers[i].Findings = append(report.Triggers[i].Findings, newTriggerFinding(
			LabelFindingSeverityError, FindingDuplicateTrigger, report.Triggers[i].Trigger, "", "",
			"another trigger produces the same label set, the time series would be shared or overwritten"))
	}
}

func (a *labelAnalysis) detectIndexKeyConvention(report *ScalerLabelCompatibilityReport) {
	if !a.usesScalerIndexKey || !a.usesTriggerIndexKey {
		return
	}
	report.Findings = append(report.Findings, LabelFinding{
		Severity:     LabelFindingSeverityWarning,
		Code:         FindingInconsistentIndexLabelKey,
		TriggerIndex: -1,
		LabelKey:     scalerIndexLabelKey + "/" + triggerIndexLabelKey,
		Message:      "trigger index is emitted as \"scalerIndex\" for ScaledObjects and \"triggerIndex\" for ScaledJobs, label-based joins across resource kinds will miss series",
	})
}

func (a *labelAnalysis) appendCardinality(report *ScalerLabelCompatibilityReport) {
	sort.Strings(a.keyOrder)
	for _, key := range a.keyOrder {
		distinct := len(a.distinctValues[key])
		cardinality := LabelCardinality{
			Key:             key,
			TriggerCount:    len(report.Triggers),
			DistinctValues:  distinct,
			HighCardinality: a.isHighCardinality(distinct),
		}
		report.Cardinality = append(report.Cardinality, cardinality)
		if cardinality.HighCardinality {
			report.Findings = append(report.Findings, LabelFinding{
				Severity:     LabelFindingSeverityWarning,
				Code:         FindingHighCardinalityLabel,
				TriggerIndex: -1,
				LabelKey:     key,
				LabelValue:   strconv.Itoa(distinct),
				Message: fmt.Sprintf("label key %q has %d distinct values across %d triggers, prefer bounded dimensions or disable high-cardinality labels",
					key, distinct, cardinality.TriggerCount),
			})
		}
	}
}

func (a *labelAnalysis) isHighCardinality(distinct int) bool {
	if distinct >= a.threshold {
		return true
	}
	return a.triggerCount >= fullyUniqueSampleSize && distinct == a.triggerCount
}

// validateScalerLabelInput checks the four identifying dimensions of a trigger
// and returns a finding per empty or abnormal field without dropping the
// trigger from the report.
func validateScalerLabelInput(input ScalerLabelInput) []LabelFinding {
	var findings []LabelFinding
	if input.ScalerType == "" {
		findings = append(findings, newTriggerFinding(
			LabelFindingSeverityWarning, FindingEmptyScalerType, input, scalerTypeLabelKey, "",
			"scaler type is empty, the trigger cannot be attributed to a scaler"))
	}
	if input.Namespace == "" {
		findings = append(findings, newTriggerFinding(
			LabelFindingSeverityWarning, FindingEmptyNamespace, input, namespaceLabelKey, "",
			"namespace is empty, series would collide under an empty namespace dimension"))
	}
	if input.Name == "" {
		resourceKey := scaledObjectLabelKey
		if !input.IsScaledObject {
			resourceKey = scaledJobLabelKey
		}
		findings = append(findings, newTriggerFinding(
			LabelFindingSeverityWarning, FindingEmptyName, input, resourceKey, "",
			"scalable resource name is empty, series cannot be attributed to a ScaledObject/ScaledJob"))
	}
	if input.TriggerIndex < 0 {
		findings = append(findings, newTriggerFinding(
			LabelFindingSeverityError, FindingNegativeTriggerIndex, input, "", strconv.Itoa(input.TriggerIndex),
			"trigger index is negative, trigger positions must be zero-based"))
	}
	return findings
}

func newTriggerFinding(severity LabelFindingSeverity, code LabelFindingCode, input ScalerLabelInput, key, value, message string) LabelFinding {
	return LabelFinding{
		Severity:     severity,
		Code:         code,
		TriggerIndex: input.TriggerIndex,
		TriggerName:  input.TriggerName,
		Identity:     ScalerTriggerIdentity(input),
		LabelKey:     key,
		LabelValue:   value,
		Message:      message,
	}
}

// ValidateScalerLabelKey checks a candidate label key against Prometheus label
// syntax, the Prometheus reserved namespace and the keys already occupied by
// KEDA metrics. Aggregate findings use trigger index -1 because they are not
// tied to a specific trigger.
func ValidateScalerLabelKey(key string) []LabelFinding {
	var findings []LabelFinding
	switch {
	case key == "":
		findings = append(findings, newKeyFinding(LabelFindingSeverityError, FindingInvalidLabelKey, key,
			"label key is empty"))
	case strings.HasPrefix(key, "__"):
		findings = append(findings, newKeyFinding(LabelFindingSeverityError, FindingReservedLabelKey, key,
			"label keys prefixed with \"__\" (including \"__name__\") are reserved by Prometheus"))
	case !promLabelNamePattern.MatchString(key):
		findings = append(findings, newKeyFinding(LabelFindingSeverityWarning, FindingInvalidLabelKey, key,
			"label key is not a valid Prometheus label name, the OTel Prometheus exporter would rewrite unsupported characters"))
	}
	if _, occupied := occupiedScalerLabelKeys[key]; occupied {
		findings = append(findings, newKeyFinding(LabelFindingSeverityError, FindingOccupiedLabelKey, key,
			"label key is already used by a KEDA metric, reusing it with different semantics would overwrite the existing dimension"))
	}
	return findings
}

func newKeyFinding(severity LabelFindingSeverity, code LabelFindingCode, key, message string) LabelFinding {
	return LabelFinding{
		Severity:     severity,
		Code:         code,
		TriggerIndex: -1,
		LabelKey:     key,
		Message:      message,
	}
}

// validateExtraLabelKeys validates candidate keys and detects pairs that the
// OTel Prometheus exporter would sanitize to the same Prometheus label name.
func validateExtraLabelKeys(keys []string) []LabelFinding {
	var findings []LabelFinding
	sanitized := make(map[string]string, len(keys))
	for _, key := range keys {
		findings = append(findings, ValidateScalerLabelKey(key)...)
		target := prometheusSanitizeKey(key)
		if previous, duplicated := sanitized[target]; duplicated && previous != key {
			findings = append(findings, newKeyFinding(LabelFindingSeverityError, FindingPrometheusKeyCollision, key,
				fmt.Sprintf("label key %q sanitizes to Prometheus label %q, colliding with %q", key, target, previous)))
			continue
		}
		sanitized[target] = key
		if _, occupied := occupiedScalerLabelKeys[target]; occupied && target != key {
			findings = append(findings, newKeyFinding(LabelFindingSeverityError, FindingPrometheusKeyCollision, key,
				fmt.Sprintf("label key %q sanitizes to %q, which is already occupied by a KEDA metric label", key, target)))
		}
	}
	return findings
}

// prometheusSanitizeKey mirrors the OTel Prometheus exporter rule of replacing
// characters outside [a-zA-Z0-9_] with underscores and prefixing keys that
// start with a digit.
func prometheusSanitizeKey(key string) string {
	var builder strings.Builder
	if len(key) > 0 && key[0] >= '0' && key[0] <= '9' {
		builder.WriteByte('_')
	}
	for _, r := range key {
		if isPromLabelRune(r) {
			builder.WriteRune(r)
		} else {
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

func isPromLabelRune(r rune) bool {
	return r == '_' ||
		(r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9')
}

// unstableLabelValueReason flags free-form label values that look generated
// rather than bounded enumerations. Bounded dimensions (scaler type, trigger
// index) are intentionally not inspected.
func unstableLabelValueReason(key, value string) (string, bool) {
	if value == "" || !isFreeFormLabelKey(key) {
		return "", false
	}
	switch {
	case uuidPattern.MatchString(value):
		return "value looks like a UUID, generated identifiers must not be used as label values", true
	case net.ParseIP(value) != nil:
		return "value looks like an IP address, network addresses are high-cardinality label values", true
	case hexHashPattern.MatchString(value):
		return "value looks like a hexadecimal hash, hashes are high-cardinality label values", true
	case numericIDPattern.MatchString(value):
		return "value looks like a numeric or timestamp identifier, such values are high-cardinality label values", true
	}
	if reason, ok := randomSuffixReason(value); ok {
		return reason, true
	}
	return "", false
}

func isFreeFormLabelKey(key string) bool {
	return key == namespaceLabelKey || key == scaledObjectLabelKey || key == scaledJobLabelKey
}

func randomSuffixReason(value string) (string, bool) {
	match := randomSuffixPattern.FindStringSubmatch(value)
	if match == nil {
		return "", false
	}
	suffix := match[1]
	hasDigit := strings.ContainsAny(suffix, "0123456789")
	hasLetter := strings.ContainsAny(suffix, "abcdefghijklmnopqrstuvwxyz")
	if !hasDigit || !hasLetter {
		return "", false
	}
	return "value looks like a generated resource name with a random pod/hash suffix, prefer the stable workload name", true
}

func sortFindings(findings []LabelFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.TriggerIndex != right.TriggerIndex {
			return left.TriggerIndex < right.TriggerIndex
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.LabelKey != right.LabelKey {
			return left.LabelKey < right.LabelKey
		}
		return left.LabelValue < right.LabelValue
	})
}
