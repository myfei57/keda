/*
Copyright 2024 The KEDA Authors

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

// Package authsource provides a static, cluster-free analysis of the secret
// sources declared on a TriggerAuthentication or ClusterTriggerAuthentication
// spec.
//
// Security guarantees:
//   - The Kubernetes API is never contacted. The analyzer only reads the spec
//     handed to it and intentionally has no client or lister dependencies.
//   - Secret values are never read, resolved or returned. The report only
//     carries reference coordinates (secret name/key, environment variable
//     name, parameter name and the originating spec block).
//
// The analyzer merges the parameter-keyed reference families:
//   - secretTargetRef entries (SourceTypeSecretTargetRef)
//   - env entries (SourceTypeEnv)
//   - nested valueFrom.secretKeyRef "parameter references" used by the
//     structured auth blocks (SourceTypeParameterRef): oauth2, azureKeyVault,
//     gcpSecretManager, awsSecretManager and azureServicePrincipal credentials.
//
// podIdentity does not produce per-parameter entries; it is summarized
// separately and checked against the same forbidden combinations the
// admission webhook enforces.
//
// When the same parameter is declared by more than one source, the winner is
// selected by a fixed priority (secretTargetRef > env > parameterRef) and,
// within the same source type, by the declaration order in the spec. Every
// shadowed declaration is retained in Report.AllSources and the collision is
// surfaced as a forbidden combination, so the output stays deterministic.
package authsource

import (
	"fmt"
	"sort"

	kedav1alpha1 "github.com/kedacore/keda/v2/apis/keda/v1alpha1"
)

// SourceType identifies where an authentication parameter is declared.
type SourceType string

const (
	// SourceTypeSecretTargetRef marks a spec.secretTargetRef entry.
	SourceTypeSecretTargetRef SourceType = "secretTargetRef"
	// SourceTypeEnv marks a spec.env entry.
	SourceTypeEnv SourceType = "env"
	// SourceTypeParameterRef marks a nested valueFrom.secretKeyRef reference
	// inside one of the structured auth blocks (oauth2, azureKeyVault,
	// gcpSecretManager, awsSecretManager, azureServicePrincipal).
	SourceTypeParameterRef SourceType = "parameterRef"
	// SourceTypePodIdentity marks the spec.podIdentity configuration. It only
	// appears on missing-field and forbidden-combination findings.
	SourceTypePodIdentity SourceType = "podIdentity"
)

// Explicit precedence applied when one parameter has several sources.
// A lower number wins; ties are broken by declaration order in the spec.
const (
	prioritySecretTargetRef = 1
	priorityEnv             = 2
	priorityParameterRef    = 3
)

// MissingCategory classifies an incomplete reference without performing any
// cluster lookup.
type MissingCategory string

const (
	// MissingParameter means a secretTargetRef or env entry does not name the
	// auth parameter it maps to.
	MissingParameter MissingCategory = "MissingParameter"
	// MissingSecretName means a secret reference has an empty secret name.
	MissingSecretName MissingCategory = "MissingSecretName"
	// MissingSecretKey means a secret reference has an empty secret key.
	MissingSecretKey MissingCategory = "MissingSecretKey"
	// MissingEnvName means an env entry does not name the environment variable.
	MissingEnvName MissingCategory = "MissingEnvName"
	// MissingPodIdentityProvider means podIdentity is set without a provider.
	MissingPodIdentityProvider MissingCategory = "MissingPodIdentityProvider"
	// InvalidPodIdentityProvider means the provider value is not one of the
	// supported pod identity providers.
	InvalidPodIdentityProvider MissingCategory = "InvalidPodIdentityProvider"
)

// ComboKind identifies a forbidden or ambiguous combination detected in the
// spec. Pod identity and Azure service principal rules mirror the admission
// webhook validation; duplicate parameter rules are static ambiguity checks.
type ComboKind string

const (
	// ComboDuplicateParameter means the same parameter is declared by more
	// than one source type.
	ComboDuplicateParameter ComboKind = "DuplicateParameter"
	// ComboDuplicateReferenceSameSource means the same parameter is declared
	// more than once within a single source type.
	ComboDuplicateReferenceSameSource ComboKind = "DuplicateReferenceWithinSource"
	// ComboAwsRoleArnIdentityOwner mirrors the webhook rule forbidding an AWS
	// roleArn together with the workload identity owner.
	ComboAwsRoleArnIdentityOwner ComboKind = "AwsRoleArnWithWorkloadIdentityOwner"
	// ComboAwsExternalIDWithoutRoleArn mirrors the webhook rule requiring
	// roleArn when externalID is set.
	ComboAwsExternalIDWithoutRoleArn ComboKind = "AwsExternalIDWithoutRoleArn"
	// ComboAzureEmptyIdentityID mirrors the webhook rule rejecting an empty
	// azure-workload identityId pointer value.
	ComboAzureEmptyIdentityID ComboKind = "AzureEmptyIdentityID"
	// ComboAzureEmptyIdentityTenantID mirrors the webhook rule rejecting an
	// empty azure-workload identityTenantId pointer value.
	ComboAzureEmptyIdentityTenantID ComboKind = "AzureEmptyIdentityTenantID"
	// ComboAzureAuthorityHostMissingTenant mirrors the webhook rule requiring
	// identityTenantId when identityAuthorityHost is set.
	ComboAzureAuthorityHostMissingTenant ComboKind = "AzureAuthorityHostWithoutTenant"
	// ComboAzureSPSecretAndCertificate mirrors the webhook rule making
	// azureServicePrincipal clientSecret and clientCertificate mutually
	// exclusive.
	ComboAzureSPSecretAndCertificate ComboKind = "AzureServicePrincipalSecretAndCertificate"
	// ComboAzureSPMissingCredential mirrors the webhook rule requiring either
	// clientSecret or clientCertificate on azureServicePrincipal.
	ComboAzureSPMissingCredential ComboKind = "AzureServicePrincipalMissingCredential"
	// ComboAzureSPCertPasswordWithoutCert mirrors the webhook rule requiring
	// clientCertificate when clientCertificatePassword is set.
	ComboAzureSPCertPasswordWithoutCert ComboKind = "AzureServicePrincipalCertificatePasswordWithoutCertificate"
)

// Spec block paths used to pinpoint nested parameter references.
const (
	blockOAuth2ClientSecret = "oauth2.clientSecret"

	blockAzureKeyVaultClientSecret = "azureKeyVault.credentials.clientSecret"
	blockGCPClientSecret           = "gcpSecretManager.credentials.clientSecret"
	blockAWSAccessKey              = "awsSecretManager.credentials.accessKey"
	blockAWSAccessSecretKey        = "awsSecretManager.credentials.accessSecretKey"
	blockAWSAccessToken            = "awsSecretManager.credentials.accessToken"

	blockAzureSPClientSecret              = "azureServicePrincipal.clientSecret"
	blockAzureSPClientCertificate         = "azureServicePrincipal.clientCertificate"
	blockAzureSPClientCertificatePassword = "azureServicePrincipal.clientCertificatePassword"
)

// Fixed parameter names owned by the nested parameter references.
const (
	paramOAuth2ClientSecret = "clientSecret"

	paramAzureKeyVaultClientSecret = "azureKeyVaultClientSecret"
	paramGCPClientSecret           = "gcpSecretManagerClientSecret"
	paramAWSAccessKey              = "awsSecretManagerAccessKey"
	paramAWSAccessSecretKey        = "awsSecretManagerAccessSecretKey"
	paramAWSAccessToken            = "awsSecretManagerAccessToken"

	paramAzureSPClientSecret              = "azureServicePrincipalClientSecret"
	paramAzureSPClientCertificate         = "azureServicePrincipalClientCertificate"
	paramAzureSPClientCertificatePassword = "azureServicePrincipalClientCertificatePassword"
)

// FieldSource describes a single declaration of an auth parameter. It only
// contains reference coordinates; secret values are never present.
type FieldSource struct {
	// Parameter is the auth parameter key the reference maps to.
	Parameter string
	// Source is the family the declaration belongs to.
	Source SourceType
	// Priority is the precedence of the source family (lower wins).
	Priority int
	// SecretName is the referenced Secret name, for secretTargetRef and
	// parameterRef entries.
	SecretName string
	// SecretKey is the referenced Secret key, for secretTargetRef and
	// parameterRef entries.
	SecretKey string
	// EnvName is the referenced workload environment variable name.
	EnvName string
	// ContainerName is the optional container qualifier of an env entry.
	ContainerName string
	// Block is the spec path of a nested parameterRef entry.
	Block string

	// ordinal keeps the declaration order in the spec for stable tie-breaks.
	ordinal int
}

// MissingField describes an incomplete reference. It never carries a value,
// only the location and category of the missing piece.
type MissingField struct {
	// Category classifies what is missing.
	Category MissingCategory
	// Source is the family the broken declaration belongs to.
	Source SourceType
	// Parameter is the affected auth parameter, empty when the parameter
	// itself is missing.
	Parameter string
	// Block is the spec path of a nested parameterRef entry.
	Block string
	// Message is a human-readable description of the problem.
	Message string
}

// ForbiddenCombo describes a forbidden or ambiguous combination in the spec.
type ForbiddenCombo struct {
	// Kind identifies the violated rule.
	Kind ComboKind
	// Source is the family the combination belongs to.
	Source SourceType
	// Parameter is the affected auth parameter, empty for spec-wide rules.
	Parameter string
	// Blocks lists the spec locations participating in the combination.
	Blocks []string
	// Message is a human-readable description of the problem.
	Message string
}

// PodIdentityInfo summarizes the podIdentity configuration without exposing
// credential material: only the provider enum, the identity owner and the
// presence of optional fields are reported.
type PodIdentityInfo struct {
	// Provider is the configured pod identity provider.
	Provider kedav1alpha1.PodIdentityProvider
	// IdentityOwner is the raw identityOwner value ("keda", "workload" or
	// empty when unset).
	IdentityOwner string
	// HasIdentityID reports whether identityId is configured.
	HasIdentityID bool
	// HasIdentityTenantID reports whether identityTenantId is configured.
	HasIdentityTenantID bool
	// HasIdentityAuthorityHost reports whether identityAuthorityHost is
	// configured.
	HasIdentityAuthorityHost bool
	// HasRoleArn reports whether roleArn is configured.
	HasRoleArn bool
	// HasExternalID reports whether externalID is configured.
	HasExternalID bool
}

// Report is the static analysis result for a TriggerAuthenticationSpec.
type Report struct {
	// Fields maps each parameter to its winning source after priority
	// resolution.
	Fields map[string]FieldSource
	// AllSources maps each parameter to every declaration targeting it,
	// sorted by priority and declaration order.
	AllSources map[string][]FieldSource
	// PodIdentity summarizes spec.podIdentity; nil when podIdentity is unset.
	PodIdentity *PodIdentityInfo
	// Missing lists incomplete references, sorted for stable consumption.
	Missing []MissingField
	// Forbidden lists forbidden or ambiguous combinations, sorted for stable
	// consumption.
	Forbidden []ForbiddenCombo
}

// SortedParameters returns the analyzed parameter keys in lexical order.
func (r *Report) SortedParameters() []string {
	params := make([]string, 0, len(r.Fields))
	for param := range r.Fields {
		params = append(params, param)
	}
	sort.Strings(params)
	return params
}

// HasFindings reports whether the spec has any missing field or forbidden
// combination.
func (r *Report) HasFindings() bool {
	return len(r.Missing) > 0 || len(r.Forbidden) > 0
}

// analyzer accumulates the static analysis while walking the spec.
type analyzer struct {
	sources         []FieldSource
	missing         []MissingField
	forbidden       []ForbiddenCombo
	podIdentityInfo *PodIdentityInfo
	ordinal         int
}

// Analyze inspects the given TriggerAuthenticationSpec statically. It never
// contacts the Kubernetes API and never returns secret values. A nil or empty
// spec yields an empty, non-nil report.
func Analyze(spec *kedav1alpha1.TriggerAuthenticationSpec) *Report {
	a := &analyzer{
		sources:   []FieldSource{},
		missing:   []MissingField{},
		forbidden: []ForbiddenCombo{},
	}
	if spec == nil {
		return a.newReport()
	}

	a.collectSecretTargetRefs(spec)
	a.collectEnv(spec)
	a.collectParameterRefs(spec)
	a.analyzePodIdentity(spec)
	a.analyzeAzureServicePrincipal(spec)

	return a.newReport()
}

// collectSecretTargetRefs walks spec.secretTargetRef.
func (a *analyzer) collectSecretTargetRefs(spec *kedav1alpha1.TriggerAuthenticationSpec) {
	for i := range spec.SecretTargetRef {
		ref := &spec.SecretTargetRef[i]
		if ref.Parameter == "" {
			a.addMissing(MissingParameter, SourceTypeSecretTargetRef, "", "",
				"secretTargetRef entry is missing parameter")
			continue
		}
		if ref.Name == "" {
			a.addMissing(MissingSecretName, SourceTypeSecretTargetRef, ref.Parameter, "",
				"secretTargetRef entry is missing secret name")
		}
		if ref.Key == "" {
			a.addMissing(MissingSecretKey, SourceTypeSecretTargetRef, ref.Parameter, "",
				"secretTargetRef entry is missing secret key")
		}
		a.addField(FieldSource{
			Parameter:  ref.Parameter,
			Source:     SourceTypeSecretTargetRef,
			Priority:   prioritySecretTargetRef,
			SecretName: ref.Name,
			SecretKey:  ref.Key,
		})
	}
}

// collectEnv walks spec.env.
func (a *analyzer) collectEnv(spec *kedav1alpha1.TriggerAuthenticationSpec) {
	for i := range spec.Env {
		ref := &spec.Env[i]
		if ref.Parameter == "" {
			a.addMissing(MissingParameter, SourceTypeEnv, "", "",
				"env entry is missing parameter")
			continue
		}
		if ref.Name == "" {
			a.addMissing(MissingEnvName, SourceTypeEnv, ref.Parameter, "",
				"env entry is missing environment variable name")
		}
		a.addField(FieldSource{
			Parameter:     ref.Parameter,
			Source:        SourceTypeEnv,
			Priority:      priorityEnv,
			EnvName:       ref.Name,
			ContainerName: ref.ContainerName,
		})
	}
}

// collectParameterRefs walks the nested valueFrom.secretKeyRef references used
// by the structured auth blocks.
func (a *analyzer) collectParameterRefs(spec *kedav1alpha1.TriggerAuthenticationSpec) {
	if spec.OAuth2 != nil {
		a.addSecretKeyRef(paramOAuth2ClientSecret, blockOAuth2ClientSecret,
			spec.OAuth2.ClientSecret.ValueFrom.SecretKeyRef)
	}
	if spec.AzureKeyVault != nil && spec.AzureKeyVault.Credentials != nil &&
		spec.AzureKeyVault.Credentials.ClientSecret != nil {
		a.addSecretKeyRef(paramAzureKeyVaultClientSecret, blockAzureKeyVaultClientSecret,
			spec.AzureKeyVault.Credentials.ClientSecret.ValueFrom.SecretKeyRef)
	}
	if spec.GCPSecretManager != nil && spec.GCPSecretManager.Credentials != nil {
		a.addSecretKeyRef(paramGCPClientSecret, blockGCPClientSecret,
			spec.GCPSecretManager.Credentials.ClientSecret.ValueFrom.SecretKeyRef)
	}
	if spec.AwsSecretManager != nil && spec.AwsSecretManager.Credentials != nil {
		credentials := spec.AwsSecretManager.Credentials
		if credentials.AccessKey != nil {
			a.addSecretKeyRef(paramAWSAccessKey, blockAWSAccessKey,
				credentials.AccessKey.ValueFrom.SecretKeyRef)
		}
		if credentials.AccessSecretKey != nil {
			a.addSecretKeyRef(paramAWSAccessSecretKey, blockAWSAccessSecretKey,
				credentials.AccessSecretKey.ValueFrom.SecretKeyRef)
		}
		if credentials.AccessToken != nil {
			a.addSecretKeyRef(paramAWSAccessToken, blockAWSAccessToken,
				credentials.AccessToken.ValueFrom.SecretKeyRef)
		}
	}
	if spec.AzureServicePrincipal != nil {
		servicePrincipal := spec.AzureServicePrincipal
		if servicePrincipal.ClientSecret != nil {
			a.addSecretKeyRef(paramAzureSPClientSecret, blockAzureSPClientSecret,
				servicePrincipal.ClientSecret.ValueFrom.SecretKeyRef)
		}
		if servicePrincipal.ClientCertificate != nil {
			a.addSecretKeyRef(paramAzureSPClientCertificate, blockAzureSPClientCertificate,
				servicePrincipal.ClientCertificate.ValueFrom.SecretKeyRef)
		}
		if servicePrincipal.ClientCertificatePassword != nil {
			a.addSecretKeyRef(paramAzureSPClientCertificatePassword, blockAzureSPClientCertificatePassword,
				servicePrincipal.ClientCertificatePassword.ValueFrom.SecretKeyRef)
		}
	}
}

// addSecretKeyRef records a nested parameter reference, flagging empty secret
// name or key without inspecting the referenced Secret.
func (a *analyzer) addSecretKeyRef(parameter, block string, secretKeyRef kedav1alpha1.SecretKeyRef) {
	if secretKeyRef.Name == "" {
		a.addMissing(MissingSecretName, SourceTypeParameterRef, parameter, block,
			fmt.Sprintf("%s reference is missing secret name", block))
	}
	if secretKeyRef.Key == "" {
		a.addMissing(MissingSecretKey, SourceTypeParameterRef, parameter, block,
			fmt.Sprintf("%s reference is missing secret key", block))
	}
	a.addField(FieldSource{
		Parameter:  parameter,
		Source:     SourceTypeParameterRef,
		Priority:   priorityParameterRef,
		Block:      block,
		SecretName: secretKeyRef.Name,
		SecretKey:  secretKeyRef.Key,
	})
}

// analyzePodIdentity summarizes spec.podIdentity and mirrors the pod identity
// rules enforced by the admission webhook.
func (a *analyzer) analyzePodIdentity(spec *kedav1alpha1.TriggerAuthenticationSpec) {
	podIdentity := spec.PodIdentity
	if podIdentity == nil {
		return
	}

	info := &PodIdentityInfo{
		Provider:                 podIdentity.Provider,
		HasIdentityID:            podIdentity.IdentityID != nil,
		HasIdentityTenantID:      podIdentity.IdentityTenantID != nil,
		HasIdentityAuthorityHost: podIdentity.IdentityAuthorityHost != nil,
		HasRoleArn:               podIdentity.RoleArn != nil,
		HasExternalID:            podIdentity.ExternalID != nil,
	}
	if podIdentity.IdentityOwner != nil {
		info.IdentityOwner = *podIdentity.IdentityOwner
	}

	if podIdentity.Provider == "" {
		a.addMissing(MissingPodIdentityProvider, SourceTypePodIdentity, "", "",
			"podIdentity is missing provider")
	} else if !isKnownProvider(podIdentity.Provider) {
		a.addMissing(InvalidPodIdentityProvider, SourceTypePodIdentity, "", "",
			fmt.Sprintf("podIdentity provider %q is not supported", podIdentity.Provider))
	}

	switch podIdentity.Provider {
	case kedav1alpha1.PodIdentityProviderAws:
		a.analyzeAwsPodIdentity(podIdentity)
	case kedav1alpha1.PodIdentityProviderAzureWorkload:
		a.analyzeAzureWorkloadPodIdentity(podIdentity)
	}
	a.podIdentityInfo = info
}

// analyzeAwsPodIdentity mirrors the AWS branch of the webhook validator.
func (a *analyzer) analyzeAwsPodIdentity(podIdentity *kedav1alpha1.AuthPodIdentity) {
	if podIdentity.RoleArn != nil && *podIdentity.RoleArn != "" && podIdentity.IsWorkloadIdentityOwner() {
		a.addForbidden(ComboAwsRoleArnIdentityOwner, SourceTypePodIdentity, "", nil,
			"roleArn of PodIdentity can't be set if KEDA isn't identityOwner")
	}
	if podIdentity.ExternalID != nil && *podIdentity.ExternalID != "" &&
		(podIdentity.RoleArn == nil || *podIdentity.RoleArn == "") {
		a.addForbidden(ComboAwsExternalIDWithoutRoleArn, SourceTypePodIdentity, "", nil,
			"externalID of PodIdentity requires roleArn to be set")
	}
}

// analyzeAzureWorkloadPodIdentity mirrors the azure-workload branch of the
// webhook validator.
func (a *analyzer) analyzeAzureWorkloadPodIdentity(podIdentity *kedav1alpha1.AuthPodIdentity) {
	if podIdentity.IdentityID != nil && *podIdentity.IdentityID == "" {
		a.addForbidden(ComboAzureEmptyIdentityID, SourceTypePodIdentity, "", nil,
			"identityId of PodIdentity should not be empty")
	}
	if podIdentity.IdentityAuthorityHost != nil && *podIdentity.IdentityAuthorityHost != "" {
		if podIdentity.IdentityTenantID == nil || *podIdentity.IdentityTenantID == "" {
			a.addForbidden(ComboAzureAuthorityHostMissingTenant, SourceTypePodIdentity, "", nil,
				"identityTenantID of PodIdentity should not be nil or empty when identityAuthorityHost is set")
		}
	} else if podIdentity.IdentityTenantID != nil && *podIdentity.IdentityTenantID == "" {
		a.addForbidden(ComboAzureEmptyIdentityTenantID, SourceTypePodIdentity, "", nil,
			"identityTenantId of PodIdentity should not be empty")
	}
}

// analyzeAzureServicePrincipal mirrors the mutually-exclusive credential rules
// of validateAzureServicePrincipal in the admission webhook.
func (a *analyzer) analyzeAzureServicePrincipal(spec *kedav1alpha1.TriggerAuthenticationSpec) {
	servicePrincipal := spec.AzureServicePrincipal
	if servicePrincipal == nil {
		return
	}

	switch {
	case servicePrincipal.ClientSecret != nil && servicePrincipal.ClientCertificate != nil:
		a.addForbidden(ComboAzureSPSecretAndCertificate, SourceTypeParameterRef, "",
			[]string{blockAzureSPClientSecret, blockAzureSPClientCertificate},
			"azureServicePrincipal.clientSecret and azureServicePrincipal.clientCertificate are mutually exclusive")
	case servicePrincipal.ClientSecret == nil && servicePrincipal.ClientCertificate == nil:
		a.addForbidden(ComboAzureSPMissingCredential, SourceTypeParameterRef, "", nil,
			"azureServicePrincipal requires either clientSecret or clientCertificate")
	}

	if servicePrincipal.ClientCertificatePassword != nil && servicePrincipal.ClientCertificate == nil {
		a.addForbidden(ComboAzureSPCertPasswordWithoutCert, SourceTypeParameterRef, "",
			[]string{blockAzureSPClientCertificatePassword, blockAzureSPClientCertificate},
			"azureServicePrincipal.clientCertificatePassword requires clientCertificate")
	}
}

// isKnownProvider reports whether provider is one of the CRD-supported values.
func isKnownProvider(provider kedav1alpha1.PodIdentityProvider) bool {
	switch provider {
	case kedav1alpha1.PodIdentityProviderNone,
		kedav1alpha1.PodIdentityProviderAzureWorkload,
		kedav1alpha1.PodIdentityProviderGCP,
		kedav1alpha1.PodIdentityProviderAwsEKS,
		kedav1alpha1.PodIdentityProviderAws:
		return true
	default:
		return false
	}
}

// addField records a declaration and assigns a monotonic ordinal.
func (a *analyzer) addField(source FieldSource) {
	source.ordinal = a.ordinal
	a.ordinal++
	a.sources = append(a.sources, source)
}

// addMissing records a missing-field finding.
func (a *analyzer) addMissing(category MissingCategory, source SourceType, parameter, block, message string) {
	a.missing = append(a.missing, MissingField{
		Category:  category,
		Source:    source,
		Parameter: parameter,
		Block:     block,
		Message:   message,
	})
}

// addForbidden records a forbidden-combination finding.
func (a *analyzer) addForbidden(kind ComboKind, source SourceType, parameter string, blocks []string, message string) {
	a.forbidden = append(a.forbidden, ForbiddenCombo{
		Kind:      kind,
		Source:    source,
		Parameter: parameter,
		Blocks:    blocks,
		Message:   message,
	})
}

// newReport merges the collected declarations, resolves priority conflicts and
// returns a deterministically ordered report.
func (a *analyzer) newReport() *Report {
	report := &Report{
		Fields:     map[string]FieldSource{},
		AllSources: map[string][]FieldSource{},
	}
	if a.podIdentityInfo != nil {
		report.PodIdentity = a.podIdentityInfo
	}

	byParameter := map[string][]FieldSource{}
	for _, source := range a.sources {
		byParameter[source.Parameter] = append(byParameter[source.Parameter], source)
	}

	for parameter, sources := range byParameter {
		sort.Slice(sources, func(i, j int) bool {
			if sources[i].Priority != sources[j].Priority {
				return sources[i].Priority < sources[j].Priority
			}
			return sources[i].ordinal < sources[j].ordinal
		})
		report.AllSources[parameter] = sources
		report.Fields[parameter] = sources[0]
		a.recordDuplicate(parameter, sources)
	}

	// Bind the finding slices only after duplicate detection has finished.
	report.Missing = a.missing
	report.Forbidden = a.forbidden
	sort.Slice(report.Missing, func(i, j int) bool {
		return compareMissing(report.Missing[i], report.Missing[j])
	})
	sort.Slice(report.Forbidden, func(i, j int) bool {
		return compareForbidden(report.Forbidden[i], report.Forbidden[j])
	})
	return report
}

// recordDuplicate flags parameters declared more than once.
func (a *analyzer) recordDuplicate(parameter string, sources []FieldSource) {
	if len(sources) < 2 {
		return
	}
	blocks := make([]string, 0, len(sources))
	distinctSources := map[SourceType]struct{}{}
	for _, source := range sources {
		distinctSources[source.Source] = struct{}{}
		blocks = append(blocks, source.coordinate())
	}
	if len(distinctSources) > 1 {
		a.addForbidden(ComboDuplicateParameter, sources[0].Source, parameter, blocks,
			fmt.Sprintf("parameter %q is declared by multiple source types, %q wins by priority",
				parameter, sources[0].Source))
		return
	}
	a.addForbidden(ComboDuplicateReferenceSameSource, sources[0].Source, parameter, blocks,
		fmt.Sprintf("parameter %q is declared more than once in %q, the first declaration wins",
			parameter, sources[0].Source))
}

// coordinate returns a stable spec location for a declaration.
func (f FieldSource) coordinate() string {
	if f.Block != "" {
		return f.Block
	}
	return string(f.Source)
}

// compareMissing defines the stable order of missing-field findings.
func compareMissing(left, right MissingField) bool {
	if left.Category != right.Category {
		return left.Category < right.Category
	}
	if left.Source != right.Source {
		return left.Source < right.Source
	}
	if left.Parameter != right.Parameter {
		return left.Parameter < right.Parameter
	}
	return left.Block < right.Block
}

// compareForbidden defines the stable order of forbidden-combination findings.
func compareForbidden(left, right ForbiddenCombo) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	if left.Parameter != right.Parameter {
		return left.Parameter < right.Parameter
	}
	return left.Source < right.Source
}
