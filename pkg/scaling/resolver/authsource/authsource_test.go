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

package authsource

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	kedav1alpha1 "github.com/kedacore/keda/v2/apis/keda/v1alpha1"
)

func TestAnalyzeNilAndEmptySpec(t *testing.T) {
	for _, spec := range []*kedav1alpha1.TriggerAuthenticationSpec{nil, {}} {
		report := Analyze(spec)

		require.NotNil(t, report)
		assert.NotNil(t, report.Fields)
		assert.NotNil(t, report.AllSources)
		assert.Empty(t, report.Fields)
		assert.Empty(t, report.AllSources)
		assert.Nil(t, report.PodIdentity)
		assert.Empty(t, report.Missing)
		assert.Empty(t, report.Forbidden)
		assert.False(t, report.HasFindings())
		assert.Empty(t, report.SortedParameters())
	}
}

func TestAnalyzeSecretTargetRef(t *testing.T) {
	spec := &kedav1alpha1.TriggerAuthenticationSpec{
		SecretTargetRef: []kedav1alpha1.AuthSecretTargetRef{
			{Parameter: "username", Name: "auth-secret", Key: "user-key"},
			{Parameter: "broken", Name: "", Key: ""},
			{Parameter: "", Name: "ignored-secret", Key: "ignored-key"},
		},
	}

	report := Analyze(spec)

	require.Contains(t, report.Fields, "username")
	winner := report.Fields["username"]
	assert.Equal(t, SourceTypeSecretTargetRef, winner.Source)
	assert.Equal(t, prioritySecretTargetRef, winner.Priority)
	assert.Equal(t, "auth-secret", winner.SecretName)
	assert.Equal(t, "user-key", winner.SecretKey)
	assert.Empty(t, winner.EnvName)
	assert.Empty(t, winner.Block)

	require.Contains(t, report.Fields, "broken")
	assert.Equal(t, "", report.Fields["broken"].SecretName)
	assert.Equal(t, "", report.Fields["broken"].SecretKey)

	// Entries without a parameter are not merged into the field maps.
	assert.NotContains(t, report.Fields, "")
	assert.NotContains(t, report.AllSources, "")

	categories := missingCategories(report)
	assert.ElementsMatch(t, []MissingCategory{
		MissingSecretName,
		MissingSecretKey,
		MissingParameter,
	}, categories)

	missingParameter := findMissing(report, MissingParameter)
	require.NotNil(t, missingParameter)
	assert.Equal(t, SourceTypeSecretTargetRef, missingParameter.Source)

	assert.True(t, report.HasFindings())
	assert.Empty(t, report.Forbidden)
}

func TestAnalyzeEnv(t *testing.T) {
	spec := &kedav1alpha1.TriggerAuthenticationSpec{
		Env: []kedav1alpha1.AuthEnvironment{
			{Parameter: "token", Name: "TOKEN_ENV", ContainerName: "sidecar"},
			{Parameter: "empty-env", Name: ""},
			{Parameter: "", Name: "NO_PARAMETER"},
		},
	}

	report := Analyze(spec)

	require.Contains(t, report.Fields, "token")
	winner := report.Fields["token"]
	assert.Equal(t, SourceTypeEnv, winner.Source)
	assert.Equal(t, priorityEnv, winner.Priority)
	assert.Equal(t, "TOKEN_ENV", winner.EnvName)
	assert.Equal(t, "sidecar", winner.ContainerName)
	assert.Empty(t, winner.SecretName)

	categories := missingCategories(report)
	assert.ElementsMatch(t, []MissingCategory{MissingEnvName, MissingParameter}, categories)
	assert.Empty(t, report.Forbidden)
}

func TestAnalyzePriorityAcrossSources(t *testing.T) {
	spec := &kedav1alpha1.TriggerAuthenticationSpec{
		SecretTargetRef: []kedav1alpha1.AuthSecretTargetRef{
			{Parameter: "password", Name: "vault-secret", Key: "password"},
		},
		Env: []kedav1alpha1.AuthEnvironment{
			{Parameter: "password", Name: "PASSWORD_ENV"},
		},
		OAuth2: &kedav1alpha1.OAuth2{
			ClientID: "client",
			TokenURL: "https://idp.example.com/token",
			ClientSecret: kedav1alpha1.OAuth2ClientSecret{
				ValueFrom: kedav1alpha1.ValueFromSecret{
					SecretKeyRef: kedav1alpha1.SecretKeyRef{Name: "oauth-secret", Key: "client-secret"},
				},
			},
		},
	}
	// Reuse the oauth2 parameterRef on a second, colliding parameter by
	// pointing a secretTargetRef at "clientSecret" as well.
	spec.SecretTargetRef = append(spec.SecretTargetRef, kedav1alpha1.AuthSecretTargetRef{
		Parameter: paramOAuth2ClientSecret,
		Name:      "explicit-secret",
		Key:       "key",
	})

	report := Analyze(spec)

	// secretTargetRef outranks env and parameterRef for the same parameter.
	assert.Equal(t, SourceTypeSecretTargetRef, report.Fields["password"].Source)
	assert.Equal(t, "vault-secret", report.Fields["password"].SecretName)
	assert.Equal(t, SourceTypeSecretTargetRef, report.Fields[paramOAuth2ClientSecret].Source)

	passwordSources := report.AllSources["password"]
	require.Len(t, passwordSources, 2)
	assert.Equal(t, SourceTypeSecretTargetRef, passwordSources[0].Source)
	assert.Equal(t, SourceTypeEnv, passwordSources[1].Source)

	clientSecretSources := report.AllSources[paramOAuth2ClientSecret]
	require.Len(t, clientSecretSources, 2)
	assert.Equal(t, SourceTypeSecretTargetRef, clientSecretSources[0].Source)
	assert.Equal(t, SourceTypeParameterRef, clientSecretSources[1].Source)
	assert.Equal(t, blockOAuth2ClientSecret, clientSecretSources[1].Block)
	assert.Equal(t, "oauth-secret", clientSecretSources[1].SecretName)

	kinds := comboKinds(report)
	assert.ElementsMatch(t, []ComboKind{ComboDuplicateParameter, ComboDuplicateParameter}, kinds)
	for _, combo := range report.Forbidden {
		require.Len(t, combo.Blocks, 2, "collision must list every participating declaration")
	}
}

func TestAnalyzeDuplicateReferenceWithinSameSource(t *testing.T) {
	spec := &kedav1alpha1.TriggerAuthenticationSpec{
		Env: []kedav1alpha1.AuthEnvironment{
			{Parameter: "host", Name: "FIRST_HOST"},
			{Parameter: "host", Name: "SECOND_HOST"},
		},
	}

	report := Analyze(spec)

	require.Len(t, report.Forbidden, 1)
	assert.Equal(t, ComboDuplicateReferenceSameSource, report.Forbidden[0].Kind)
	assert.Equal(t, "host", report.Forbidden[0].Parameter)
	assert.Equal(t, SourceTypeEnv, report.Forbidden[0].Source)

	// First declaration in spec order wins the tie.
	require.Len(t, report.AllSources["host"], 2)
	assert.Equal(t, "FIRST_HOST", report.Fields["host"].EnvName)
	assert.Equal(t, 0, report.AllSources["host"][0].ordinal)
	assert.Equal(t, 1, report.AllSources["host"][1].ordinal)
}

func TestAnalyzeParameterRefs(t *testing.T) {
	spec := &kedav1alpha1.TriggerAuthenticationSpec{
		OAuth2: &kedav1alpha1.OAuth2{
			ClientID: "client",
			TokenURL: "https://idp.example.com/token",
			ClientSecret: kedav1alpha1.OAuth2ClientSecret{
				ValueFrom: kedav1alpha1.ValueFromSecret{
					SecretKeyRef: kedav1alpha1.SecretKeyRef{Name: "", Key: ""},
				},
			},
		},
		AzureServicePrincipal: &kedav1alpha1.AzureServicePrincipal{
			TenantID: "tenant",
			ClientID: "client",
			ClientSecret: &kedav1alpha1.AzureServicePrincipalCredential{
				ValueFrom: kedav1alpha1.ValueFromSecret{
					SecretKeyRef: kedav1alpha1.SecretKeyRef{Name: "sp-secret", Key: "secret"},
				},
			},
		},
	}

	report := Analyze(spec)

	require.Contains(t, report.Fields, paramOAuth2ClientSecret)
	oauthSource := report.Fields[paramOAuth2ClientSecret]
	assert.Equal(t, SourceTypeParameterRef, oauthSource.Source)
	assert.Equal(t, blockOAuth2ClientSecret, oauthSource.Block)

	require.Contains(t, report.Fields, paramAzureSPClientSecret)
	spSource := report.Fields[paramAzureSPClientSecret]
	assert.Equal(t, blockAzureSPClientSecret, spSource.Block)
	assert.Equal(t, "sp-secret", spSource.SecretName)
	assert.Equal(t, "secret", spSource.SecretKey)

	categories := missingCategories(report)
	assert.ElementsMatch(t, []MissingCategory{MissingSecretName, MissingSecretKey}, categories)
	for _, missing := range report.Missing {
		assert.Equal(t, SourceTypeParameterRef, missing.Source)
		assert.Equal(t, blockOAuth2ClientSecret, missing.Block)
	}
}

func TestAnalyzeAllCloudParameterRefs(t *testing.T) {
	spec := &kedav1alpha1.TriggerAuthenticationSpec{
		AzureKeyVault: &kedav1alpha1.AzureKeyVault{
			VaultURI: "https://vault.example.com",
			Credentials: &kedav1alpha1.AzureKeyVaultCredentials{
				ClientID:     "client",
				TenantID:     "tenant",
				ClientSecret: &kedav1alpha1.AzureKeyVaultClientSecret{},
			},
		},
		GCPSecretManager: &kedav1alpha1.GCPSecretManager{
			Credentials: &kedav1alpha1.GCPCredentials{},
		},
		AwsSecretManager: &kedav1alpha1.AwsSecretManager{
			Credentials: &kedav1alpha1.AwsSecretManagerCredentials{
				AccessKey:       &kedav1alpha1.AwsSecretManagerValue{},
				AccessSecretKey: &kedav1alpha1.AwsSecretManagerValue{},
				AccessToken:     &kedav1alpha1.AwsSecretManagerValue{},
			},
		},
	}

	report := Analyze(spec)

	expected := []string{
		paramAzureKeyVaultClientSecret,
		paramGCPClientSecret,
		paramAWSAccessKey,
		paramAWSAccessSecretKey,
		paramAWSAccessToken,
	}
	assert.ElementsMatch(t, expected, report.SortedParameters())
	for _, parameter := range expected {
		assert.Equal(t, SourceTypeParameterRef, report.Fields[parameter].Source)
		assert.NotEmpty(t, report.Fields[parameter].Block)
	}
	// Every empty nested reference is reported as missing, never silently kept.
	assert.Len(t, report.Missing, len(expected)*2)
}

func TestAnalyzePodIdentitySummary(t *testing.T) {
	spec := &kedav1alpha1.TriggerAuthenticationSpec{
		PodIdentity: &kedav1alpha1.AuthPodIdentity{
			Provider:              kedav1alpha1.PodIdentityProviderAzureWorkload,
			IdentityID:            ptr.To("managed-id"),
			IdentityTenantID:      ptr.To("tenant"),
			IdentityAuthorityHost: ptr.To("https://login.example.com"),
		},
	}

	report := Analyze(spec)

	require.NotNil(t, report.PodIdentity)
	assert.Equal(t, kedav1alpha1.PodIdentityProviderAzureWorkload, report.PodIdentity.Provider)
	assert.True(t, report.PodIdentity.HasIdentityID)
	assert.True(t, report.PodIdentity.HasIdentityTenantID)
	assert.True(t, report.PodIdentity.HasIdentityAuthorityHost)
	assert.False(t, report.PodIdentity.HasRoleArn)
	assert.False(t, report.PodIdentity.HasExternalID)
	assert.Empty(t, report.PodIdentity.IdentityOwner)
	assert.False(t, report.HasFindings())
}

func TestAnalyzePodIdentityMissingAndInvalidProvider(t *testing.T) {
	missingProvider := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		PodIdentity: &kedav1alpha1.AuthPodIdentity{},
	})
	require.NotNil(t, missingProvider.PodIdentity)
	require.Len(t, missingProvider.Missing, 1)
	assert.Equal(t, MissingPodIdentityProvider, missingProvider.Missing[0].Category)

	invalidProvider := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		PodIdentity: &kedav1alpha1.AuthPodIdentity{Provider: "made-up"},
	})
	require.Len(t, invalidProvider.Missing, 1)
	assert.Equal(t, InvalidPodIdentityProvider, invalidProvider.Missing[0].Category)
}

func TestAnalyzeAwsPodIdentityCombinations(t *testing.T) {
	roleAndWorkloadOwner := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		PodIdentity: &kedav1alpha1.AuthPodIdentity{
			Provider:      kedav1alpha1.PodIdentityProviderAws,
			RoleArn:       ptr.To("arn:aws:iam::1234:role/keda"),
			IdentityOwner: ptr.To("workload"),
		},
	})
	require.Len(t, roleAndWorkloadOwner.Forbidden, 1)
	assert.Equal(t, ComboAwsRoleArnIdentityOwner, roleAndWorkloadOwner.Forbidden[0].Kind)

	externalIDWithoutRole := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		PodIdentity: &kedav1alpha1.AuthPodIdentity{
			Provider:   kedav1alpha1.PodIdentityProviderAws,
			ExternalID: ptr.To("external-id"),
		},
	})
	require.Len(t, externalIDWithoutRole.Forbidden, 1)
	assert.Equal(t, ComboAwsExternalIDWithoutRoleArn, externalIDWithoutRole.Forbidden[0].Kind)

	valid := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		PodIdentity: &kedav1alpha1.AuthPodIdentity{
			Provider:      kedav1alpha1.PodIdentityProviderAws,
			RoleArn:       ptr.To("arn:aws:iam::1234:role/keda"),
			ExternalID:    ptr.To("external-id"),
			IdentityOwner: ptr.To("keda"),
		},
	})
	assert.False(t, valid.HasFindings())
	require.NotNil(t, valid.PodIdentity)
	assert.True(t, valid.PodIdentity.HasRoleArn)
	assert.True(t, valid.PodIdentity.HasExternalID)
	assert.Equal(t, "keda", valid.PodIdentity.IdentityOwner)
}

func TestAnalyzeAzureWorkloadPodIdentityCombinations(t *testing.T) {
	emptyIdentityID := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		PodIdentity: &kedav1alpha1.AuthPodIdentity{
			Provider:   kedav1alpha1.PodIdentityProviderAzureWorkload,
			IdentityID: ptr.To(""),
		},
	})
	require.Len(t, emptyIdentityID.Forbidden, 1)
	assert.Equal(t, ComboAzureEmptyIdentityID, emptyIdentityID.Forbidden[0].Kind)

	authorityWithoutTenant := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		PodIdentity: &kedav1alpha1.AuthPodIdentity{
			Provider:              kedav1alpha1.PodIdentityProviderAzureWorkload,
			IdentityAuthorityHost: ptr.To("https://login.example.com"),
		},
	})
	require.Len(t, authorityWithoutTenant.Forbidden, 1)
	assert.Equal(t, ComboAzureAuthorityHostMissingTenant, authorityWithoutTenant.Forbidden[0].Kind)

	emptyTenant := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		PodIdentity: &kedav1alpha1.AuthPodIdentity{
			Provider:         kedav1alpha1.PodIdentityProviderAzureWorkload,
			IdentityTenantID: ptr.To(""),
		},
	})
	require.Len(t, emptyTenant.Forbidden, 1)
	assert.Equal(t, ComboAzureEmptyIdentityTenantID, emptyTenant.Forbidden[0].Kind)
}

func TestAnalyzeAzureServicePrincipalCombinations(t *testing.T) {
	secretAndCertificate := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		AzureServicePrincipal: &kedav1alpha1.AzureServicePrincipal{
			TenantID:          "tenant",
			ClientID:          "client",
			ClientSecret:      &kedav1alpha1.AzureServicePrincipalCredential{},
			ClientCertificate: &kedav1alpha1.AzureServicePrincipalCredential{},
		},
	})
	require.Len(t, secretAndCertificate.Forbidden, 1)
	assert.Equal(t, ComboAzureSPSecretAndCertificate, secretAndCertificate.Forbidden[0].Kind)

	noCredential := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		AzureServicePrincipal: &kedav1alpha1.AzureServicePrincipal{
			TenantID: "tenant",
			ClientID: "client",
		},
	})
	require.Len(t, noCredential.Forbidden, 1)
	assert.Equal(t, ComboAzureSPMissingCredential, noCredential.Forbidden[0].Kind)

	passwordWithoutCertificate := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		AzureServicePrincipal: &kedav1alpha1.AzureServicePrincipal{
			TenantID:                  "tenant",
			ClientID:                  "client",
			ClientSecret:              &kedav1alpha1.AzureServicePrincipalCredential{},
			ClientCertificatePassword: &kedav1alpha1.AzureServicePrincipalCredential{},
		},
	})
	require.Len(t, passwordWithoutCertificate.Forbidden, 1)
	assert.Equal(t, ComboAzureSPCertPasswordWithoutCert, passwordWithoutCertificate.Forbidden[0].Kind)

	certificateWithPassword := Analyze(&kedav1alpha1.TriggerAuthenticationSpec{
		AzureServicePrincipal: &kedav1alpha1.AzureServicePrincipal{
			TenantID:                  "tenant",
			ClientID:                  "client",
			ClientCertificate:         &kedav1alpha1.AzureServicePrincipalCredential{},
			ClientCertificatePassword: &kedav1alpha1.AzureServicePrincipalCredential{},
		},
	})
	assert.Empty(t, certificateWithPassword.Forbidden)
}

func TestAnalyzeSortedParametersAndStableOutput(t *testing.T) {
	spec := &kedav1alpha1.TriggerAuthenticationSpec{
		SecretTargetRef: []kedav1alpha1.AuthSecretTargetRef{
			{Parameter: "zebra", Name: "z-secret", Key: "z"},
			{Parameter: "alpha", Name: "a-secret", Key: "a"},
			{Parameter: "middle", Name: "m-secret", Key: "m"},
		},
	}

	first := Analyze(spec)
	second := Analyze(spec)

	assert.Equal(t, []string{"alpha", "middle", "zebra"}, first.SortedParameters())
	assert.Equal(t, first, second, "Analyze must produce identical, deterministic output")
}

func TestAnalyzeNeverCarriesSecretValues(t *testing.T) {
	spec := &kedav1alpha1.TriggerAuthenticationSpec{
		SecretTargetRef: []kedav1alpha1.AuthSecretTargetRef{
			{Parameter: "password", Name: "auth-secret", Key: "password-key"},
		},
	}

	report := Analyze(spec)
	source := report.Fields["password"]

	// The report exposes reference coordinates only; FieldSource intentionally
	// has no field capable of holding a resolved secret value.
	assert.Equal(t, "auth-secret", source.SecretName)
	assert.Equal(t, "password-key", source.SecretKey)
	assert.Empty(t, source.EnvName)
	assert.Empty(t, source.Block)
	assert.Empty(t, source.ContainerName)
}

// missingCategories collects the categories of every missing-field finding.
func missingCategories(report *Report) []MissingCategory {
	categories := make([]MissingCategory, 0, len(report.Missing))
	for _, missing := range report.Missing {
		categories = append(categories, missing.Category)
	}
	return categories
}

// comboKinds collects the kinds of every forbidden-combination finding.
func comboKinds(report *Report) []ComboKind {
	kinds := make([]ComboKind, 0, len(report.Forbidden))
	for _, combo := range report.Forbidden {
		kinds = append(kinds, combo.Kind)
	}
	return kinds
}

// findMissing returns the first finding of the given category, or nil.
func findMissing(report *Report, category MissingCategory) *MissingField {
	for i := range report.Missing {
		if report.Missing[i].Category == category {
			return &report.Missing[i]
		}
	}
	return nil
}
