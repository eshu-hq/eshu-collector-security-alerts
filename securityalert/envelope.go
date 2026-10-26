// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema"
	sdkidentity "github.com/eshu-hq/eshu-sdk/factschema/identity"
	securityalertv1 "github.com/eshu-hq/eshu-sdk/factschema/securityalert/v1"
)

// NewRepositoryAlertFact converts one GitHub Dependabot alert into a
// repository-scoped provider security-alert source fact.
//
// When ctx.RepositoryID is non-empty (org-wide targets), it is used for
// payload["repository_id"] and the stable key so host reconciliation keys
// on the per-repository scope. ctx.ScopeID (the committed generation
// scope) is used for the fact scope so the envelope matches the committed
// generation scope the host streaming fact writer requires on every fact.
//
// The stable key carries the dedup identity (provider + alert number +
// repository) and is stable across generations, byte-identical to the
// in-tree stableFactKey (see the golden test); the SDK identity helper
// shares the in-tree StableID scheme (fact_type + identity, sha256 hex).
// Generation binding travels via SourceRef.GenerationID and the Result
// generation, and fencing travels at the claim level: the SDK Fact carries
// no per-fact generation or fencing fields.
func NewRepositoryAlertFact(ctx EnvelopeContext, alert GitHubDependabotAlert) (collector.Fact, error) {
	if err := validateEnvelopeContext(ctx); err != nil {
		return collector.Fact{}, err
	}
	if alert.Number <= 0 {
		return collector.Fact{}, fmt.Errorf("github dependabot alert number must be positive")
	}
	identity, err := packageIdentityFromDependabot(alert)
	if err != nil {
		return collector.Fact{}, err
	}
	// repositoryID is the per-repository scope used for reducer keying and
	// stable fact dedup. For per-repository targets it equals ctx.ScopeID.
	// For org targets ctx.RepositoryID carries the per-repo scope while
	// ctx.ScopeID holds the org generation scope.
	repositoryID := ctx.ScopeID
	if r := strings.TrimSpace(ctx.RepositoryID); r != "" {
		repositoryID = r
	}
	providerAlertID := githubDependabotAlertID(repositoryID, alert.Number)
	stableFactKey := sdkidentity.StableID(KindRepositoryAlert, map[string]any{
		"provider":              ProviderGitHubDependabot,
		"provider_alert_number": alert.Number,
		"repository_id":         repositoryID,
	})
	payload := map[string]any{
		"collector_instance_id": ctx.CollectorInstanceID,
		"provider":              ProviderGitHubDependabot,
		"provider_alert_id":     providerAlertID,
		"provider_alert_number": int64(alert.Number),
		"provider_state":        strings.TrimSpace(alert.State),
		"repository_id":         repositoryID,
		"ecosystem":             string(identity.Ecosystem),
		"package_name":          identity.NormalizedName,
		"package_id":            identity.PackageID,
		"manifest_path":         strings.TrimSpace(alert.Dependency.ManifestPath),
		"dependency_scope":      strings.TrimSpace(alert.Dependency.Scope),
		"relationship":          strings.TrimSpace(alert.Dependency.Relationship),
		"ghsa_ids":              githubDependabotGHSAIDs(alert.SecurityAdvisory),
		"cve_ids":               githubDependabotCVEIDs(alert.SecurityAdvisory),
		"vulnerable_range":      strings.TrimSpace(alert.SecurityVulnerability.VulnerableVersionRange),
		"patched_version":       strings.TrimSpace(alert.SecurityVulnerability.FirstPatchedVersion.Identifier),
		"severity":              strings.ToLower(strings.TrimSpace(alert.SecurityAdvisory.Severity)),
		"cvss":                  githubDependabotCVSSPayload(alert.SecurityAdvisory.CVSS),
		"epss":                  githubDependabotEPSSPayload(alert.SecurityAdvisory.EPSS),
		"cwes":                  githubDependabotCWEPayload(alert.SecurityAdvisory.CWEs),
		"summary":               strings.TrimSpace(alert.SecurityAdvisory.Summary),
		"description":           strings.TrimSpace(alert.SecurityAdvisory.Description),
		"created_at":            strings.TrimSpace(alert.CreatedAt),
		"updated_at":            strings.TrimSpace(alert.UpdatedAt),
		"fixed_at":              strings.TrimSpace(alert.FixedAt),
		"dismissed_at":          strings.TrimSpace(alert.DismissedAt),
		"source_url":            sanitizeURL(alert.HTMLURL),
		"correlation_anchors":   githubDependabotCorrelationAnchors(providerAlertID, identity.PackageID, alert),
	}
	if err := mergeContractPayload(payload, func() (map[string]any, error) {
		return factschema.EncodeSecurityAlertRepositoryAlert(securityalertv1.RepositoryAlert{
			RepositoryID:        repositoryID,
			Provider:            stringPtr(ProviderGitHubDependabot),
			ProviderAlertID:     stringPtr(providerAlertID),
			ProviderAlertNumber: int64Ptr(int64(alert.Number)),
			ProviderState:       stringPtr(strings.TrimSpace(alert.State)),
			PackageID:           stringPtr(identity.PackageID),
			Ecosystem:           stringPtr(string(identity.Ecosystem)),
			PackageName:         stringPtr(identity.NormalizedName),
			ManifestPath:        stringPtr(strings.TrimSpace(alert.Dependency.ManifestPath)),
			DependencyScope:     stringPtr(strings.TrimSpace(alert.Dependency.Scope)),
			Relationship:        stringPtr(strings.TrimSpace(alert.Dependency.Relationship)),
			GHSAIDs:             githubDependabotGHSAIDs(alert.SecurityAdvisory),
			CVEIDs:              githubDependabotCVEIDs(alert.SecurityAdvisory),
			VulnerableRange:     stringPtr(strings.TrimSpace(alert.SecurityVulnerability.VulnerableVersionRange)),
			PatchedVersion:      stringPtr(strings.TrimSpace(alert.SecurityVulnerability.FirstPatchedVersion.Identifier)),
			Severity:            stringPtr(strings.ToLower(strings.TrimSpace(alert.SecurityAdvisory.Severity))),
			CVSS:                githubDependabotCVSSPayload(alert.SecurityAdvisory.CVSS),
			EPSS:                githubDependabotEPSSPayload(alert.SecurityAdvisory.EPSS),
			CWEs:                githubDependabotCWEPayload(alert.SecurityAdvisory.CWEs),
			Summary:             stringPtr(strings.TrimSpace(alert.SecurityAdvisory.Summary)),
			Description:         stringPtr(strings.TrimSpace(alert.SecurityAdvisory.Description)),
			CreatedAt:           stringPtr(strings.TrimSpace(alert.CreatedAt)),
			UpdatedAt:           stringPtr(strings.TrimSpace(alert.UpdatedAt)),
			FixedAt:             stringPtr(strings.TrimSpace(alert.FixedAt)),
			DismissedAt:         stringPtr(strings.TrimSpace(alert.DismissedAt)),
			SourceURL:           stringPtr(sanitizeURL(alert.HTMLURL)),
			CorrelationAnchors:  githubDependabotCorrelationAnchors(providerAlertID, identity.PackageID, alert),
			CollectorInstanceID: stringPtr(ctx.CollectorInstanceID),
		})
	}); err != nil {
		return collector.Fact{}, err
	}
	return collector.Fact{
		Kind:             KindRepositoryAlert,
		SchemaVersion:    SchemaVersionV1,
		StableKey:        stableFactKey,
		SourceConfidence: collector.SourceConfidenceReported,
		ObservedAt:       normalizedObservedAt(ctx.ObservedAt),
		Payload:          payload,
		SourceRef: collector.SourceRef{
			SourceSystem: CollectorKind,
			ScopeID:      ctx.ScopeID,
			GenerationID: ctx.GenerationID,
			FactKey:      stableFactKey,
			URI:          sanitizeURL(ctx.SourceURI),
			RecordID:     providerAlertID,
		},
	}, nil
}

func validateEnvelopeContext(ctx EnvelopeContext) error {
	if strings.TrimSpace(ctx.ScopeID) == "" {
		return fmt.Errorf("security alert envelope scope_id must not be blank")
	}
	if strings.TrimSpace(ctx.GenerationID) == "" {
		return fmt.Errorf("security alert envelope generation_id must not be blank")
	}
	if strings.TrimSpace(ctx.CollectorInstanceID) == "" {
		return fmt.Errorf("security alert envelope collector_instance_id must not be blank")
	}
	return nil
}

func packageIdentityFromDependabot(alert GitHubDependabotAlert) (Identity, error) {
	pkg := alert.Dependency.Package
	if strings.TrimSpace(pkg.Name) == "" {
		pkg = alert.SecurityVulnerability.Package
	}
	ecosystem := NormalizeEcosystem(Ecosystem(pkg.Ecosystem))
	if ecosystem == "" {
		return Identity{}, fmt.Errorf("github dependabot package ecosystem %q is unsupported", pkg.Ecosystem)
	}
	name := strings.TrimSpace(pkg.Name)
	namespace := ""
	if ecosystem == EcosystemMaven && strings.Contains(name, ":") {
		namespace, name, _ = strings.Cut(name, ":")
	}
	identity, err := Normalize(RawIdentity{
		Ecosystem: ecosystem,
		Registry:  defaultRegistryForEcosystem(ecosystem),
		RawName:   name,
		Namespace: namespace,
	})
	if err != nil {
		return Identity{}, fmt.Errorf("normalize github dependabot package: %w", err)
	}
	return identity, nil
}

func defaultRegistryForEcosystem(ecosystem Ecosystem) string {
	switch ecosystem {
	case EcosystemNPM:
		return "registry.npmjs.org"
	case EcosystemPyPI:
		return "pypi.org/simple"
	case EcosystemGoModule:
		return "proxy.golang.org"
	case EcosystemMaven:
		return "repo.maven.apache.org/maven2"
	case EcosystemNuGet:
		return "api.nuget.org/v3/index.json"
	case EcosystemComposer:
		return "repo.packagist.org"
	case EcosystemRubyGems:
		return "rubygems.org"
	case EcosystemCargo:
		return "crates.io"
	default:
		return "unknown"
	}
}

func githubDependabotAlertID(scopeID string, number int) string {
	return strings.Join([]string{
		ProviderGitHubDependabot,
		strings.TrimSpace(scopeID),
		strconv.Itoa(number),
	}, ":")
}

func githubDependabotGHSAIDs(advisory GitHubDependabotSecurityAdvisory) []string {
	ids := []string{advisory.GHSAID}
	for _, identifier := range advisory.Identifiers {
		if strings.EqualFold(identifier.Type, "GHSA") {
			ids = append(ids, identifier.Value)
		}
	}
	return cleanStrings(ids)
}

func githubDependabotCVEIDs(advisory GitHubDependabotSecurityAdvisory) []string {
	ids := []string{advisory.CVEID}
	for _, identifier := range advisory.Identifiers {
		if strings.EqualFold(identifier.Type, "CVE") {
			ids = append(ids, identifier.Value)
		}
	}
	return cleanStrings(ids)
}

func githubDependabotCVSSPayload(cvss GitHubDependabotCVSS) map[string]any {
	payload := map[string]any{}
	if cvss.Score != 0 {
		payload["score"] = cvss.Score
	}
	if vector := strings.TrimSpace(cvss.Vector); vector != "" {
		payload["vector"] = vector
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func githubDependabotEPSSPayload(epss GitHubDependabotEPSS) map[string]string {
	payload := map[string]string{}
	if percentage := anyString(epss.Percentage); percentage != "" {
		payload["percentage"] = percentage
	}
	if percentile := anyString(epss.Percentile); percentile != "" {
		payload["percentile"] = percentile
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func githubDependabotCWEPayload(cwes []GitHubDependabotCWE) []map[string]string {
	out := make([]map[string]string, 0, len(cwes))
	seen := make(map[string]struct{}, len(cwes))
	for _, cwe := range cwes {
		cweID := strings.TrimSpace(cwe.CWEID)
		if cweID == "" {
			continue
		}
		if _, ok := seen[cweID]; ok {
			continue
		}
		seen[cweID] = struct{}{}
		out = append(out, map[string]string{
			"cwe_id": cweID,
			"name":   strings.TrimSpace(cwe.Name),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func githubDependabotCorrelationAnchors(
	providerAlertID string,
	packageID string,
	alert GitHubDependabotAlert,
) []string {
	anchors := []string{providerAlertID, packageID}
	anchors = append(anchors, githubDependabotGHSAIDs(alert.SecurityAdvisory)...)
	anchors = append(anchors, githubDependabotCVEIDs(alert.SecurityAdvisory)...)
	return cleanStrings(anchors)
}

// mergeContractPayload merges the SDK-encoded contract payload into the
// producer payload. Producer-computed keys win on conflict, matching the
// in-tree census.
func mergeContractPayload(payload map[string]any, encode func() (map[string]any, error)) error {
	encoded, err := encode()
	if err != nil {
		return err
	}
	for key, value := range encoded {
		if _, exists := payload[key]; !exists {
			payload[key] = value
		}
	}
	return nil
}

func stringPtr(value string) *string {
	return &value
}

func int64Ptr(value int64) *int64 {
	return &value
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return out
}

func anyString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func normalizedObservedAt(observedAt time.Time) time.Time {
	if observedAt.IsZero() {
		return time.Now().UTC()
	}
	return observedAt.UTC()
}
