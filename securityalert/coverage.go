// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Collection coverage and freshness, ported from the in-tree alertruntime
// census. The coverage annotation rides on every emitted fact; the
// freshness digest feeds the Result generation so the host can skip
// unchanged generations.

const (
	securityAlertSourceFreshnessActive  = "active"
	securityAlertSourceFreshnessPartial = "partial"

	collectionCoverageComplete   = "complete"
	collectionCoverageIncomplete = "incomplete"

	collectionOpenAlertStateFilter       = githubDependabotOpenAlertState
	collectionOpenPageLimitReachedReason = "provider_open_alert_page_limit_reached"
)

// repositoryAlertCollectionCoverage is the provider-read coverage stamped
// onto every fact of one repository. extraReasons carries org fan-out
// reasons on top of the page-limit reason; it is set only on truncated
// coverage.
type repositoryAlertCollectionCoverage struct {
	pagesFetched int
	truncated    bool
	extraReasons []string
}

// alertCollection is the merged provider read for one claimed target.
type alertCollection struct {
	alerts             []GitHubDependabotAlert
	observedAt         time.Time
	pagesFetched       int
	truncated          bool
	coverage           repositoryAlertCollectionCoverage
	repositoryCoverage map[string]repositoryAlertCollectionCoverage
	fanoutOutcomes     map[string]string
}

// singleReadCollection wraps one bounded provider read without fan-out.
func singleReadCollection(result GitHubDependabotAlertResult) alertCollection {
	coverage := repositoryAlertCollectionCoverageFromResult(result)
	return alertCollection{
		alerts:       result.Alerts,
		observedAt:   result.ObservedAt,
		pagesFetched: result.PagesFetched,
		truncated:    result.Truncated,
		coverage:     coverage,
	}
}

// coverageFor returns the coverage that applies to one alert's facts.
func (c alertCollection) coverageFor(alert GitHubDependabotAlert) repositoryAlertCollectionCoverage {
	if c.repositoryCoverage != nil {
		if coverage, ok := c.repositoryCoverage[normalizeOrganizationAlertRepositoryFullName(alert)]; ok {
			return coverage
		}
	}
	return c.coverage
}

func repositoryAlertCollectionCoverageFromResult(
	result GitHubDependabotAlertResult,
) repositoryAlertCollectionCoverage {
	pagesFetched := result.PagesFetched
	if pagesFetched <= 0 && len(result.Alerts) > 0 {
		pagesFetched = 1
	}
	return repositoryAlertCollectionCoverage{
		pagesFetched: pagesFetched,
		truncated:    result.Truncated,
	}
}

func annotateRepositoryAlertCollectionCoverage(
	payload map[string]any,
	coverage repositoryAlertCollectionCoverage,
) {
	payload["source_freshness"] = coverage.sourceFreshness()
	payload["collection_coverage_state"] = coverage.coverageState()
	payload["collection_truncated"] = coverage.truncated
	payload["collection_pages_fetched"] = int64(coverage.pagesFetched)
	payload["collection_state_filter"] = collectionOpenAlertStateFilter
	if reasons := coverage.incompleteReasons(); len(reasons) > 0 {
		payload["collection_incomplete_reasons"] = reasons
	}
}

func (c repositoryAlertCollectionCoverage) sourceFreshness() string {
	if c.truncated {
		return securityAlertSourceFreshnessPartial
	}
	return securityAlertSourceFreshnessActive
}

func (c repositoryAlertCollectionCoverage) coverageState() string {
	if c.truncated {
		return collectionCoverageIncomplete
	}
	return collectionCoverageComplete
}

func (c repositoryAlertCollectionCoverage) incompleteReasons() []string {
	if !c.truncated {
		return nil
	}
	return []string{collectionOpenPageLimitReachedReason}
}

// securityAlertFreshnessInput is the provider truth a freshness digest covers.
type securityAlertFreshnessInput struct {
	alerts         []GitHubDependabotAlert
	pagesFetched   int
	truncated      bool
	fanoutOutcomes map[string]string
	targetSetHash  string
}

type securityAlertFreshnessSnapshot struct {
	Repository             string                              `json:"repository,omitempty"`
	Number                 int                                 `json:"number"`
	State                  string                              `json:"state"`
	Ecosystem              string                              `json:"ecosystem"`
	PackageName            string                              `json:"package_name"`
	ManifestPath           string                              `json:"manifest_path"`
	DependencyScope        string                              `json:"dependency_scope"`
	Relationship           string                              `json:"relationship"`
	GHSAIDs                []string                            `json:"ghsa_ids"`
	CVEIDs                 []string                            `json:"cve_ids"`
	VulnerableVersionRange string                              `json:"vulnerable_version_range"`
	FirstPatchedVersion    string                              `json:"first_patched_version"`
	Severity               string                              `json:"severity"`
	CVSSVector             string                              `json:"cvss_vector"`
	CVSSScore              float64                             `json:"cvss_score"`
	EPSSPercentage         string                              `json:"epss_percentage"`
	EPSSPercentile         string                              `json:"epss_percentile"`
	CWEs                   []securityAlertFreshnessCWESnapshot `json:"cwes"`
	CreatedAt              string                              `json:"created_at"`
	UpdatedAt              string                              `json:"updated_at"`
	FixedAt                string                              `json:"fixed_at"`
	DismissedAt            string                              `json:"dismissed_at"`
}

type securityAlertFreshnessCWESnapshot struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

func securityAlertFreshnessHint(input securityAlertFreshnessInput) string {
	snapshots := make([]securityAlertFreshnessSnapshot, 0, len(input.alerts))
	for _, alert := range input.alerts {
		snapshots = append(snapshots, securityAlertSnapshot(alert))
	}
	slices.SortFunc(snapshots, func(a, b securityAlertFreshnessSnapshot) int {
		if cmp := strings.Compare(a.Repository, b.Repository); cmp != 0 {
			return cmp
		}
		if a.Number != b.Number {
			return cmp.Compare(a.Number, b.Number)
		}
		if cmp := strings.Compare(a.PackageName, b.PackageName); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.ManifestPath, b.ManifestPath)
	})
	digest := map[string]any{
		"alerts":        snapshots,
		"pages_fetched": input.pagesFetched,
		"truncated":     input.truncated,
	}
	if len(input.fanoutOutcomes) > 0 {
		digest["org_fanout"] = input.fanoutOutcomes
	}
	if input.targetSetHash != "" {
		digest["target_set"] = input.targetSetHash
	}
	raw, err := json.Marshal(digest)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func securityAlertSnapshot(alert GitHubDependabotAlert) securityAlertFreshnessSnapshot {
	pkg := alert.Dependency.Package
	if strings.TrimSpace(pkg.Name) == "" {
		pkg = alert.SecurityVulnerability.Package
	}
	return securityAlertFreshnessSnapshot{
		Repository:             normalizeOrganizationAlertRepositoryFullName(alert),
		Number:                 alert.Number,
		State:                  strings.TrimSpace(alert.State),
		Ecosystem:              strings.TrimSpace(pkg.Ecosystem),
		PackageName:            strings.TrimSpace(pkg.Name),
		ManifestPath:           strings.TrimSpace(alert.Dependency.ManifestPath),
		DependencyScope:        strings.TrimSpace(alert.Dependency.Scope),
		Relationship:           strings.TrimSpace(alert.Dependency.Relationship),
		GHSAIDs:                securityAlertIdentifierValues(alert.SecurityAdvisory, "GHSA"),
		CVEIDs:                 securityAlertIdentifierValues(alert.SecurityAdvisory, "CVE"),
		VulnerableVersionRange: strings.TrimSpace(alert.SecurityVulnerability.VulnerableVersionRange),
		FirstPatchedVersion:    strings.TrimSpace(alert.SecurityVulnerability.FirstPatchedVersion.Identifier),
		Severity:               strings.ToLower(strings.TrimSpace(alert.SecurityAdvisory.Severity)),
		CVSSVector:             strings.TrimSpace(alert.SecurityAdvisory.CVSS.Vector),
		CVSSScore:              alert.SecurityAdvisory.CVSS.Score,
		EPSSPercentage:         securityAlertAnyString(alert.SecurityAdvisory.EPSS.Percentage),
		EPSSPercentile:         securityAlertAnyString(alert.SecurityAdvisory.EPSS.Percentile),
		CWEs:                   securityAlertCWESnapshot(alert.SecurityAdvisory.CWEs),
		CreatedAt:              strings.TrimSpace(alert.CreatedAt),
		UpdatedAt:              strings.TrimSpace(alert.UpdatedAt),
		FixedAt:                strings.TrimSpace(alert.FixedAt),
		DismissedAt:            strings.TrimSpace(alert.DismissedAt),
	}
}

func securityAlertIdentifierValues(
	advisory GitHubDependabotSecurityAdvisory,
	identifierType string,
) []string {
	values := make([]string, 0, 1+len(advisory.Identifiers))
	switch strings.ToUpper(strings.TrimSpace(identifierType)) {
	case "GHSA":
		values = append(values, advisory.GHSAID)
	case "CVE":
		values = append(values, advisory.CVEID)
	}
	for _, identifier := range advisory.Identifiers {
		if strings.EqualFold(identifier.Type, identifierType) {
			values = append(values, identifier.Value)
		}
	}
	return cleanFreshnessStrings(values)
}

func securityAlertCWESnapshot(cwes []GitHubDependabotCWE) []securityAlertFreshnessCWESnapshot {
	snapshots := make([]securityAlertFreshnessCWESnapshot, 0, len(cwes))
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
		snapshots = append(snapshots, securityAlertFreshnessCWESnapshot{
			CWEID: cweID,
			Name:  strings.TrimSpace(cwe.Name),
		})
	}
	slices.SortFunc(snapshots, func(a, b securityAlertFreshnessCWESnapshot) int {
		return strings.Compare(a.CWEID, b.CWEID)
	})
	return snapshots
}

func cleanFreshnessStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
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
		cleaned = append(cleaned, value)
	}
	slices.Sort(cleaned)
	return cleaned
}

func securityAlertAnyString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}
