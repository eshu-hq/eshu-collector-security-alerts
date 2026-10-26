// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Golden vectors generated from the in-tree
// NewGitHubDependabotAlertEnvelope for the canonical fixture alert
// (security-alert:github:example-org/example-repo, alert 42,
// generation-9). The port must reproduce the stable key and the wire
// payload byte-for-byte; any divergence fails here, not in production.
const (
	goldenStableKey = "b670abea59577b18bca99651ad8f3da352c97d7afa2ae19970d19fcf3273ec4d"
	goldenPayload   = `{"collector_instance_id":"collector-security-alerts","correlation_anchors":["CVE-2026-0001","GHSA-abcd-1234","github_dependabot:security-alert:github:example-org/example-repo:42","npm://registry.npmjs.org/@scope/left-pad"],"created_at":"2026-05-20T12:00:00Z","cve_ids":["CVE-2026-0001"],"cvss":{"score":9.8,"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},"cwes":[{"cwe_id":"CWE-79","name":"Cross-site Scripting"}],"dependency_scope":"runtime","description":"Synthetic advisory description","dismissed_at":"","ecosystem":"npm","epss":{"percentage":"0.721","percentile":"0.981"},"fixed_at":"","ghsa_ids":["GHSA-abcd-1234"],"manifest_path":"package-lock.json","package_id":"npm://registry.npmjs.org/@scope/left-pad","package_name":"@scope/left-pad","patched_version":"1.2.3","provider":"github_dependabot","provider_alert_id":"github_dependabot:security-alert:github:example-org/example-repo:42","provider_alert_number":42,"provider_state":"open","relationship":"direct","repository_id":"security-alert:github:example-org/example-repo","severity":"critical","source_url":"https://github.com/example-org/example-repo/security/dependabot/42","summary":"Synthetic advisory","updated_at":"2026-05-23T10:15:00Z","vulnerable_range":"\u003c1.2.3"}`
)

func goldenFixtureContext() EnvelopeContext {
	return EnvelopeContext{
		ScopeID:             "security-alert:github:example-org/example-repo",
		GenerationID:        "security-alert:generation-9",
		CollectorInstanceID: "collector-security-alerts",
		ObservedAt:          time.Date(2026, 5, 16, 11, 0, 0, 0, time.UTC),
		SourceURI:           "https://api.github.com/repos/example-org/example-repo/dependabot/alerts",
	}
}

func goldenFixtureAlert() GitHubDependabotAlert {
	return GitHubDependabotAlert{
		Number:    42,
		State:     "open",
		HTMLURL:   "https://github.com/example-org/example-repo/security/dependabot/42",
		CreatedAt: "2026-05-20T12:00:00Z",
		UpdatedAt: "2026-05-23T10:15:00Z",
		Dependency: GitHubDependabotDependency{
			ManifestPath: "package-lock.json",
			Scope:        "runtime",
			Package:      GitHubDependabotPackage{Ecosystem: "npm", Name: "@scope/left-pad"},
			Relationship: "direct",
		},
		SecurityAdvisory: GitHubDependabotSecurityAdvisory{
			GHSAID:      "GHSA-abcd-1234",
			CVEID:       "CVE-2026-0001",
			Summary:     "Synthetic advisory",
			Description: "Synthetic advisory description",
			Severity:    "critical",
			CVSS:        GitHubDependabotCVSS{Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			EPSS:        GitHubDependabotEPSS{Percentage: "0.721", Percentile: "0.981"},
			CWEs:        []GitHubDependabotCWE{{CWEID: "CWE-79", Name: "Cross-site Scripting"}},
		},
		SecurityVulnerability: GitHubDependabotSecurityVulnerability{
			VulnerableVersionRange: "<1.2.3",
			FirstPatchedVersion:    GitHubDependabotVersion{Identifier: "1.2.3"},
			Package:                GitHubDependabotPackage{Ecosystem: "npm", Name: "@scope/left-pad"},
		},
	}
}

func TestGoldenStableKeyAndPayload(t *testing.T) {
	t.Parallel()

	fact, err := NewRepositoryAlertFact(goldenFixtureContext(), goldenFixtureAlert())
	if err != nil {
		t.Fatalf("NewRepositoryAlertFact() error = %v, want nil", err)
	}
	if fact.StableKey != goldenStableKey {
		t.Errorf("StableKey = %q, want golden %q", fact.StableKey, goldenStableKey)
	}
	raw, err := json.Marshal(fact.Payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if string(raw) != goldenPayload {
		t.Errorf("payload wire bytes differ from golden vector:\n got: %s\nwant: %s", raw, goldenPayload)
	}
	if fact.Kind != KindRepositoryAlert {
		t.Errorf("Kind = %q, want %q", fact.Kind, KindRepositoryAlert)
	}
	if fact.SchemaVersion != SchemaVersionV1 {
		t.Errorf("SchemaVersion = %q, want %q", fact.SchemaVersion, SchemaVersionV1)
	}
}

func TestGoldenStableKeySurvivesGenerationRebind(t *testing.T) {
	t.Parallel()

	first, err := NewRepositoryAlertFact(goldenFixtureContext(), goldenFixtureAlert())
	if err != nil {
		t.Fatalf("NewRepositoryAlertFact() error = %v, want nil", err)
	}
	rebound := goldenFixtureContext()
	rebound.GenerationID = "security-alert:generation-10"
	second, err := NewRepositoryAlertFact(rebound, goldenFixtureAlert())
	if err != nil {
		t.Fatalf("NewRepositoryAlertFact(rebound) error = %v, want nil", err)
	}
	if first.StableKey != second.StableKey {
		t.Errorf("StableKey changed across generations: %q vs %q", first.StableKey, second.StableKey)
	}
	if second.SourceRef.GenerationID != rebound.GenerationID {
		t.Errorf("SourceRef.GenerationID = %q, want rebound %q", second.SourceRef.GenerationID, rebound.GenerationID)
	}
	if !strings.Contains(second.SourceRef.FactKey, first.StableKey) && second.SourceRef.FactKey != first.StableKey {
		t.Errorf("SourceRef.FactKey = %q, want stable key %q", second.SourceRef.FactKey, first.StableKey)
	}
}
