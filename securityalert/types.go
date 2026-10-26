// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import "time"

// CollectorKind is the durable collector family name for provider security
// alert facts. It matches scope.CollectorSecurityAlert in eshu-hq/eshu and
// the manifest-declared collector kind the producer grant scope must equal
// at admission.
const CollectorKind = "security_alert"

// ProviderGitHubDependabot is the only provider this producer collects.
const ProviderGitHubDependabot = "github_dependabot"

// Scope values a target may carry.
const (
	// TargetScopeRepository polls one allowlisted repository.
	TargetScopeRepository = "repository"
	// TargetScopeOrganization polls one organization and fans out
	// per-repository facts.
	TargetScopeOrganization = "org"
)

// AuthMode values a target may carry.
const (
	// AuthModeTokenEnv uses the static token resolved once at startup.
	AuthModeTokenEnv = "token_env"
	// AuthModeGitHubApp mints an installation token per claim through the
	// host-supplied TokenProvider.
	AuthModeGitHubApp = "github_app"
	// AuthModeHostMinted spends the host-minted token the satellite receives
	// per claim over stdio. It is a static bearer like AuthModeTokenEnv at
	// the provider layer; only the delivery differs (per-claim host stanza
	// instead of a process-environment variable), so the two shapes never
	// mix with token_env or github_app references on one target.
	AuthModeHostMinted = "host_minted"
)

// EnvelopeContext carries the fact boundary fields for one provider
// security-alert observation. ScopeID is the committed generation scope
// the envelope belongs to; RepositoryID, when non-empty (org-wide
// targets), carries the per-repository scope used for payload
// repository_id and stable-fact-key dedup.
type EnvelopeContext struct {
	ScopeID             string
	RepositoryID        string
	GenerationID        string
	CollectorInstanceID string
	FencingToken        int64
	ObservedAt          time.Time
	SourceURI           string
}

// GitHubDependabotAlert is the GitHub Dependabot alert API subset normalized
// by this producer.
type GitHubDependabotAlert struct {
	Number                int                                   `json:"number"`
	State                 string                                `json:"state"`
	Dependency            GitHubDependabotDependency            `json:"dependency"`
	SecurityAdvisory      GitHubDependabotSecurityAdvisory      `json:"security_advisory"`
	SecurityVulnerability GitHubDependabotSecurityVulnerability `json:"security_vulnerability"`
	HTMLURL               string                                `json:"html_url"`
	CreatedAt             string                                `json:"created_at"`
	UpdatedAt             string                                `json:"updated_at"`
	FixedAt               string                                `json:"fixed_at"`
	DismissedAt           string                                `json:"dismissed_at"`
	Repository            GitHubDependabotRepository            `json:"repository"`
}

// GitHubDependabotRepository identifies the repository an alert belongs to.
// It is populated by the organization-wide alerts endpoint so a single org
// request can fan out into per-repository facts.
type GitHubDependabotRepository struct {
	FullName string                          `json:"full_name"`
	Name     string                          `json:"name"`
	Owner    GitHubDependabotRepositoryOwner `json:"owner"`
}

// GitHubDependabotRepositoryOwner is the owner login embedded in an
// organization alert's repository object.
type GitHubDependabotRepositoryOwner struct {
	Login string `json:"login"`
}

// GitHubDependabotDependency identifies the repository-local dependency that
// triggered a Dependabot alert.
type GitHubDependabotDependency struct {
	Package      GitHubDependabotPackage `json:"package"`
	ManifestPath string                  `json:"manifest_path"`
	Scope        string                  `json:"scope"`
	Relationship string                  `json:"relationship"`
}

// GitHubDependabotPackage identifies one provider-reported package.
type GitHubDependabotPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// GitHubDependabotSecurityAdvisory is the advisory summary embedded in a
// Dependabot alert.
type GitHubDependabotSecurityAdvisory struct {
	GHSAID      string                       `json:"ghsa_id"`
	CVEID       string                       `json:"cve_id"`
	Identifiers []GitHubDependabotIdentifier `json:"identifiers"`
	Summary     string                       `json:"summary"`
	Description string                       `json:"description"`
	Severity    string                       `json:"severity"`
	CVSS        GitHubDependabotCVSS         `json:"cvss"`
	EPSS        GitHubDependabotEPSS         `json:"epss"`
	CWEs        []GitHubDependabotCWE        `json:"cwes"`
}

// GitHubDependabotIdentifier is one advisory identifier such as GHSA or CVE.
type GitHubDependabotIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// GitHubDependabotCVSS is the source-reported CVSS summary.
type GitHubDependabotCVSS struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector_string"`
}

// GitHubDependabotEPSS is the source-reported EPSS summary.
type GitHubDependabotEPSS struct {
	Percentage any `json:"percentage"`
	Percentile any `json:"percentile"`
}

// GitHubDependabotCWE is one source-reported CWE summary.
type GitHubDependabotCWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

// GitHubDependabotSecurityVulnerability carries affected range and fixed
// version detail for one alert.
type GitHubDependabotSecurityVulnerability struct {
	Package                GitHubDependabotPackage `json:"package"`
	VulnerableVersionRange string                  `json:"vulnerable_version_range"`
	FirstPatchedVersion    GitHubDependabotVersion `json:"first_patched_version"`
}

// GitHubDependabotVersion identifies the first provider-reported patched
// version when one is available.
type GitHubDependabotVersion struct {
	Identifier string `json:"identifier"`
}

// GitHubRateLimitInfo captures bounded GitHub rate-limit retry metadata.
type GitHubRateLimitInfo struct {
	Remaining      int
	RemainingKnown bool
	Reset          time.Time
	RetryAfter     time.Duration
}

// GitHubDependabotAlertResult is one bounded provider alert fetch result.
type GitHubDependabotAlertResult struct {
	Alerts       []GitHubDependabotAlert
	PagesFetched int
	Truncated    bool
	ObservedAt   time.Time
	RateLimit    GitHubRateLimitInfo
}
