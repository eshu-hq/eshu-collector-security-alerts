// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/eshu-hq/eshu-sdk/collector/transport"
)

func defaultClientFactory(target TargetConfig) (RepositoryAlertClient, error) {
	return NewGitHubDependabotClient(GitHubDependabotClientConfig{
		BaseURL:              target.APIBaseURL,
		Token:                target.Token,
		AllowedRepositories:  target.AllowedRepositories,
		RepositoryAlertLimit: target.RepositoryAlertLimit,
		AppAuth:              target.AuthMode == AuthModeGitHubApp,
		TokenProvider:        target.TokenProvider,
	}), nil
}

// classifiedProviderFailure maps a source error onto the host claim
// disposition vocabulary. Terminal classes fail the claim; retryable
// classes release it for a bounded retry.
func classifiedProviderFailure(err error) transport.ProviderFailure {
	var providerErr GitHubDependabotError
	if isProviderError(err, &providerErr) {
		class := providerErr.FailureClass()
		terminal := providerErr.TerminalFailure()
		return transport.NewProviderFailure(
			ProviderGitHubDependabot, transportFailureClass(class), terminal, err,
		).WithOperation(providerErr.FailureOperation())
	}
	return transport.ClassifyProviderFailure(
		ProviderGitHubDependabot, err,
		transport.StatusPolicy{
			AuthDeniedClass: transport.FailureAuthDenied,
			NotFoundClass:   transport.FailureTerminal,
		},
		transport.FailureRetryable,
	)
}

func providerFailureClass(err error) string {
	var providerErr GitHubDependabotError
	if isProviderError(err, &providerErr) {
		return providerErr.FailureClass()
	}
	return GitHubDependabotFailureRetryable
}

func isProviderError(err error, target *GitHubDependabotError) bool {
	for err != nil {
		if e, ok := err.(GitHubDependabotError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func transportFailureClass(class string) transport.FailureClass {
	switch class {
	case GitHubDependabotFailureAuthDenied:
		return transport.FailureAuthDenied
	case GitHubDependabotFailureNotFound:
		return transport.FailureNotFound
	case GitHubDependabotFailureRateLimited:
		return transport.FailureRateLimited
	case GitHubDependabotFailureTerminal:
		return transport.FailureTerminal
	default:
		return transport.FailureRetryable
	}
}

// validateTarget normalizes and validates one target. A half-configured
// credential or scope shape fails closed at construction, never at first
// claim.
func validateTarget(target TargetConfig) (TargetConfig, error) {
	target.Provider = strings.TrimSpace(target.Provider)
	if target.Provider == "" {
		target.Provider = ProviderGitHubDependabot
	}
	target.Scope = strings.TrimSpace(target.Scope)
	if target.Scope == "" {
		target.Scope = TargetScopeRepository
	}
	target.ScopeID = strings.TrimSpace(target.ScopeID)
	target.Repository = normalizeRepository(target.Repository)
	target.Organization = normalizeOrganization(target.Organization)
	target.Token = strings.TrimSpace(target.Token)
	target.AuthMode = strings.ToLower(strings.TrimSpace(target.AuthMode))
	if target.AuthMode == "" {
		target.AuthMode = AuthModeTokenEnv
	}
	target.GitHubAppID = strings.TrimSpace(target.GitHubAppID)
	target.GitHubAppInstallationID = strings.TrimSpace(target.GitHubAppInstallationID)
	target.GitHubAppPrivateKey = strings.TrimSpace(target.GitHubAppPrivateKey)
	target.APIBaseURL = strings.TrimRight(strings.TrimSpace(target.APIBaseURL), "/")
	target.SourceURI = strings.TrimSpace(target.SourceURI)
	target.AllowedRepositories = cleanRepositories(target.AllowedRepositories)
	if target.Provider != ProviderGitHubDependabot {
		if target.Provider == "" {
			return TargetConfig{}, fmt.Errorf("provider is required")
		}
		return TargetConfig{}, fmt.Errorf("unsupported security alert provider %q", target.Provider)
	}
	if target.ScopeID == "" {
		return TargetConfig{}, fmt.Errorf("scope_id is required")
	}
	if strings.Contains(target.ScopeID, shardMarker) {
		// Shard expansion is host-owned after extraction; a marker scope_id
		// names a host plan, not a configured target.
		return TargetConfig{}, fmt.Errorf("scope_id must not contain the reserved %q marker", shardMarker)
	}
	if strings.Contains(target.ScopeID, retirementMarker) {
		return TargetConfig{}, fmt.Errorf("scope_id must not contain the reserved %q marker", retirementMarker)
	}
	switch target.AuthMode {
	case AuthModeTokenEnv:
		if target.Token == "" {
			return TargetConfig{}, fmt.Errorf("token is required")
		}
		if target.GitHubAppID != "" || target.GitHubAppInstallationID != "" || target.GitHubAppPrivateKey != "" {
			return TargetConfig{}, fmt.Errorf("github_app credentials must be empty when auth_mode is %q", AuthModeTokenEnv)
		}
	case AuthModeGitHubApp:
		if target.Token != "" {
			return TargetConfig{}, fmt.Errorf("token must be empty when auth_mode is %q", AuthModeGitHubApp)
		}
		if target.GitHubAppID == "" {
			return TargetConfig{}, fmt.Errorf("github_app_id is required when auth_mode is %q", AuthModeGitHubApp)
		}
		if target.GitHubAppInstallationID == "" {
			return TargetConfig{}, fmt.Errorf("github_app_installation_id is required when auth_mode is %q", AuthModeGitHubApp)
		}
		if target.GitHubAppPrivateKey == "" {
			return TargetConfig{}, fmt.Errorf("github_app_private_key is required when auth_mode is %q", AuthModeGitHubApp)
		}
		if target.TokenProvider == nil {
			return TargetConfig{}, fmt.Errorf("token_provider is required when auth_mode is %q", AuthModeGitHubApp)
		}
	default:
		return TargetConfig{}, fmt.Errorf("unsupported security alert auth_mode %q", target.AuthMode)
	}
	switch target.Scope {
	case TargetScopeRepository:
		if target.Organization != "" {
			return TargetConfig{}, fmt.Errorf("organization must be empty for repository scope")
		}
		if target.Repository == "" {
			return TargetConfig{}, fmt.Errorf("repository must be owner/name")
		}
		if len(target.AllowedRepositories) == 0 {
			return TargetConfig{}, fmt.Errorf("allowed_repositories is required")
		}
		if !repositoryAllowed(target.Repository, target.AllowedRepositories) {
			return TargetConfig{}, fmt.Errorf("repository must be listed in allowed_repositories")
		}
	case TargetScopeOrganization:
		if target.Organization == "" {
			return TargetConfig{}, fmt.Errorf("organization is required for org scope")
		}
		if target.Repository != "" {
			return TargetConfig{}, fmt.Errorf("repository must be empty for org scope")
		}
		if len(target.AllowedRepositories) == 0 {
			return TargetConfig{}, fmt.Errorf("allowed_repositories is required for org scope")
		}
	default:
		return TargetConfig{}, fmt.Errorf("unsupported security alert scope %q", target.Scope)
	}
	if target.RepositoryAlertLimit < 0 || target.RepositoryAlertLimit > 100 {
		return TargetConfig{}, fmt.Errorf("repository_alert_limit must be between 0 and 100")
	}
	if target.MaxPages <= 0 {
		target.MaxPages = 1
	}
	if target.MaxPages > 100 {
		return TargetConfig{}, fmt.Errorf("max_pages must be between 1 and 100")
	}
	if target.APIBaseURL != "" {
		if _, err := transport.ParseBaseURL("github dependabot", target.APIBaseURL); err != nil {
			return TargetConfig{}, fmt.Errorf("api_base_url is invalid")
		}
	}
	return target, nil
}

// organizationAlertScopeID derives the canonical per-repository security
// alert scope ID from an organization alert's repository object. It returns
// "" when the repository cannot be resolved.
func organizationAlertScopeID(alert GitHubDependabotAlert) string {
	fullName := normalizeOrganizationAlertRepositoryFullName(alert)
	if fullName == "" {
		return ""
	}
	return "security-alert:github:" + fullName
}

// organizationAlertFullName returns the normalized "owner/repo" full name
// for an organization alert. Used for allowlist filtering.
func organizationAlertFullName(alert GitHubDependabotAlert) string {
	return normalizeOrganizationAlertRepositoryFullName(alert)
}

// organizationAlertRepositoryName returns the short repository name for an
// organization alert, used to populate the repository_name payload field
// that the per-repository path leaves for the host to derive.
func organizationAlertRepositoryName(alert GitHubDependabotAlert) string {
	if name := strings.TrimSpace(alert.Repository.Name); name != "" {
		return name
	}
	fullName := normalizeOrganizationAlertRepositoryFullName(alert)
	if slash := strings.LastIndex(fullName, "/"); slash >= 0 && slash+1 < len(fullName) {
		return fullName[slash+1:]
	}
	return ""
}

func normalizeOrganizationAlertRepositoryFullName(alert GitHubDependabotAlert) string {
	fullName := strings.ToLower(strings.Trim(strings.TrimSpace(alert.Repository.FullName), "/"))
	if fullName != "" {
		if strings.Count(fullName, "/") == 1 {
			return fullName
		}
		return ""
	}
	owner := strings.ToLower(strings.TrimSpace(alert.Repository.Owner.Login))
	name := strings.ToLower(strings.TrimSpace(alert.Repository.Name))
	if owner == "" || name == "" {
		return ""
	}
	return owner + "/" + name
}

// organizationFanoutRepositories returns the allowlisted repositories owned
// by the target organization, in allowlist order. An allowlisted repository
// of another owner can never appear in this org's stream.
func organizationFanoutRepositories(target TargetConfig) []string {
	prefix := target.Organization + "/"
	repositories := make([]string, 0, len(target.AllowedRepositories))
	for _, repository := range target.AllowedRepositories {
		if strings.HasPrefix(repository, prefix) {
			repositories = append(repositories, repository)
		}
	}
	return repositories
}

// fanoutRepositoryObject builds the repository object stamped onto a
// per-repository fan-out alert from the normalized allowlist entry, because
// the per-repository endpoint returns no repository object. repository_id
// is lowercase on both paths, so stable keys match.
func fanoutRepositoryObject(repository string) GitHubDependabotRepository {
	owner, name, _ := strings.Cut(repository, "/")
	return GitHubDependabotRepository{
		FullName: repository,
		Name:     name,
		Owner:    GitHubDependabotRepositoryOwner{Login: owner},
	}
}

// fanoutFailureOutcome maps a failed per-repository read to its outcome and
// to the outcome later repositories record. Only failures specific to one
// repository let the fan-out continue: not_found, and a 403 the provider
// marked as alerts-disabled. A rate limit stops the fan-out as
// rate_limited. Any other class stops it as stopped, because the next read
// against the same credential and provider would most likely fail the same
// way.
func fanoutFailureOutcome(err error) (outcome string, stop string) {
	var providerErr GitHubDependabotError
	if isProviderError(err, &providerErr) {
		class := providerErr.FailureClass()
		if class == GitHubDependabotFailureNotFound && providerErr.AlertsDisabled {
			return fanoutOutcomeAlertsDisabled, ""
		}
		switch class {
		case GitHubDependabotFailureNotFound:
			return fanoutOutcomeFailed, ""
		case GitHubDependabotFailureRateLimited:
			return fanoutOutcomeRateLimited, fanoutOutcomeRateLimited
		default:
			return fanoutOutcomeFailed, fanoutOutcomeStopped
		}
	}
	return fanoutOutcomeFailed, fanoutOutcomeStopped
}

// fanoutOutcomeReason returns the incomplete reason for a repository the
// fan-out could not read, or "" when the repository's own read applies.
func fanoutOutcomeReason(outcome string) string {
	switch outcome {
	case fanoutOutcomeFailed:
		return "org_repository_read_failed"
	case fanoutOutcomeAlertsDisabled:
		return "org_repository_alerts_disabled"
	case fanoutOutcomeRateLimited:
		return "org_repository_read_rate_limited"
	case fanoutOutcomeSkippedCap:
		return "org_repository_fanout_cap_reached"
	case fanoutOutcomeStopped:
		return "org_repository_fanout_stopped"
	default:
		return ""
	}
}

// mergeFanoutAlerts merges per-repository reads with the org window. A
// repository's own read wins: its alerts are emitted first, and org-window
// alerts for a repository whose own read was complete are dropped because
// that read is the newer, whole truth for it. Org-window alerts of every
// other allowlisted repository are kept so a failed, rate-limited, or
// skipped read never loses facts the org window already held. Duplicates
// collapse on (repository, alert number), the same identity the stable key
// uses.
func mergeFanoutAlerts(
	target TargetConfig,
	repositories []string,
	reads map[string]GitHubDependabotAlertResult,
	outcomes map[string]string,
	orgAlerts []GitHubDependabotAlert,
) []GitHubDependabotAlert {
	type alertKey struct {
		repository string
		number     int
	}
	seen := map[alertKey]struct{}{}
	merged := make([]GitHubDependabotAlert, 0, len(orgAlerts))
	add := func(repository string, alert GitHubDependabotAlert) {
		key := alertKey{repository: repository, number: alert.Number}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		merged = append(merged, alert)
	}
	for _, repository := range repositories {
		read, ok := reads[repository]
		if !ok {
			continue
		}
		for _, alert := range read.Alerts {
			// The per-repository endpoint omits the repository object, so
			// stamp the requested repository: the envelope then derives the
			// same repository_id, and so the same stable key, as the org path.
			alert.Repository = fanoutRepositoryObject(repository)
			add(repository, alert)
		}
	}
	for _, alert := range orgAlerts {
		repository := normalizeOrganizationAlertRepositoryFullName(alert)
		if repository == "" || !target.RepositoryAllowed(repository) {
			continue
		}
		if outcomes[repository] == fanoutOutcomeComplete {
			continue
		}
		add(repository, alert)
	}
	return merged
}

// normalizeRepository normalizes one owner/name repository slug for config
// comparison. It lowercases and strips a .git suffix; anything else shaped
// is left for validation to reject.
func normalizeRepository(repository string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(repository), "/"), "/")
	if len(parts) != 2 {
		return strings.ToLower(strings.TrimSpace(repository))
	}
	owner := strings.ToLower(strings.TrimSpace(parts[0]))
	repo := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parts[1]), ".git"))
	if owner == "" || repo == "" {
		return ""
	}
	return owner + "/" + repo
}

func normalizeOrganization(organization string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(organization), "/"))
}

func cleanRepositories(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := normalizeRepositoryFullName(value); normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}

func repositoryAllowed(repository string, allowed []string) bool {
	repository = normalizeRepositoryFullName(repository)
	if repository == "" {
		return false
	}
	return slices.Contains(allowed, repository)
}

func readOperation(target TargetConfig) string {
	if target.IsOrganizationScope() {
		return dependabotOrganizationAlertsOperation
	}
	return dependabotRepositoryAlertsOperation
}

func safeSourceURI(raw string) string {
	return sanitizeURL(raw)
}

// targetSetHash hashes the canonical repository set the target collects:
// the repository of a repository target, or the organization's allowlisted
// repositories of an organization target. The JSON array is sorted and
// deduplicated, so equal sets hash equal; the freshness digest carries it so
// an allowlist change commits a new generation instead of being skipped as
// unchanged.
func targetSetHash(target TargetConfig) string {
	var slugs []string
	if target.IsOrganizationScope() {
		slugs = organizationFanoutRepositories(target)
	} else {
		slugs = []string{target.Repository}
	}
	canonical := make([]string, 0, len(slugs))
	for _, slug := range slugs {
		if slug = strings.TrimSpace(slug); slug != "" {
			canonical = append(canonical, slug)
		}
	}
	sort.Strings(canonical)
	canonical = slices.Compact(canonical)
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	if string(encoded) == "null" {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func securityAlertFreshnessInputFor(target TargetConfig, collection alertCollection) securityAlertFreshnessInput {
	return securityAlertFreshnessInput{
		alerts:         collection.alerts,
		pagesFetched:   collection.pagesFetched,
		truncated:      collection.truncated,
		fanoutOutcomes: collection.fanoutOutcomes,
		targetSetHash:  targetSetHash(target),
	}
}

// incompleteReasonSet collects the distinct incomplete reasons across the
// collection for the warning status count.
func (c alertCollection) incompleteReasonSet() []string {
	seen := map[string]struct{}{}
	var out []string
	if c.truncated && c.coverage.truncated {
		for _, reason := range c.coverage.incompleteReasons() {
			if _, ok := seen[reason]; !ok {
				seen[reason] = struct{}{}
				out = append(out, reason)
			}
		}
	}
	for repository, outcome := range c.fanoutOutcomes {
		_ = repository
		if reason := fanoutOutcomeReason(outcome); reason != "" {
			if _, ok := seen[reason]; !ok {
				seen[reason] = struct{}{}
				out = append(out, reason)
			}
		}
	}
	sort.Strings(out)
	return out
}
