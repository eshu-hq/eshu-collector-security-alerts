// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-sdk/collector"
)

type stubRepositoryClient struct {
	alerts []GitHubDependabotAlert
}

func (s stubRepositoryClient) ListRepositoryAlertsPages(
	ctx context.Context,
	repository string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	return GitHubDependabotAlertResult{
		Alerts:       s.alerts,
		PagesFetched: 1,
		ObservedAt:   time.Date(2026, 5, 16, 11, 0, 0, 0, time.UTC),
	}, nil
}

func (s stubRepositoryClient) ListOrganizationAlertsPages(
	ctx context.Context,
	organization string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	return GitHubDependabotAlertResult{}, GitHubDependabotError{Message: "not implemented"}
}

func collectTestClaim() collector.Claim {
	return collector.Claim{
		ComponentID:   "collector-security-alerts",
		InstanceID:    "security-alert-primary",
		CollectorKind: CollectorKind,
		SourceSystem:  CollectorKind,
		SourceRunID:   "source-run-1",
		ConfigHandle:  "config-1",
		Scope:         collector.Scope{ID: "security-alert:github:example-org/example-repo", Kind: "security_alert"},
		GenerationID:  "security-alert:generation-9",
		WorkItemID:    "work-1",
		FencingToken:  "7",
		Attempt:       1,
		Deadline:      time.Now().Add(time.Minute),
	}
}

func validatorForTest() collector.Validator {
	return collector.NewValidator(collector.Contract{
		ProtocolVersion: collector.ProtocolVersionV1Alpha1,
		Facts: []collector.FactDeclaration{{
			Kind:             KindRepositoryAlert,
			SchemaVersions:   []string{SchemaVersionV1},
			SourceConfidence: []collector.SourceConfidence{collector.SourceConfidenceReported},
		}},
	})
}

func TestCollectEmitsValidatorCleanResult(t *testing.T) {
	t.Parallel()

	source, err := NewClaimedSource(SourceConfig{
		CollectorInstanceID: "security-alert-primary",
		Targets: []TargetConfig{{
			Provider:   ProviderGitHubDependabot,
			Scope:      TargetScopeRepository,
			ScopeID:    "security-alert:github:example-org/example-repo",
			Repository: "example-org/example-repo",
			Token:      "token-value",
			AllowedRepositories: []string{
				"example-org/example-repo",
			},
		}},
		ClientFactory: func(TargetConfig) (RepositoryAlertClient, error) {
			return stubRepositoryClient{alerts: []GitHubDependabotAlert{goldenFixtureAlert()}}, nil
		},
		Now: func() time.Time { return time.Date(2026, 5, 16, 11, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewClaimedSource() error = %v, want nil", err)
	}

	result, err := source.Collect(context.Background(), collectTestClaim())
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil", err)
	}
	if result.State != collector.ResultComplete {
		t.Errorf("State = %q, want complete", result.State)
	}
	if len(result.Facts) != 1 {
		t.Fatalf("len(Facts) = %d, want 1", len(result.Facts))
	}
	if result.Facts[0].StableKey != goldenStableKey {
		t.Errorf("StableKey = %q, want golden %q", result.Facts[0].StableKey, goldenStableKey)
	}
	if result.Generation.ID != "security-alert:generation-9" {
		t.Errorf("Generation.ID = %q, want claim generation", result.Generation.ID)
	}
	if !strings.HasPrefix(result.Generation.FreshnessHint, "sha256:") {
		t.Errorf("FreshnessHint = %q, want sha256 digest", result.Generation.FreshnessHint)
	}

	report, err := validatorForTest().ValidateResult(result)
	if err != nil {
		t.Fatalf("ValidateResult() error = %v, want nil", err)
	}
	if report.FactCount != 1 {
		t.Errorf("FactCount = %d, want 1", report.FactCount)
	}
}

// truncatingStubClient returns a read that hit max_pages so Collect must
// stay partial with a warning status instead of a complete claim.
type truncatingStubClient struct {
	alerts []GitHubDependabotAlert
}

func (s truncatingStubClient) ListRepositoryAlertsPages(
	ctx context.Context,
	repository string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	return GitHubDependabotAlertResult{
		Alerts:       s.alerts,
		PagesFetched: maxPages,
		Truncated:    true,
		ObservedAt:   time.Date(2026, 5, 16, 11, 0, 0, 0, time.UTC),
	}, nil
}

func (s truncatingStubClient) ListOrganizationAlertsPages(
	ctx context.Context,
	organization string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	return GitHubDependabotAlertResult{}, GitHubDependabotError{Message: "not implemented"}
}

func TestCollectPartialReadStaysPartial(t *testing.T) {
	t.Parallel()

	source, err := NewClaimedSource(SourceConfig{
		CollectorInstanceID: "security-alert-primary",
		Targets: []TargetConfig{{
			Provider:   ProviderGitHubDependabot,
			Scope:      TargetScopeRepository,
			ScopeID:    "security-alert:github:example-org/example-repo",
			Repository: "example-org/example-repo",
			Token:      "token-value",
			AllowedRepositories: []string{
				"example-org/example-repo",
			},
			MaxPages: 1,
		}},
		ClientFactory: func(TargetConfig) (RepositoryAlertClient, error) {
			return truncatingStubClient{alerts: []GitHubDependabotAlert{goldenFixtureAlert()}}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClaimedSource() error = %v, want nil", err)
	}

	result, err := source.Collect(context.Background(), collectTestClaim())
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil", err)
	}
	if result.State != collector.ResultPartial {
		t.Fatalf("State = %q, want partial for a truncated read", result.State)
	}
	if len(result.Statuses) != 1 || !result.Statuses[0].Partial {
		t.Fatalf("Statuses = %+v, want one partial warning status", result.Statuses)
	}
	if _, err := validatorForTest().ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult(partial) error = %v, want nil", err)
	}
}

func TestCollectRejectsUnknownScope(t *testing.T) {
	t.Parallel()

	source, err := NewClaimedSource(SourceConfig{
		CollectorInstanceID: "security-alert-primary",
		Targets: []TargetConfig{{
			Provider:            ProviderGitHubDependabot,
			Scope:               TargetScopeRepository,
			ScopeID:             "security-alert:github:example-org/example-repo",
			Repository:          "example-org/example-repo",
			Token:               "token-value",
			AllowedRepositories: []string{"example-org/example-repo"},
		}},
		ClientFactory: func(TargetConfig) (RepositoryAlertClient, error) {
			return stubRepositoryClient{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClaimedSource() error = %v, want nil", err)
	}
	claim := collectTestClaim()
	claim.Scope.ID = "security-alert:github:example-org#shard-0"
	if _, err := source.Collect(context.Background(), claim); err == nil {
		t.Error("Collect(shard scope) = nil, want unconfigured-scope failure")
	}
}

// cancelOrgStubClient serves a truncated org read so Collect fans out,
// then fails the per-repository read while the claim context is already
// cancelled.
type cancelOrgStubClient struct {
	org GitHubDependabotAlertResult
}

func (s cancelOrgStubClient) ListRepositoryAlertsPages(
	ctx context.Context,
	repository string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	return GitHubDependabotAlertResult{}, GitHubDependabotError{
		Message:   "fetch github dependabot alerts",
		Operation: dependabotRepositoryAlertsOperation,
	}
}

func (s cancelOrgStubClient) ListOrganizationAlertsPages(
	ctx context.Context,
	organization string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	return s.org, nil
}

func collectOrgTestClaim() collector.Claim {
	claim := collectTestClaim()
	claim.Scope = collector.Scope{ID: "security-alert:github:example-org", Kind: "security_alert"}
	return claim
}

func TestCollectCancelledFanoutPropagatesError(t *testing.T) {
	t.Parallel()

	orgAlert := goldenFixtureAlert()
	orgAlert.Repository = GitHubDependabotRepository{
		FullName: "example-org/example-repo",
		Name:     "example-repo",
		Owner:    GitHubDependabotRepositoryOwner{Login: "example-org"},
	}
	source, err := NewClaimedSource(SourceConfig{
		CollectorInstanceID: "security-alert-primary",
		Targets: []TargetConfig{{
			Provider:     ProviderGitHubDependabot,
			Scope:        TargetScopeOrganization,
			ScopeID:      "security-alert:github:example-org",
			Organization: "example-org",
			Token:        "token-value",
			AllowedRepositories: []string{
				"example-org/example-repo",
			},
			MaxPages: 1,
		}},
		ClientFactory: func(TargetConfig) (RepositoryAlertClient, error) {
			return cancelOrgStubClient{org: GitHubDependabotAlertResult{
				Alerts:       []GitHubDependabotAlert{orgAlert},
				PagesFetched: 1,
				Truncated:    true,
				ObservedAt:   time.Date(2026, 5, 16, 11, 0, 0, 0, time.UTC),
			}}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClaimedSource() error = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Collect(ctx, collectOrgTestClaim()); err == nil {
		t.Error("Collect(cancelled fan-out) = nil, want the cancellation propagated as an error, not a partial success with zero facts")
	}
}

func TestNewClaimedSourceRejectsTokenProviderOnTokenEnvTarget(t *testing.T) {
	t.Parallel()

	_, err := NewClaimedSource(SourceConfig{
		CollectorInstanceID: "security-alert-primary",
		Targets: []TargetConfig{{
			Provider:   ProviderGitHubDependabot,
			Scope:      TargetScopeRepository,
			ScopeID:    "security-alert:github:example-org/example-repo",
			Repository: "example-org/example-repo",
			Token:      "token-value",
			AuthMode:   AuthModeTokenEnv,
			AllowedRepositories: []string{
				"example-org/example-repo",
			},
			TokenProvider: func(ctx context.Context) (string, error) {
				return "stray-provider-token", nil
			},
		}},
	})
	if err == nil {
		t.Error("NewClaimedSource(token_env with TokenProvider) = nil, want fail-closed rejection: the credential shapes never mix")
	}
}

// countingMetrics records how many fetch observations one Collect attempt
// produces.
type countingMetrics struct {
	fetches int
}

func (m *countingMetrics) RecordFetch(provider string, statusClass string, latency time.Duration) {
	m.fetches++
}

func (m *countingMetrics) RecordRateLimited(provider string, count int) {}

func (m *countingMetrics) RecordFactsEmitted(provider string, counts map[string]int64) {}

func (m *countingMetrics) RecordTruncatedReads(provider string, operation string, count int) {}

func (m *countingMetrics) RecordFanoutOutcome(provider string, outcome string, count int) {}

type failingRepositoryClient struct{}

func (failingRepositoryClient) ListRepositoryAlertsPages(
	ctx context.Context,
	repository string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	return GitHubDependabotAlertResult{}, GitHubDependabotError{
		Message:   "fetch github dependabot alerts",
		Operation: dependabotRepositoryAlertsOperation,
	}
}

func (failingRepositoryClient) ListOrganizationAlertsPages(
	ctx context.Context,
	organization string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	return GitHubDependabotAlertResult{}, GitHubDependabotError{
		Message:   "fetch github dependabot alerts",
		Operation: dependabotOrganizationAlertsOperation,
	}
}

func TestFailedCollectRecordsOneFetch(t *testing.T) {
	t.Parallel()

	recorder := &countingMetrics{}
	source, err := NewClaimedSource(SourceConfig{
		CollectorInstanceID: "security-alert-primary",
		Targets: []TargetConfig{{
			Provider:   ProviderGitHubDependabot,
			Scope:      TargetScopeRepository,
			ScopeID:    "security-alert:github:example-org/example-repo",
			Repository: "example-org/example-repo",
			Token:      "token-value",
			AllowedRepositories: []string{
				"example-org/example-repo",
			},
		}},
		ClientFactory: func(TargetConfig) (RepositoryAlertClient, error) {
			return failingRepositoryClient{}, nil
		},
		Metrics: recorder,
	})
	if err != nil {
		t.Fatalf("NewClaimedSource() error = %v, want nil", err)
	}

	if _, err := source.Collect(context.Background(), collectTestClaim()); err == nil {
		t.Fatal("Collect(failing provider) = nil, want provider failure")
	}
	if recorder.fetches != 1 {
		t.Errorf("RecordFetch calls = %d, want exactly 1 per failed Collect", recorder.fetches)
	}
}

func TestCollectValidatesClaimBinding(t *testing.T) {
	t.Parallel()

	source, err := NewClaimedSource(SourceConfig{
		CollectorInstanceID: "security-alert-primary",
		Targets: []TargetConfig{{
			Provider:            ProviderGitHubDependabot,
			Scope:               TargetScopeRepository,
			ScopeID:             "security-alert:github:example-org/example-repo",
			Repository:          "example-org/example-repo",
			Token:               "token-value",
			AllowedRepositories: []string{"example-org/example-repo"},
		}},
		ClientFactory: func(TargetConfig) (RepositoryAlertClient, error) {
			return stubRepositoryClient{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewClaimedSource() error = %v, want nil", err)
	}
	foreign := collectTestClaim()
	foreign.SourceSystem = "grafana"
	if _, err := source.Collect(context.Background(), foreign); err == nil {
		t.Error("Collect(foreign source_system) = nil, want binding rejection")
	}
	blankGen := collectTestClaim()
	blankGen.GenerationID = ""
	if _, err := source.Collect(context.Background(), blankGen); err == nil {
		t.Error("Collect(blank generation) = nil, want rejection")
	}
}

// TestNewClaimedSourceAcceptsHostMintedTarget proves the producer layer
// accepts a host_minted target carrying the injected per-claim credential as
// its static credential, and still fails closed without one. Scope binding
// of the host stanza to the claim stays the satellite adapter's job; here
// only the credential shape is proved.
func TestNewClaimedSourceAcceptsHostMintedTarget(t *testing.T) {
	t.Parallel()

	hostMinted := TargetConfig{
		Provider:   ProviderGitHubDependabot,
		Scope:      TargetScopeRepository,
		ScopeID:    "security-alert:github:example-org/example-repo",
		Repository: "example-org/example-repo",
		Token:      "host-minted-token",
		AuthMode:   AuthModeHostMinted,
		AllowedRepositories: []string{
			"example-org/example-repo",
		},
	}
	if _, err := NewClaimedSource(SourceConfig{
		CollectorInstanceID: "security-alert-primary",
		Targets:             []TargetConfig{hostMinted},
		ClientFactory: func(TargetConfig) (RepositoryAlertClient, error) {
			return stubRepositoryClient{}, nil
		},
	}); err != nil {
		t.Errorf("NewClaimedSource(host_minted) error = %v, want nil", err)
	}

	withoutToken := hostMinted
	withoutToken.Token = ""
	if _, err := NewClaimedSource(SourceConfig{
		CollectorInstanceID: "security-alert-primary",
		Targets:             []TargetConfig{withoutToken},
		ClientFactory: func(TargetConfig) (RepositoryAlertClient, error) {
			return stubRepositoryClient{}, nil
		},
	}); err == nil {
		t.Error("NewClaimedSource(host_minted without token) = nil, want fail-closed rejection")
	}
}

// TestDefaultClientFactoryMapsHostMintedToAppAuth proves a host_minted
// target's client treats an alert-read 401 as installation-token expiry and
// stays retryable, so the next claim mints fresh — unlike a static PAT 401,
// which denies terminally until the operator rotates it.
func TestDefaultClientFactoryMapsHostMintedToAppAuth(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := defaultClientFactory(TargetConfig{
		Provider:             ProviderGitHubDependabot,
		Scope:                TargetScopeRepository,
		ScopeID:              "security-alert:github:example-org/example-repo",
		Repository:           "example-org/example-repo",
		Token:                "host-minted-token",
		AuthMode:             AuthModeHostMinted,
		AllowedRepositories:  []string{"example-org/example-repo"},
		RepositoryAlertLimit: 25,
		APIBaseURL:           server.URL,
	})
	if err != nil {
		t.Fatalf("defaultClientFactory(host_minted) error = %v, want nil", err)
	}
	_, err = client.ListRepositoryAlertsPages(context.Background(), "example-org/example-repo", 1)
	providerErr, ok := err.(GitHubDependabotError)
	if !ok {
		t.Fatalf("error type = %T, want GitHubDependabotError", err)
	}
	if providerErr.FailureClass() != GitHubDependabotFailureRetryable {
		t.Fatalf("FailureClass() = %q, want %q", providerErr.FailureClass(), GitHubDependabotFailureRetryable)
	}
	if providerErr.TerminalFailure() {
		t.Fatal("TerminalFailure() = true, want retryable expiry for a host-minted 401")
	}
}
