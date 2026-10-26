// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-security-alerts/grant"
)

// UsableTestGrant returns a valid host-delivered grant for tests.
// Production grants are issued by core, never minted here.
func UsableTestGrant() grant.Grant {
	return grant.UsableGrant(time.Now())
}

func zeroGrant() grant.Grant {
	return grant.Grant{}
}

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

	result, err := source.Collect(context.Background(), collectTestClaim(), UsableTestGrant())
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

	result, err := source.Collect(context.Background(), collectTestClaim(), UsableTestGrant())
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

func TestCollectRequiresGrant(t *testing.T) {
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
	if _, err := source.Collect(context.Background(), collectTestClaim(), zeroGrant()); err == nil {
		t.Error("Collect(zero grant) = nil, want fail-closed denial before any provider contact")
	}
	revoked := UsableTestGrant()
	revoked.Revoked = true
	if _, err := source.Collect(context.Background(), collectTestClaim(), revoked); err == nil {
		t.Error("Collect(revoked grant) = nil, want fail-closed denial")
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
	if _, err := source.Collect(context.Background(), claim, UsableTestGrant()); err == nil {
		t.Error("Collect(shard scope) = nil, want unconfigured-scope failure")
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
	if _, err := source.Collect(context.Background(), foreign, UsableTestGrant()); err == nil {
		t.Error("Collect(foreign source_system) = nil, want binding rejection")
	}
	blankGen := collectTestClaim()
	blankGen.GenerationID = ""
	if _, err := source.Collect(context.Background(), blankGen, UsableTestGrant()); err == nil {
		t.Error("Collect(blank generation) = nil, want rejection")
	}
}
