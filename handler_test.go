// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-security-alerts/securityalert"
)

// stubAlertClient serves one canned Dependabot alert page without a network.
type stubAlertClient struct {
	alerts []securityalert.GitHubDependabotAlert
}

func (s stubAlertClient) ListRepositoryAlertsPages(
	_ context.Context, _ string, _ int,
) (securityalert.GitHubDependabotAlertResult, error) {
	return securityalert.GitHubDependabotAlertResult{
		Alerts:       s.alerts,
		PagesFetched: 1,
		ObservedAt:   time.Now().UTC(),
	}, nil
}

func (s stubAlertClient) ListOrganizationAlertsPages(
	_ context.Context, _ string, _ int,
) (securityalert.GitHubDependabotAlertResult, error) {
	return securityalert.GitHubDependabotAlertResult{}, errOrgScopeUnimplemented
}

var errOrgScopeUnimplemented = testError("organization fan-out is not covered by this stub")

type testError string

func (e testError) Error() string { return string(e) }

// fixtureAlert is the canonical synthetic Dependabot alert this package's
// tests collect: one open npm alert on an allowlisted repository.
func fixtureAlert() securityalert.GitHubDependabotAlert {
	return securityalert.GitHubDependabotAlert{
		Number:    42,
		State:     "open",
		HTMLURL:   "https://github.com/example-org/example-repo/security/dependabot/42",
		CreatedAt: "2026-05-20T12:00:00Z",
		UpdatedAt: "2026-05-23T10:15:00Z",
		Dependency: securityalert.GitHubDependabotDependency{
			ManifestPath: "package-lock.json",
			Scope:        "runtime",
			Package:      securityalert.GitHubDependabotPackage{Ecosystem: "npm", Name: "@scope/left-pad"},
			Relationship: "direct",
		},
		SecurityAdvisory: securityalert.GitHubDependabotSecurityAdvisory{
			GHSAID:      "GHSA-abcd-1234",
			CVEID:       "CVE-2026-0001",
			Summary:     "Synthetic advisory",
			Description: "Synthetic advisory description",
			Severity:    "critical",
			CVSS:        securityalert.GitHubDependabotCVSS{Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			EPSS:        securityalert.GitHubDependabotEPSS{Percentage: "0.721", Percentile: "0.981"},
			CWEs:        []securityalert.GitHubDependabotCWE{{CWEID: "CWE-79", Name: "Cross-site Scripting"}},
		},
		SecurityVulnerability: securityalert.GitHubDependabotSecurityVulnerability{
			VulnerableVersionRange: "<1.2.3",
			FirstPatchedVersion:    securityalert.GitHubDependabotVersion{Identifier: "1.2.3"},
			Package:                securityalert.GitHubDependabotPackage{Ecosystem: "npm", Name: "@scope/left-pad"},
		},
	}
}

// testClaim returns the claim every handler test serves.
func testClaim() sdk.Claim {
	return sdk.Claim{
		ComponentID:   ComponentID,
		InstanceID:    "security-alert-primary",
		CollectorKind: CollectorKind,
		SourceSystem:  CollectorKind,
		Scope:         sdk.Scope{ID: "security-alert:github:example-org/example-repo", Kind: "security_alert"},
		SourceRunID:   "run-1",
		GenerationID:  "security-alert:generation-9",
		WorkItemID:    "work-1",
		FencingToken:  "7",
		Attempt:       1,
		Deadline:      time.Now().Add(time.Hour).UTC(),
		ConfigHandle:  "component-config:security-alert",
	}
}

// testConfig returns the activation config every handler test serves: one
// token_env repository target plus the host-delivered producer grant.
func testConfig(t *testing.T) map[string]any {
	t.Helper()

	// The expiry sits one hour after the real clock: both the handler
	// pre-check and Collect enforce the grant against time.Now, so a fixed
	// test clock in the past would deny it either as expired (Collect) or as
	// exceeding the maximum lifetime (the pre-check).
	grant := map[string]any{
		"producer_id": ProducerID,
		"version":     "0.1.0",
		"scope":       CollectorKind,
		"kinds":       map[string]any{FactKindRepositoryAlert: []any{"1.0.0"}},
		"expires_at":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"revoked":     false,
	}
	return map[string]any{
		"targets": []any{map[string]any{
			"provider":               "github_dependabot",
			"scope_id":               "security-alert:github:example-org/example-repo",
			"repository":             "example-org/example-repo",
			"token_env":              "GITHUB_TOKEN",
			"allowed_repositories":   []any{"example-org/example-repo"},
			"repository_alert_limit": float64(25),
			"max_pages":              float64(2),
		}},
		"grant": grant,
	}
}

// testHandler returns a Handler wired to the stub client and a static env.
// The clock is real: Collect enforces the grant against time.Now, so a fixed
// past clock would deny a live grant as expired.
func testHandler(env map[string]string, alerts []securityalert.GitHubDependabotAlert) Handler {
	return Handler{
		Getenv: func(key string) string { return env[key] },
		Now:    func() time.Time { return time.Now().UTC() },
		ClientFactory: func(securityalert.TargetConfig) (securityalert.RepositoryAlertClient, error) {
			return stubAlertClient{alerts: alerts}, nil
		},
	}
}

// TestHandleServesOneValidatorCleanResult serves one claim against the stub
// client and asserts the SDK result is complete, carries the single fact, and
// passes the published SDK validator against this package's contract.
func TestHandleServesOneValidatorCleanResult(t *testing.T) {
	t.Parallel()

	env := map[string]string{"GITHUB_TOKEN": "token-value"}
	handler := testHandler(env, []securityalert.GitHubDependabotAlert{fixtureAlert()})
	result := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           testClaim(),
		Contract:        Contract(),
		Config:          testConfig(t),
	})
	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete", result.State)
	}
	if len(result.Facts) != 1 {
		t.Fatalf("facts = %d, want 1", len(result.Facts))
	}
	if result.Facts[0].Kind != FactKindRepositoryAlert {
		t.Fatalf("Kind = %q, want %q", result.Facts[0].Kind, FactKindRepositoryAlert)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
}

// TestHandleDeniesMissingGrantWithoutProviderContact fails closed with a
// terminal invalid_config result when the host delivers no producer grant,
// and never constructs a provider client.
func TestHandleDeniesMissingGrantWithoutProviderContact(t *testing.T) {
	t.Parallel()

	contacted := false
	handler := Handler{
		Getenv: func(key string) string { return "token-value" },
		Now:    time.Now,
		ClientFactory: func(securityalert.TargetConfig) (securityalert.RepositoryAlertClient, error) {
			contacted = true
			return stubAlertClient{}, nil
		},
	}
	config := testConfig(t)
	delete(config, "grant")
	result := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           testClaim(),
		Contract:        Contract(),
		Config:          config,
	})
	if contacted {
		t.Fatal("missing grant constructed a provider client; emission must fail closed first")
	}
	if result.State != sdk.ResultTerminal {
		t.Fatalf("State = %q, want terminal", result.State)
	}
	if len(result.Facts) != 0 {
		t.Fatalf("facts = %d, want 0 with a failure state", len(result.Facts))
	}
	if failureClass(result) != FailureInvalidConfig {
		t.Fatalf("failure class = %q, want %q", failureClass(result), FailureInvalidConfig)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
}

// TestHandleRejectsUnknownScope maps an unconfigured scope to a retryable
// result with no facts, never a terminal failure for a routing miss.
func TestHandleRejectsUnknownScope(t *testing.T) {
	t.Parallel()

	env := map[string]string{"GITHUB_TOKEN": "token-value"}
	handler := testHandler(env, []securityalert.GitHubDependabotAlert{fixtureAlert()})
	claim := testClaim()
	claim.Scope.ID = "security-alert:github:example-org/unknown"
	result := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          testConfig(t),
	})
	if result.State != sdk.ResultRetryable {
		t.Fatalf("State = %q, want retryable", result.State)
	}
	if len(result.Facts) != 0 {
		t.Fatalf("facts = %d, want 0 with a failure state", len(result.Facts))
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
}

// failureClass returns the failure class of a failure-state result.
func failureClass(result sdk.Result) string {
	for _, status := range result.Statuses {
		if status.Class == sdk.StatusFailure {
			return status.FailureClass
		}
	}
	return ""
}

// TestRequestRoundTrip proves the stdio wire shape decodes: one JSON request
// in, the same claim echoed on the result.
func TestRequestRoundTrip(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           testClaim(),
		Contract:        Contract(),
		Config:          map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := ParseRequest(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if request.Claim.WorkItemID != "work-1" {
		t.Fatalf("WorkItemID = %q, want work-1", request.Claim.WorkItemID)
	}
}
