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

// otherScopeTarget returns a copy of the claim's target pointed at a second
// repository: the shape of an activation that lists a repository the single
// claim scope can never serve.
func otherScopeTarget(base map[string]any) map[string]any {
	other := make(map[string]any, len(base))
	for key, value := range base {
		other[key] = value
	}
	other["scope_id"] = "security-alert:github:example-org/other-repo"
	other["repository"] = "example-org/other-repo"
	other["allowed_repositories"] = []any{"example-org/other-repo"}
	return other
}

// TestParseSettingsRefusesTargetOutsideClaimScope proves an activation plans
// exactly one scope: any target, host_minted or static, whose scope_id differs
// from the claim scope fails the whole activation as target_scope_mismatch.
// Dropping it silently would leave the repository uncollected with no signal
// (eshu-hq/eshu#9289). The error names the count, never a credential.
func TestParseSettingsRefusesTargetOutsideClaimScope(t *testing.T) {
	t.Parallel()

	const tokenSentinel = "HOST-TOKEN-SENTINEL-9289"
	const staticSentinel = "STATIC-TOKEN-SENTINEL-9289"
	hostMinted := hostMintedTarget()
	static := validTarget()
	tests := []struct {
		name      string
		targets   []any
		wantCount string
	}{
		{
			name:      "host_minted second target",
			targets:   []any{hostMinted, otherScopeTarget(hostMinted)},
			wantCount: "1 target",
		},
		{
			name:      "static second target",
			targets:   []any{hostMinted, otherScopeTarget(static)},
			wantCount: "1 target",
		},
		{
			name:      "static only activation for another scope",
			targets:   []any{otherScopeTarget(static)},
			wantCount: "1 target",
		},
		{
			name:      "two mismatched targets are both counted",
			targets:   []any{hostMinted, otherScopeTarget(hostMinted), otherScopeTarget(static)},
			wantCount: "2 target",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			config := map[string]any{
				"targets": tc.targets,
				"host_github_app_token": map[string]any{
					"token":    tokenSentinel,
					"scope_id": hostMintedScope,
				},
			}
			_, err := parseSettings(config, func(string) string { return staticSentinel }, hostMintedScope)
			if err == nil {
				t.Fatal("parseSettings() error = nil, want target_scope_mismatch")
			}
			if got := configFailureReason(err); got != "target_scope_mismatch" {
				t.Fatalf("reason = %q, want target_scope_mismatch (err = %v)", got, err)
			}
			if !strings.Contains(err.Error(), tc.wantCount) {
				t.Fatalf("error = %q, want it to name the count %q", err, tc.wantCount)
			}
			for _, leaked := range []string{tokenSentinel, staticSentinel, "other-repo"} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatalf("error = %q, must not carry %q", err, leaked)
				}
			}
		})
	}
}

// TestParseSettingsAcceptsSingleClaimScopedTarget keeps the supported shape
// working: one target whose scope_id equals the claim scope, in either auth
// mode, even when the activation spells the scope with stray whitespace.
func TestParseSettingsAcceptsSingleClaimScopedTarget(t *testing.T) {
	t.Parallel()

	spaced := validTarget()
	spaced["scope_id"] = " " + hostMintedScope + " "
	tests := []struct {
		name   string
		config map[string]any
	}{
		{name: "host_minted", config: hostMintedConfig(hostMintedTarget(), "host-minted-token", hostMintedScope)},
		{name: "static", config: map[string]any{"targets": []any{validTarget()}}},
		{name: "static with padded scope id", config: map[string]any{"targets": []any{spaced}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			parsed, err := parseSettings(tc.config, func(string) string { return "static-token" }, hostMintedScope)
			if err != nil {
				t.Fatalf("parseSettings() error = %v, want nil", err)
			}
			if len(parsed.targets) != 1 || parsed.targets[0].ScopeID != hostMintedScope {
				t.Fatalf("targets = %+v, want exactly the claim-scoped target", parsed.targets)
			}
		})
	}
}

// TestHandleSurfacesTargetScopeMismatchReasonInResult proves the refusal is
// visible to the host: the terminal result carries one failure status whose
// class refines invalid_config with the bounded reason, the only channel the SDK
// status offers. The diagnostic line keeps class and reason separate and adds
// the count.
func TestHandleSurfacesTargetScopeMismatchReasonInResult(t *testing.T) {
	t.Parallel()

	const tokenSentinel = "HOST-TOKEN-SENTINEL-9289"
	contacted := false
	var logLines strings.Builder
	handler := Handler{
		Getenv: func(string) string { return "" },
		Now:    time.Now,
		ClientFactory: func(securityalert.TargetConfig) (securityalert.RepositoryAlertClient, error) {
			contacted = true
			return stubAlertClient{}, nil
		},
		Log: &logLines,
	}
	target := hostMintedTarget()
	config := hostMintedConfig(target, tokenSentinel, hostMintedScope)
	config["targets"] = []any{target, otherScopeTarget(target)}
	result := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           testClaim(),
		Contract:        Contract(),
		Config:          config,
	})
	if contacted {
		t.Fatal("scope-mismatched activation constructed a provider client; it must fail closed first")
	}
	if result.State != sdk.ResultTerminal {
		t.Fatalf("State = %q, want terminal", result.State)
	}
	if len(result.Statuses) != 1 {
		t.Fatalf("statuses = %+v, want exactly one failure status", result.Statuses)
	}
	if got := result.Statuses[0]; got.Class != sdk.StatusFailure || got.FailureClass != "invalid_config.target_scope_mismatch" {
		t.Fatalf("status = %+v, want failure invalid_config.target_scope_mismatch", got)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error = %v", err)
	}
	if strings.Contains(string(encoded), tokenSentinel) || strings.Contains(logLines.String(), tokenSentinel) {
		t.Fatal("result or diagnostic log carries host credential material")
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(logLines.String())), &line); err != nil {
		t.Fatalf("diagnostic line is not JSON: %v", err)
	}
	if line["reason"] != "target_scope_mismatch" || line["mismatched_targets"] != float64(1) {
		t.Fatalf("diagnostic line = %v, want reason target_scope_mismatch and mismatched_targets 1", line)
	}
}

// TestRefinedClassKeepsClassWhenReasonCannotFormAToken guards the dotted
// failure_class: a blank, dotted, uppercase, or over-long reason would break
// the host's bound on the token, so it falls back to the bare class.
func TestRefinedClassKeepsClassWhenReasonCannotFormAToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		reason string
		want   string
	}{
		{name: "blank", reason: "", want: "invalid_config"},
		{name: "valid", reason: "target_scope_mismatch", want: "invalid_config.target_scope_mismatch"},
		{name: "nested dot", reason: "a.b", want: "invalid_config"},
		{name: "uppercase", reason: "Bad", want: "invalid_config"},
		{name: "hyphen", reason: "bad-reason", want: "invalid_config"},
		{name: "over the token bound", reason: strings.Repeat("a", 90), want: "invalid_config"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := refinedClass(FailureInvalidConfig, tc.reason); got != tc.want {
				t.Fatalf("refinedClass() = %q, want %q", got, tc.want)
			}
		})
	}
}
