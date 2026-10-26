// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-security-alerts/securityalert"
)

// hostMintedScope is the claim scope the host-minted token tests bind to.
const hostMintedScope = "security-alert:github:example-org/example-repo"

// hostMintedTarget returns the minimal host_minted target the host-token
// tests reuse: empty token_env and empty github_app env references, with the
// credential arriving per claim in host_github_app_token instead.
func hostMintedTarget() map[string]any {
	return map[string]any{
		"provider":               "github_dependabot",
		"scope_id":               hostMintedScope,
		"repository":             "example-org/example-repo",
		"auth_mode":              "host_minted",
		"token_env":              "",
		"allowed_repositories":   []any{"example-org/example-repo"},
		"repository_alert_limit": float64(25),
		"max_pages":              float64(2),
	}
}

// hostMintedConfig wraps one target with a top-level host-minted credential
// shaped as the host delivers it per claim: {token, scope_id}.
func hostMintedConfig(target map[string]any, token, scopeID string) map[string]any {
	return map[string]any{
		"targets": []any{target},
		"host_github_app_token": map[string]any{
			"token":    token,
			"scope_id": scopeID,
		},
	}
}

// TestParseSettingsSpendsHostMintedToken proves the happy path: a host_minted
// target resolves its bearer from the top-level host_github_app_token whose
// scope_id binds to the claim scope.
func TestParseSettingsSpendsHostMintedToken(t *testing.T) {
	t.Parallel()

	parsed, err := parseSettings(
		hostMintedConfig(hostMintedTarget(), "host-minted-token", hostMintedScope),
		func(string) string { return "" },
		hostMintedScope,
	)
	if err != nil {
		t.Fatalf("parseSettings(host_minted) error = %v", err)
	}
	if len(parsed.targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(parsed.targets))
	}
	got := parsed.targets[0]
	if got.Token != "host-minted-token" {
		t.Fatal("target token was not injected from host_github_app_token")
	}
	if got.AuthMode != securityalert.AuthModeHostMinted {
		t.Fatalf("AuthMode = %q, want %q", got.AuthMode, securityalert.AuthModeHostMinted)
	}
}

// TestParseSettingsRejectsHostMintedWithoutHostToken fails closed when a
// host_minted target arrives with no per-claim credential, naming the key
// and never credential material.
func TestParseSettingsRejectsHostMintedWithoutHostToken(t *testing.T) {
	t.Parallel()

	_, err := parseSettings(
		map[string]any{"targets": []any{hostMintedTarget()}},
		func(string) string { return "" },
		hostMintedScope,
	)
	if err == nil {
		t.Fatal("parseSettings(host_minted without host token) error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "host_github_app_token") {
		t.Fatalf("error %q does not name the missing credential key", err)
	}
}

// TestParseSettingsRejectsHostMintedEmptyToken fails closed on a present but
// empty per-claim credential.
func TestParseSettingsRejectsHostMintedEmptyToken(t *testing.T) {
	t.Parallel()

	_, err := parseSettings(
		hostMintedConfig(hostMintedTarget(), "  ", hostMintedScope),
		func(string) string { return "" },
		hostMintedScope,
	)
	if err == nil {
		t.Fatal("parseSettings(host_minted with empty host token) error = nil, want non-nil")
	}
	if strings.Contains(err.Error(), "host-minted-token") {
		t.Fatalf("error %q carries credential material", err)
	}
}

// TestParseSettingsRejectsHostMintedScopeMismatch fails closed when the
// host-minted credential is scoped to another claim, and the error carries
// neither the token nor either scope value.
func TestParseSettingsRejectsHostMintedScopeMismatch(t *testing.T) {
	t.Parallel()

	const tokenSentinel = "HOST-TOKEN-SENTINEL-9185"
	const foreignScope = "security-alert:github:example-org/other-repo"
	_, err := parseSettings(
		hostMintedConfig(hostMintedTarget(), tokenSentinel, foreignScope),
		func(string) string { return "" },
		hostMintedScope,
	)
	if err == nil {
		t.Fatal("parseSettings(host_minted with foreign scope) error = nil, want non-nil")
	}
	for _, leaked := range []string{tokenSentinel, foreignScope, hostMintedScope} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("error %q leaks credential or scope material %q", err, leaked)
		}
	}
}

// TestParseSettingsRejectsHostMintedCredentialMix proves the token_env mix
// rules apply to host_minted targets: any credential env reference fails
// closed, because the credential shapes never mix on one target.
func TestParseSettingsRejectsHostMintedCredentialMix(t *testing.T) {
	t.Parallel()

	cases := map[string]func(map[string]any){
		"token_env set": func(target map[string]any) {
			target["token_env"] = "GITHUB_TOKEN"
		},
		"github_app id ref set": func(target map[string]any) {
			target["github_app_id_env"] = "GITHUB_APP_ID"
		},
		"github_app installation ref set": func(target map[string]any) {
			target["github_app_installation_id_env"] = "GITHUB_APP_INSTALLATION_ID"
		},
		"github_app key ref set": func(target map[string]any) {
			target["github_app_private_key_env"] = "GITHUB_APP_PRIVATE_KEY"
		},
	}
	for name, mutate := range cases {
		target := hostMintedTarget()
		mutate(target)
		_, err := parseSettings(
			hostMintedConfig(target, "host-minted-token", hostMintedScope),
			func(string) string { return "credential-value" },
			hostMintedScope,
		)
		if err == nil {
			t.Fatalf("%s: parseSettings() error = nil, want non-nil", name)
		}
		if strings.Contains(err.Error(), "credential-value") {
			t.Fatalf("%s: error %q carries credential material", name, err)
		}
	}
}

// TestParseSettingsIgnoresHostTokenForTokenEnvTargets proves the top-level
// host key does not break target parsing when no target needs it: a
// token_env activation carrying the host stanza still parses, and the host
// credential never leaks into the static target.
func TestParseSettingsIgnoresHostTokenForTokenEnvTargets(t *testing.T) {
	t.Parallel()

	config := map[string]any{
		"targets": []any{validTarget()},
		"host_github_app_token": map[string]any{
			"token":    "host-minted-token",
			"scope_id": hostMintedScope,
		},
	}
	parsed, err := parseSettings(config,
		func(key string) string {
			if key == "GITHUB_TOKEN" {
				return "static-token-value"
			}
			return ""
		}, hostMintedScope)
	if err != nil {
		t.Fatalf("parseSettings(token_env with host stanza) error = %v", err)
	}
	if len(parsed.targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(parsed.targets))
	}
	if parsed.targets[0].Token != "static-token-value" {
		t.Fatal("token_env target must keep its static credential when a host stanza is present")
	}
}

// TestHandleSpendsHostMintedToken serves one host_minted claim against the
// fake ClientFactory and proves the spent bearer equals the injected host
// token: the factory observes the validated target carrying it.
func TestHandleSpendsHostMintedToken(t *testing.T) {
	t.Parallel()

	var observed []securityalert.TargetConfig
	handler := Handler{
		Getenv: func(string) string { return "" },
		Now:    func() time.Time { return time.Now().UTC() },
		ClientFactory: func(target securityalert.TargetConfig) (securityalert.RepositoryAlertClient, error) {
			observed = append(observed, target)
			return stubAlertClient{alerts: []securityalert.GitHubDependabotAlert{fixtureAlert()}}, nil
		},
	}
	result := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           testClaim(),
		Contract:        Contract(),
		Config:          hostMintedConfig(hostMintedTarget(), "host-minted-token", hostMintedScope),
	})
	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete", result.State)
	}
	if len(observed) != 1 {
		t.Fatalf("factory observations = %d, want 1", len(observed))
	}
	if observed[0].Token != "host-minted-token" {
		t.Fatal("factory did not observe the injected host token as the spent bearer")
	}
	if observed[0].AuthMode != securityalert.AuthModeHostMinted {
		t.Fatalf("AuthMode = %q, want %q", observed[0].AuthMode, securityalert.AuthModeHostMinted)
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
}

// TestHandleDeniesHostMintedScopeMismatchWithoutProviderContact fails a
// foreign-scoped host credential closed as terminal invalid_config before any
// provider client exists, with no credential material in the result log.
func TestHandleDeniesHostMintedScopeMismatchWithoutProviderContact(t *testing.T) {
	t.Parallel()

	const tokenSentinel = "HOST-TOKEN-SENTINEL-9185"
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
	claim := testClaim()
	result := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config: hostMintedConfig(hostMintedTarget(), tokenSentinel,
			"security-alert:github:example-org/other-repo"),
	})
	if contacted {
		t.Fatal("scope-mismatched host token constructed a provider client; emission must fail closed first")
	}
	if result.State != sdk.ResultTerminal {
		t.Fatalf("State = %q, want terminal", result.State)
	}
	if failureClass(result) != FailureInvalidConfig {
		t.Fatalf("failure class = %q, want %q", failureClass(result), FailureInvalidConfig)
	}
	if strings.Contains(logLines.String(), tokenSentinel) {
		t.Fatal("diagnostic log carries host credential material")
	}
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
}

// TestParseSettingsInjectsOnlyClaimScopedHostMintedTarget proves per-target
// scope gating: in a two-target activation the claim's target receives the
// host token and the other target is dropped from this claim's run, so a
// claim-scoped credential never reaches a non-serving target even in memory.
func TestParseSettingsInjectsOnlyClaimScopedHostMintedTarget(t *testing.T) {
	t.Parallel()

	other := hostMintedTarget()
	other["scope_id"] = "security-alert:github:example-org/other-repo"
	other["repository"] = "example-org/other-repo"
	other["allowed_repositories"] = []any{"example-org/other-repo"}
	config := map[string]any{
		"targets": []any{hostMintedTarget(), other},
		"host_github_app_token": map[string]any{
			"token":    "host-minted-token",
			"scope_id": hostMintedScope,
		},
	}
	parsed, err := parseSettings(config, func(string) string { return "" }, hostMintedScope)
	if err != nil {
		t.Fatalf("parseSettings() error = %v, want nil", err)
	}
	if len(parsed.targets) != 1 {
		t.Fatalf("targets = %d, want 1 (only the claim-scoped target)", len(parsed.targets))
	}
	if parsed.targets[0].ScopeID != hostMintedScope {
		t.Fatalf("target scope = %q, want %q", parsed.targets[0].ScopeID, hostMintedScope)
	}
	if parsed.targets[0].Token != "host-minted-token" {
		t.Fatal("claim-scoped target did not receive the injected host token")
	}
}

// TestParseSettingsRejectsClaimScopeWithoutHostMintedTarget fails a claim
// closed when every host_minted target serves another scope: nothing in this
// claim's run may spend a credential minted for a different scope.
func TestParseSettingsRejectsClaimScopeWithoutHostMintedTarget(t *testing.T) {
	t.Parallel()

	other := hostMintedTarget()
	other["scope_id"] = "security-alert:github:example-org/other-repo"
	other["repository"] = "example-org/other-repo"
	other["allowed_repositories"] = []any{"example-org/other-repo"}
	config := map[string]any{
		"targets": []any{other},
		"host_github_app_token": map[string]any{
			"token":    "host-minted-token",
			"scope_id": hostMintedScope,
		},
	}
	_, err := parseSettings(config, func(string) string { return "" }, hostMintedScope)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want fail-closed with no claim-scoped target")
	}
}

// TestParseSettingsRejectsMalformedHostStanzaOnStaticActivation pins the
// fail-closed stanza decode for activations that do not need it: a static
// token_env activation carrying a malformed host stanza fails before any
// provider contact, naming only the key.
func TestParseSettingsRejectsMalformedHostStanzaOnStaticActivation(t *testing.T) {
	t.Parallel()

	target := map[string]any{
		"provider":               "github_dependabot",
		"scope_id":               hostMintedScope,
		"repository":             "example-org/example-repo",
		"token_env":              "STATIC_PAT",
		"allowed_repositories":   []any{"example-org/example-repo"},
		"repository_alert_limit": float64(25),
		"max_pages":              float64(2),
	}
	config := map[string]any{
		"targets":               []any{target},
		"host_github_app_token": map[string]any{"token": float64(123), "scope_id": hostMintedScope},
	}
	_, err := parseSettings(config, func(string) string { return "static-pat" }, hostMintedScope)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want fail-closed on malformed host stanza")
	}
	if !strings.Contains(err.Error(), "host_github_app_token") {
		t.Fatalf("error = %q, want it to name the host stanza key", err.Error())
	}
}

// TestHandleLogsHostTokenFailureReason proves the diagnostic line
// distinguishes host-token fail-closed reasons: a missing stanza on a
// host_minted target logs reason missing_host_token with no credential
// material.
func TestHandleLogsHostTokenFailureReason(t *testing.T) {
	t.Parallel()

	var logLines strings.Builder
	handler := Handler{
		Getenv: func(string) string { return "" },
		Now:    time.Now,
		Log:    &logLines,
	}
	result := handler.Handle(context.Background(), Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           testClaim(),
		Contract:        Contract(),
		Config:          map[string]any{"targets": []any{hostMintedTarget()}},
	})
	if result.State != sdk.ResultTerminal {
		t.Fatalf("State = %q, want terminal", result.State)
	}
	if failureClass(result) != FailureInvalidConfig {
		t.Fatalf("failure class = %q, want %q", failureClass(result), FailureInvalidConfig)
	}
	if !strings.Contains(logLines.String(), `"reason":"missing_host_token"`) {
		t.Fatalf("diagnostic log = %q, want reason missing_host_token", logLines.String())
	}
}
