// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// validTarget returns the minimal token_env target the config tests reuse.
func validTarget() map[string]any {
	return map[string]any{
		"provider":               "github_dependabot",
		"scope_id":               "security-alert:github:example-org/example-repo",
		"repository":             "example-org/example-repo",
		"token_env":              "GITHUB_TOKEN",
		"allowed_repositories":   []any{"example-org/example-repo"},
		"repository_alert_limit": float64(25),
		"max_pages":              float64(2),
	}
}

func parseConfig(t *testing.T, config map[string]any, env map[string]string) settings {
	t.Helper()

	parsed, err := parseSettings(config, func(key string) string { return env[key] }, hostMintedScope)
	if err != nil {
		t.Fatalf("parseSettings() error = %v", err)
	}
	return parsed
}

// TestParseSettingsResolvesTokenEnv proves the happy path: one target with
// its credential resolved from the environment.
func TestParseSettingsResolvesTokenEnv(t *testing.T) {
	t.Parallel()

	parsed := parseConfig(t, map[string]any{
		"targets": []any{validTarget()},
	}, map[string]string{"GITHUB_TOKEN": "token-value"})
	if len(parsed.targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(parsed.targets))
	}
	if parsed.targets[0].Token != "token-value" {
		t.Fatal("target token was not resolved from the environment")
	}
}

// TestParseSettingsRejectsUnresolvableToken fails closed naming the variable,
// never the credential value.
func TestParseSettingsRejectsUnresolvableToken(t *testing.T) {
	t.Parallel()

	_, err := parseSettings(map[string]any{
		"targets": []any{validTarget()},
	}, func(string) string { return "" }, hostMintedScope)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("error %q does not name the variable", err)
	}
}

// TestParseSettingsRejectsGitHubAppOverStdio proves github_app targets fail
// closed at config parse: no mint callback crosses the request boundary.
func TestParseSettingsRejectsGitHubAppOverStdio(t *testing.T) {
	t.Parallel()

	target := validTarget()
	target["auth_mode"] = "github_app"
	target["token_env"] = ""
	target["github_app_id_env"] = "GITHUB_APP_ID"
	_, err := parseSettings(map[string]any{
		"targets": []any{target},
	}, func(key string) string { return "credential-value" }, hostMintedScope)
	if err == nil {
		t.Fatal("parseSettings() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "github_app") {
		t.Fatalf("error %q does not name the unsupported auth mode", err)
	}
}

// TestParseSettingsRequiresTargets proves an activation without targets
// fails before any client exists. No grant material is required: the host
// enforces authorization at emission.
func TestParseSettingsRequiresTargets(t *testing.T) {
	t.Parallel()

	if _, err := parseSettings(map[string]any{},
		func(string) string { return "x" }, hostMintedScope); err == nil {
		t.Fatal("config without targets: parseSettings() error = nil, want non-nil")
	}
	parsed, err := parseSettings(map[string]any{"targets": []any{validTarget()}},
		func(string) string { return "token-value" }, hostMintedScope)
	if err != nil {
		t.Fatalf("config with targets but no grant: parseSettings() error = %v, want nil", err)
	}
	if len(parsed.targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(parsed.targets))
	}
}

// TestParseSettingsAcceptsLiveActivationEnvelope proves the host contract:
// the activation config block arrives verbatim, including the shared
// host-level limits stanza, with no grant material. This mirrors the literal
// ops-qa activation (eshu-hq/eshu#8866); rejecting it fails production closed.
func TestParseSettingsAcceptsLiveActivationEnvelope(t *testing.T) {
	t.Parallel()

	getenv := func(key string) string {
		if key == "GITHUB_TOKEN" {
			return "secret-value"
		}
		return ""
	}
	parsed, err := parseSettings(map[string]any{
		"targets": []any{
			map[string]any{
				"provider": "github_dependabot", "scope": "repository",
				"scope_id":   "security-alert:github:boatsgroup/iac-eks-eshu",
				"repository": "boatsgroup/iac-eks-eshu", "token_env": "GITHUB_TOKEN",
				"max_pages": float64(5), "repository_alert_limit": float64(100),
				"allowed_repositories": []any{"boatsgroup/iac-eks-eshu"},
			},
		},
		"limits": map[string]any{
			"maxRecordsPerClaim": float64(50000), "maxPayloadBytes": float64(1048576),
			"maxResultBytes": float64(3145728), "claimTimeoutSeconds": float64(300),
		},
	}, getenv, "security-alert:github:boatsgroup/iac-eks-eshu")
	if err != nil {
		t.Fatalf("parseSettings(live envelope) error = %v", err)
	}
	if len(parsed.targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(parsed.targets))
	}
}

// TestParseSettingsRejectsUnknownKeys proves a typo in the activation fails
// closed instead of silently running with defaults. The shared host-level
// limits stanza is allowlisted; anything else unknown still fails.
func TestParseSettingsRejectsUnknownKeys(t *testing.T) {
	t.Parallel()

	if _, err := parseSettings(map[string]any{
		"targets":  []any{validTarget()},
		"typo_key": map[string]any{"max_pages": float64(2)},
	}, func(string) string { return "x" }, hostMintedScope); err == nil {
		t.Fatal("config with unknown key: parseSettings() error = nil, want non-nil")
	}
}

// TestParseRequestRejectsBadShapes proves the stdio boundary fails closed on
// trailing JSON, unknown fields, a foreign protocol, and a foreign
// collector kind.
func TestParseRequestRejectsBadShapes(t *testing.T) {
	t.Parallel()

	base, err := marshalRequestForTest()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(string) string{
		"trailing JSON":    func(s string) string { return s + " {}" },
		"unknown field":    func(s string) string { return strings.Replace(s, `"claim":`, `"bogus":1,"claim":`, 1) },
		"foreign protocol": func(s string) string { return strings.Replace(s, sdk.ProtocolVersionV1Alpha1, "other/v9", 1) },
		"foreign kind": func(s string) string {
			return strings.Replace(s, `"collector_kind":"security_alert"`, `"collector_kind":"package_registry"`, 1)
		},
		"missing generation": func(s string) string {
			return strings.Replace(s, `"generation_id":"security-alert:generation-9",`, "", 1)
		},
	}
	for name, mutate := range cases {
		if _, err := ParseRequest(strings.NewReader(mutate(base))); err == nil {
			t.Fatalf("%s: ParseRequest() error = nil, want non-nil", name)
		}
	}
}
