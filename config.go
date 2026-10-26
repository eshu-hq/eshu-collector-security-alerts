// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eshu-hq/eshu-collector-security-alerts/securityalert"
)

// targetJSON is the activation config shape for one provider target. It
// mirrors the in-tree claimed runtime configuration (eshu-hq/eshu
// go/cmd/collector-security-alerts config.go): the same fields, the same
// token_env credential indirection, and the same fail-closed credential mix
// rules.
type targetJSON struct {
	Provider                   string   `json:"provider"`
	Scope                      string   `json:"scope"`
	ScopeID                    string   `json:"scope_id"`
	Repository                 string   `json:"repository"`
	Organization               string   `json:"organization"`
	TokenEnv                   string   `json:"token_env"`
	AuthMode                   string   `json:"auth_mode"`
	GitHubAppIDEnv             string   `json:"github_app_id_env"`
	GitHubAppInstallationIDEnv string   `json:"github_app_installation_id_env"`
	GitHubAppPrivateKeyEnv     string   `json:"github_app_private_key_env"`
	AllowedRepositories        []string `json:"allowed_repositories"`
	APIBaseURL                 string   `json:"api_base_url"`
	RepositoryAlertLimit       int      `json:"repository_alert_limit"`
	MaxPages                   int      `json:"max_pages"`
	SourceURI                  string   `json:"source_uri"`
}

// limitsJSON is the shared host-level limits stanza. It carries no
// satellite-side consumer today; it is accepted so the verbatim envelope
// parses and host-side enforcement stays the single owner.
type limitsJSON struct {
	MaxRecordsPerClaim  int `json:"maxRecordsPerClaim"`
	MaxPayloadBytes     int `json:"maxPayloadBytes"`
	MaxResultBytes      int `json:"maxResultBytes"`
	ClaimTimeoutSeconds int `json:"claimTimeoutSeconds"`
}

// settings is the parsed activation: the producer targets. The host
// delivers the activation config block verbatim, including its shared
// limits stanza; authorization material never arrives here because
// core-owned-kind authorization is host-enforced at emission.
type settings struct {
	targets []securityalert.TargetConfig
}

// parseSettings decodes the activation config into producer targets. The
// claim's instance id becomes the producer's collector identity. Credential
// values never enter errors: a missing token names the variable, never its
// content.
func parseSettings(config map[string]any, getenv func(string) string) (settings, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return settings{}, fmt.Errorf("encode config: %w", err)
	}
	var decoded struct {
		Targets []targetJSON `json:"targets"`
		Limits  *limitsJSON  `json:"limits"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return settings{}, fmt.Errorf("decode config: %s", decodeReason(err))
	}
	if len(decoded.Targets) == 0 {
		return settings{}, fmt.Errorf("config targets are required")
	}
	targets := make([]securityalert.TargetConfig, 0, len(decoded.Targets))
	for i, target := range decoded.Targets {
		mapped, err := mapTarget(target, getenv)
		if err != nil {
			return settings{}, fmt.Errorf("targets[%d]: %w", i, err)
		}
		targets = append(targets, mapped)
	}
	return settings{
		targets: targets,
	}, nil
}

// mapTarget resolves one configured target against the process environment,
// mirroring the in-tree claimed runtime mapping. A static token_env target
// resolves its credential once at startup. A github_app target fails closed
// here: installation-token minting is host-owned and no mint callback crosses
// the stdio boundary, so the stdio entrypoint cannot serve one.
func mapTarget(target targetJSON, getenv func(string) string) (securityalert.TargetConfig, error) {
	authMode := strings.ToLower(strings.TrimSpace(target.AuthMode))
	if authMode == "" {
		authMode = securityalert.AuthModeTokenEnv
	}
	switch authMode {
	case securityalert.AuthModeTokenEnv:
		if strings.TrimSpace(target.GitHubAppIDEnv) != "" ||
			strings.TrimSpace(target.GitHubAppInstallationIDEnv) != "" ||
			strings.TrimSpace(target.GitHubAppPrivateKeyEnv) != "" {
			return securityalert.TargetConfig{}, fmt.Errorf("github_app env references must be empty when auth_mode is %q", securityalert.AuthModeTokenEnv)
		}
		tokenEnv := strings.TrimSpace(target.TokenEnv)
		token := ""
		if tokenEnv != "" && getenv != nil {
			token = strings.TrimSpace(getenv(tokenEnv))
		}
		if token == "" {
			return securityalert.TargetConfig{}, fmt.Errorf("token_env %s did not resolve a credential", tokenEnv)
		}
		return securityalert.TargetConfig{
			Provider:             strings.TrimSpace(target.Provider),
			Scope:                strings.TrimSpace(target.Scope),
			ScopeID:              strings.TrimSpace(target.ScopeID),
			Repository:           strings.Trim(target.Repository, "/"),
			Organization:         strings.Trim(target.Organization, "/"),
			Token:                token,
			AuthMode:             securityalert.AuthModeTokenEnv,
			AllowedRepositories:  cleanStrings(target.AllowedRepositories),
			APIBaseURL:           strings.TrimRight(strings.TrimSpace(target.APIBaseURL), "/"),
			RepositoryAlertLimit: target.RepositoryAlertLimit,
			MaxPages:             target.MaxPages,
			SourceURI:            strings.TrimSpace(firstNonBlank(target.SourceURI, target.APIBaseURL)),
		}, nil
	case securityalert.AuthModeGitHubApp:
		return securityalert.TargetConfig{}, fmt.Errorf("auth_mode %q is not served over stdio: installation-token minting is host-owned and no mint callback crosses the request boundary", securityalert.AuthModeGitHubApp)
	default:
		return securityalert.TargetConfig{}, fmt.Errorf("unsupported security alert auth_mode %q", strings.TrimSpace(target.AuthMode))
	}
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
