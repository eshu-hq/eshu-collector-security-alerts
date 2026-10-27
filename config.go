// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"errors"
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

// #nosec G101 -- the flagged string is a config key name, not credential material.
// hostGitHubAppTokenKey is the top-level activation config key carrying the
// per-claim host-minted credential: {"token": ..., "scope_id": ...}. It is
// extracted before target parsing so the DisallowUnknownFields target decode
// never sees it.
const hostGitHubAppTokenKey = "host_github_app_token"

// hostAppToken is the extracted per-claim host-minted credential. Token is
// the only value that may reach a provider request; errors and logs name the
// key, never the value.
type hostAppToken struct {
	// Token is the host-minted credential, trimmed of surrounding
	// whitespace. Empty means no usable credential arrived.
	Token string
	// ScopeID is the claim scope the host minted the credential for.
	ScopeID string
	// Present reports whether the host stanza arrived at all (even an empty
	// one), distinguishing a missing stanza from an empty credential.
	Present bool
}

// settings is the parsed activation: the producer targets. The host
// delivers the activation config block verbatim, including its shared
// limits stanza and, for host_minted targets, the per-claim host-minted
// credential; core-owned-kind authorization material never arrives here
// because authorization is host-enforced at emission.
type settings struct {
	targets []securityalert.TargetConfig
}

// configError is a bounded activation-config failure. The message names
// keys, never credential values; the reason is a stable machine-readable
// code for the diagnostic line, so an operator can tell a missing stanza
// from a wrong-scope mint without ever seeing a secret.
type configError struct {
	reason string
	msg    string
}

func (e *configError) Error() string { return e.msg }

// host failure reason codes carried on configError for the diagnostic line.
const (
	reasonMissingHostToken  = "missing_host_token"
	reasonHostTokenMismatch = "host_token_scope_mismatch"
	reasonMalformedHostKey  = "malformed_host_token"
	reasonNoClaimTarget     = "no_claim_scoped_target"
)

// configFailureReason recovers the bounded reason from a parseSettings
// failure for the diagnostic line. Unclassified failures carry no reason.
func configFailureReason(err error) string {
	var cerr *configError
	if errors.As(err, &cerr) {
		return cerr.reason
	}
	return ""
}

// parseSettings decodes the activation config into producer targets. The
// claim's instance id becomes the producer's collector identity, and the
// claim scope id binds the per-claim host-minted credential to this claim.
// Credential values never enter errors: a missing token names the variable
// or key, never its content.
func parseSettings(config map[string]any, getenv func(string) string, claimScopeID string) (settings, error) {
	host, err := extractHostAppToken(config)
	if err != nil {
		return settings{}, err
	}
	rest := make(map[string]any, len(config))
	for key, value := range config {
		if key == hostGitHubAppTokenKey {
			continue
		}
		rest[key] = value
	}
	raw, err := json.Marshal(rest)
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
		// Only the claim's host_minted target may receive the per-claim
		// credential: a host_minted target scoped elsewhere is dropped from
		// this claim's run instead of inheriting a token minted for a
		// different scope. Collect looks up targets by claim scope, so the
		// dropped target is never spent here; the claim for its own scope
		// keeps it with its own stanza.
		if hostMintedForOtherScope(target, claimScopeID) {
			continue
		}
		mapped, err := mapTarget(target, getenv, host, claimScopeID)
		if err != nil {
			return settings{}, fmt.Errorf("targets[%d]: %w", i, err)
		}
		targets = append(targets, mapped)
	}
	if len(targets) == 0 {
		return settings{}, &configError{reason: reasonNoClaimTarget, msg: "no configured target serves the claim scope"}
	}
	return settings{
		targets: targets,
	}, nil
}

// hostMintedForOtherScope reports whether a target spends per-claim host
// credentials for a scope other than the claim's. Static targets are never
// dropped: their credential resolves from the process environment and carries
// no per-claim binding.
func hostMintedForOtherScope(target targetJSON, claimScopeID string) bool {
	if strings.ToLower(strings.TrimSpace(target.AuthMode)) != securityalert.AuthModeHostMinted {
		return false
	}
	return strings.TrimSpace(target.ScopeID) != strings.TrimSpace(claimScopeID)
}

// extractHostAppToken pulls the per-claim host-minted credential out of the
// top-level activation config, independent of the {targets, limits} decode.
// A missing (or null) stanza is not an error here: targets that need it fail
// closed in mapTarget, while static targets ignore it. A present stanza with
// the wrong shape fails closed without carrying credential material.
func extractHostAppToken(config map[string]any) (hostAppToken, error) {
	raw, ok := config[hostGitHubAppTokenKey]
	if !ok || raw == nil {
		return hostAppToken{}, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return hostAppToken{}, fmt.Errorf("encode %s: %w", hostGitHubAppTokenKey, err)
	}
	var decoded struct {
		Token   string `json:"token"`
		ScopeID string `json:"scope_id"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return hostAppToken{}, &configError{reason: reasonMalformedHostKey, msg: fmt.Sprintf("decode %s: %s", hostGitHubAppTokenKey, decodeReason(err))}
	}
	return hostAppToken{
		Token:   strings.TrimSpace(decoded.Token),
		ScopeID: strings.TrimSpace(decoded.ScopeID),
		Present: true,
	}, nil
}

// mapTarget resolves one configured target against the process environment
// and the per-claim host-minted credential, mirroring the in-tree claimed
// runtime mapping. A static token_env target resolves its credential once at
// startup. A host_minted target spends the host stanza credential, bound to
// the claim scope id, and must carry no credential env reference of its own.
// A github_app target fails closed here: installation-token minting is
// host-owned and no mint callback crosses the stdio boundary, so the stdio
// entrypoint cannot serve one.
func mapTarget(target targetJSON, getenv func(string) string, host hostAppToken, claimScopeID string) (securityalert.TargetConfig, error) {
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
	case securityalert.AuthModeHostMinted:
		if strings.TrimSpace(target.TokenEnv) != "" ||
			strings.TrimSpace(target.GitHubAppIDEnv) != "" ||
			strings.TrimSpace(target.GitHubAppInstallationIDEnv) != "" ||
			strings.TrimSpace(target.GitHubAppPrivateKeyEnv) != "" {
			return securityalert.TargetConfig{}, fmt.Errorf("token_env and github_app env references must be empty when auth_mode is %q", securityalert.AuthModeHostMinted)
		}
		if !host.Present || host.Token == "" {
			return securityalert.TargetConfig{}, &configError{reason: reasonMissingHostToken, msg: fmt.Sprintf("host_github_app_token did not resolve a credential for auth_mode %q", securityalert.AuthModeHostMinted)}
		}
		if scope := strings.TrimSpace(claimScopeID); scope == "" || host.ScopeID != scope {
			return securityalert.TargetConfig{}, &configError{reason: reasonHostTokenMismatch, msg: "host_github_app_token is not scoped to the claim scope"}
		}
		return securityalert.TargetConfig{
			Provider:             strings.TrimSpace(target.Provider),
			Scope:                strings.TrimSpace(target.Scope),
			ScopeID:              strings.TrimSpace(target.ScopeID),
			Repository:           strings.Trim(target.Repository, "/"),
			Organization:         strings.Trim(target.Organization, "/"),
			Token:                host.Token,
			AuthMode:             securityalert.AuthModeHostMinted,
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
