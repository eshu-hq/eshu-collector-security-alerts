// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
