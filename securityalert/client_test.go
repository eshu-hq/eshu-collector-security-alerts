// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testAlertJSON(number int, state string) string {
	alerts, _ := json.Marshal([]GitHubDependabotAlert{{
		Number:    number,
		State:     state,
		HTMLURL:   "https://github.com/example-org/example-repo/security/dependabot/42",
		CreatedAt: "2026-05-20T12:00:00Z",
		UpdatedAt: "2026-05-23T10:15:00Z",
		Dependency: GitHubDependabotDependency{
			ManifestPath: "package-lock.json",
			Scope:        "runtime",
			Package:      GitHubDependabotPackage{Ecosystem: "npm", Name: "left-pad"},
			Relationship: "direct",
		},
		SecurityAdvisory: GitHubDependabotSecurityAdvisory{
			GHSAID:   "GHSA-abcd-1234",
			Severity: "high",
		},
		SecurityVulnerability: GitHubDependabotSecurityVulnerability{
			VulnerableVersionRange: "<1.2.3",
			FirstPatchedVersion:    GitHubDependabotVersion{Identifier: "1.2.3"},
		},
	}})
	return string(alerts)
}

func testClient(t *testing.T, handler http.Handler) (GitHubDependabotClient, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewGitHubDependabotClient(GitHubDependabotClientConfig{
		BaseURL:              server.URL,
		Token:                "token-value",
		AllowedRepositories:  []string{"example-org/example-repo"},
		RepositoryAlertLimit: 25,
	}), server
}

func TestListRepositoryAlertsSendsBearerHeaderAndStateFilter(t *testing.T) {
	t.Parallel()

	var gotAuth, gotAccept, gotVersion, gotQuery string
	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotVersion = r.Header.Get("X-GitHub-Api-Version")
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testAlertJSON(42, "open")))
	}))

	alerts, err := client.ListRepositoryAlerts(context.Background(), "example-org/example-repo")
	if err != nil {
		t.Fatalf("ListRepositoryAlerts() error = %v, want nil", err)
	}
	if len(alerts) != 1 || alerts[0].Number != 42 {
		t.Fatalf("alerts = %+v, want one alert 42", alerts)
	}
	if gotAuth != "Bearer token-value" {
		t.Errorf("Authorization = %q, want Bearer transport without credential leak", gotAuth)
	}
	if gotAccept != "application/vnd.github+json" {
		t.Errorf("Accept = %q, want GitHub JSON media type", gotAccept)
	}
	if gotVersion == "" {
		t.Error("X-GitHub-Api-Version missing")
	}
	if !strings.Contains(gotQuery, "state=open") {
		t.Errorf("query = %q, want state=open filter", gotQuery)
	}
}

func TestListRepositoryAlertsRequiresAllowlist(t *testing.T) {
	t.Parallel()

	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[]"))
	}))
	if _, err := client.ListRepositoryAlerts(context.Background(), "other-org/private-repo"); err == nil {
		t.Fatal("ListRepositoryAlerts(unallowlisted) = nil, want allowlist error")
	}
	missingToken := NewGitHubDependabotClient(GitHubDependabotClientConfig{
		BaseURL:             "https://api.github.test",
		AllowedRepositories: []string{"example-org/example-repo"},
	})
	if _, err := missingToken.ListRepositoryAlerts(context.Background(), "example-org/example-repo"); err == nil {
		t.Fatal("ListRepositoryAlerts() = nil, want missing token error")
	}
}

func TestListRepositoryAlertsPaginatesUntilLinkExhausted(t *testing.T) {
	t.Parallel()

	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		if page == "" || page == "1" {
			w.Header().Set("Link", `<http://`+r.Host+`/repos/x?page=2>; rel="next"`)
			_, _ = w.Write([]byte(testAlertJSON(1, "open")))
			return
		}
		_, _ = w.Write([]byte(testAlertJSON(2, "open")))
	}))

	result, err := client.ListRepositoryAlertsPages(context.Background(), "example-org/example-repo", 2)
	if err != nil {
		t.Fatalf("ListRepositoryAlertsPages() error = %v, want nil", err)
	}
	if result.PagesFetched != 2 || result.Truncated {
		t.Errorf("PagesFetched = %d, Truncated = %v; want 2, false", result.PagesFetched, result.Truncated)
	}
	if len(result.Alerts) != 2 {
		t.Errorf("len(Alerts) = %d, want 2", len(result.Alerts))
	}
}

func TestListRepositoryAlertsTruncatesPastMaxPages(t *testing.T) {
	t.Parallel()

	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<http://`+r.Host+`/repos/x?page=99>; rel="next"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testAlertJSON(1, "open")))
	}))

	result, err := client.ListRepositoryAlertsPages(context.Background(), "example-org/example-repo", 1)
	if err != nil {
		t.Fatalf("ListRepositoryAlertsPages() error = %v, want nil", err)
	}
	if !result.Truncated {
		t.Error("Truncated = false, want true past max_pages")
	}
}

func TestListAlertsPageFailureClasses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		status    int
		headers   map[string]string
		body      string
		appAuth   bool
		wantClass string
		wantRetry bool
	}{
		{"unauthorized is terminal", http.StatusUnauthorized, nil, "{}", false, GitHubDependabotFailureAuthDenied, false},
		{"app 401 is retryable mint", http.StatusUnauthorized, nil, "{}", true, GitHubDependabotFailureRetryable, true},
		{"rate limited", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}, "{}", false, GitHubDependabotFailureRateLimited, true},
		{"not found", http.StatusNotFound, nil, "{}", false, GitHubDependabotFailureNotFound, false},
		{"too many requests", http.StatusTooManyRequests, nil, "{}", false, GitHubDependabotFailureRateLimited, true},
		{"server error retryable", http.StatusBadGateway, nil, "{}", false, GitHubDependabotFailureRetryable, true},
		{"disabled surface is not found", http.StatusForbidden, nil, `{"message":"Dependabot alerts are disabled for this repository"}`, false, GitHubDependabotFailureNotFound, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for key, value := range tt.headers {
					w.Header().Set(key, value)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			live := NewGitHubDependabotClient(GitHubDependabotClientConfig{
				BaseURL:              server.URL,
				Token:                "token-value",
				AllowedRepositories:  []string{"example-org/example-repo"},
				RepositoryAlertLimit: 25,
				AppAuth:              tt.appAuth,
			})
			_, err := live.ListRepositoryAlerts(context.Background(), "example-org/example-repo")
			providerErr, ok := err.(GitHubDependabotError)
			if !ok {
				t.Fatalf("error type = %T, want GitHubDependabotError", err)
			}
			if providerErr.FailureClass() != tt.wantClass {
				t.Errorf("FailureClass() = %q, want %q", providerErr.FailureClass(), tt.wantClass)
			}
			if providerErr.TerminalFailure() == tt.wantRetry {
				t.Errorf("TerminalFailure() = %v, want %v", providerErr.TerminalFailure(), !tt.wantRetry)
			}
			if strings.Contains(providerErr.Error(), "token-value") {
				t.Errorf("bounded error carries credential: %q", providerErr.Error())
			}
		})
	}
}

func TestCrossHostLinkRejected(t *testing.T) {
	t.Parallel()

	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example.test/repos/x?page=2>; rel="next"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(testAlertJSON(1, "open")))
	}))

	result, err := client.ListRepositoryAlertsPages(context.Background(), "example-org/example-repo", 3)
	if err != nil {
		t.Fatalf("ListRepositoryAlertsPages() error = %v, want nil", err)
	}
	if result.Truncated || result.PagesFetched != 1 {
		t.Errorf("PagesFetched = %d, Truncated = %v; cross-host next link must be dropped", result.PagesFetched, result.Truncated)
	}
}

func TestResolveTokenUsesProviderPerCall(t *testing.T) {
	t.Parallel()

	calls := 0
	client := NewGitHubDependabotClient(GitHubDependabotClientConfig{
		BaseURL:             "https://api.github.test",
		AllowedRepositories: []string{"example-org/example-repo"},
		AppAuth:             true,
		TokenProvider: func(ctx context.Context) (string, error) {
			calls++
			return "minted-token", nil
		},
	})
	first, err := client.resolveToken(context.Background(), dependabotRepositoryAlertsOperation)
	if err != nil {
		t.Fatalf("resolveToken() error = %v, want nil", err)
	}
	second, err := client.resolveToken(context.Background(), dependabotRepositoryAlertsOperation)
	if err != nil {
		t.Fatalf("resolveToken() error = %v, want nil", err)
	}
	if first != "minted-token" || second != "minted-token" || calls != 2 {
		t.Errorf("tokens = %q, %q, calls = %d; want fresh mint per call", first, second, calls)
	}
	// With no credential configured, resolveToken yields the empty static
	// token and the listing call fails closed with the required-token
	// error instead.
	emptyClient := NewGitHubDependabotClient(GitHubDependabotClientConfig{
		BaseURL:             "https://api.github.test",
		AllowedRepositories: []string{"example-org/example-repo"},
	})
	if token, err := emptyClient.resolveToken(context.Background(), dependabotRepositoryAlertsOperation); err != nil || token != "" {
		t.Errorf("resolveToken(no credential) = %q, %v; want empty token, nil error", token, err)
	}
	if _, err := emptyClient.ListRepositoryAlerts(context.Background(), "example-org/example-repo"); err == nil {
		t.Error("ListRepositoryAlerts(no credential) = nil, want missing credential error")
	}
}

func TestListRepositoryAlertsMarksTruncatedWhenPageExceedsLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		overLimit := make([]GitHubDependabotAlert, 4)
		for i := range overLimit {
			overLimit[i].Number = i + 1
			overLimit[i].State = "open"
		}
		raw, err := json.Marshal(overLimit)
		if err != nil {
			t.Errorf("marshal over-limit page: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(server.Close)
	client := NewGitHubDependabotClient(GitHubDependabotClientConfig{
		BaseURL:              server.URL,
		Token:                "token-value",
		AllowedRepositories:  []string{"example-org/example-repo"},
		RepositoryAlertLimit: 2,
	})

	result, err := client.ListRepositoryAlertsPages(context.Background(), "example-org/example-repo", 1)
	if err != nil {
		t.Fatalf("ListRepositoryAlertsPages() error = %v, want nil", err)
	}
	if len(result.Alerts) != 2 {
		t.Errorf("len(Alerts) = %d, want clamped to limit 2", len(result.Alerts))
	}
	if !result.Truncated {
		t.Error("Truncated = false, want true: the per-page clamp dropped provider alerts")
	}
}

func TestRateLimitMetadataParsed(t *testing.T) {
	t.Parallel()

	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "12")
		w.Header().Set("X-RateLimit-Reset", "1780000000")
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))

	result, err := client.ListRepositoryAlertsPages(context.Background(), "example-org/example-repo", 1)
	if err != nil {
		t.Fatalf("ListRepositoryAlertsPages() error = %v, want nil", err)
	}
	if !result.RateLimit.RemainingKnown || result.RateLimit.Remaining != 12 {
		t.Errorf("RateLimit = %+v, want remaining 12 known", result.RateLimit)
	}
	if result.RateLimit.Reset.Unix() != 1780000000 {
		t.Errorf("Reset = %v, want 1780000000", result.RateLimit.Reset)
	}
	if result.RateLimit.RetryAfter != 5*time.Second {
		t.Errorf("RetryAfter = %v, want 5s", result.RateLimit.RetryAfter)
	}
}
