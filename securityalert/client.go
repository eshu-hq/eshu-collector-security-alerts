// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eshu-hq/eshu-sdk/collector/transport"
)

const (
	defaultGitHubAPIBaseURL        = "https://api.github.com"
	defaultGitHubDependabotVersion = "2022-11-28"
	githubDependabotOpenAlertState = "open"
	defaultRepositoryAlertLimit    = 100
	defaultRepositoryAlertMaxPages = 1
	maxGitHubErrorBodyBytes        = 4096
	githubAlertsDisabledMessage    = "dependabot alerts are disabled"
)

const (
	// GitHubDependabotFailureAuthDenied classifies missing or forbidden
	// credentials as terminal until operators rotate or grant credentials.
	GitHubDependabotFailureAuthDenied = "auth_denied"
	// GitHubDependabotFailureNotFound classifies missing repositories or
	// disabled Dependabot surfaces as terminal for the current target.
	GitHubDependabotFailureNotFound = "not_found"
	// GitHubDependabotFailureRateLimited classifies GitHub primary or
	// secondary rate-limit responses as retryable.
	GitHubDependabotFailureRateLimited = "rate_limited"
	// GitHubDependabotFailureRetryable classifies transient transport or 5xx
	// provider failures as retryable.
	GitHubDependabotFailureRetryable = "retryable"
	// GitHubDependabotFailureTerminal classifies malformed requests and other
	// bounded non-retryable provider failures as terminal.
	GitHubDependabotFailureTerminal = "terminal"
)

// Bounded Dependabot endpoint tokens. The token names the endpoint shape
// (per-repository or organization-wide), never the repository,
// organization, URL, or credential.
const (
	dependabotRepositoryAlertsOperation   = "list_repo_alerts"
	dependabotOrganizationAlertsOperation = "list_org_alerts"
)

// GitHubDependabotClientConfig configures the bounded GitHub Dependabot
// alert source. Token and repository allowlists are required before any
// HTTP request.
//
// For GitHub App auth, set AppAuth and TokenProvider instead of Token: the
// host mints one installation token per listing call, so sequential claims
// always send a fresh credential and no token is cached on the client.
// Minting itself is host-owned; this package only threads the provider.
type GitHubDependabotClientConfig struct {
	BaseURL              string
	Token                string
	AllowedRepositories  []string
	RepositoryAlertLimit int
	HTTPClient           *http.Client
	AppAuth              bool
	TokenProvider        func(ctx context.Context) (string, error)
}

// GitHubDependabotClient reads repository-scoped GitHub Dependabot alerts.
type GitHubDependabotClient struct {
	baseURL             string
	token               string
	allowedRepositories map[string]struct{}
	repositoryLimit     int
	httpClient          *http.Client
	appAuth             bool
	tokenProvider       func(ctx context.Context) (string, error)
}

// NewGitHubDependabotClient builds a GitHub Dependabot alert client. It does
// not validate credentials until a request is made so callers can construct
// disabled sources from optional config.
func NewGitHubDependabotClient(config GitHubDependabotClientConfig) GitHubDependabotClient {
	baseURL := strings.TrimRight(strings.TrimSpace(config.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultGitHubAPIBaseURL
	}
	limit := config.RepositoryAlertLimit
	if limit <= 0 || limit > defaultRepositoryAlertLimit {
		limit = defaultRepositoryAlertLimit
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = transport.DefaultHTTPClient(30 * time.Second)
	}
	allowed := make(map[string]struct{}, len(config.AllowedRepositories))
	for _, repository := range config.AllowedRepositories {
		if normalized := normalizeRepositoryFullName(repository); normalized != "" {
			allowed[normalized] = struct{}{}
		}
	}
	// The provider is the source of truth for App mode: a set provider
	// always marks expiry-style 401s retryable, even when a caller forgets
	// AppAuth, so a half-wired config cannot silently flip to terminal.
	appAuth := config.AppAuth || config.TokenProvider != nil
	return GitHubDependabotClient{
		baseURL:             baseURL,
		token:               strings.TrimSpace(config.Token),
		allowedRepositories: allowed,
		repositoryLimit:     limit,
		httpClient:          httpClient,
		appAuth:             appAuth,
		tokenProvider:       config.TokenProvider,
	}
}

// ListRepositoryAlerts returns one bounded page of Dependabot alerts for an
// explicitly allowlisted repository.
func (c GitHubDependabotClient) ListRepositoryAlerts(
	ctx context.Context,
	repository string,
) ([]GitHubDependabotAlert, error) {
	result, err := c.ListRepositoryAlertsPages(ctx, repository, defaultRepositoryAlertMaxPages)
	if err != nil {
		return nil, err
	}
	return result.Alerts, nil
}

// ListRepositoryAlertsPages returns bounded Dependabot alert pages for an
// explicitly allowlisted repository.
func (c GitHubDependabotClient) ListRepositoryAlertsPages(
	ctx context.Context,
	repository string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	if c.tokenProvider == nil && c.token == "" {
		return GitHubDependabotAlertResult{}, GitHubDependabotError{
			Message: "github dependabot token is required",
		}
	}
	repository = normalizeRepositoryFullName(repository)
	if repository == "" {
		return GitHubDependabotAlertResult{}, GitHubDependabotError{
			Message: "github dependabot repository scope must not be blank",
		}
	}
	if _, ok := c.allowedRepositories[repository]; !ok {
		return GitHubDependabotAlertResult{}, GitHubDependabotError{
			Message: "github dependabot repository is not allowlisted",
		}
	}
	firstURL, err := c.repositoryAlertsURL(repository)
	if err != nil {
		return GitHubDependabotAlertResult{}, err
	}
	return c.paginateAlerts(ctx, firstURL, maxPages, dependabotRepositoryAlertsOperation)
}

// ListOrganizationAlertsPages returns bounded Dependabot alert pages for an
// organization via GET /orgs/{org}/dependabot/alerts. Each returned alert
// carries its source repository so callers can fan out per-repository facts.
// Pagination, rate-limit metadata, cross-host link rejection, and the
// state=open filter behave identically to the per-repository path.
func (c GitHubDependabotClient) ListOrganizationAlertsPages(
	ctx context.Context,
	organization string,
	maxPages int,
) (GitHubDependabotAlertResult, error) {
	if c.tokenProvider == nil && c.token == "" {
		return GitHubDependabotAlertResult{}, GitHubDependabotError{
			Message: "github dependabot token is required",
		}
	}
	organization = normalizeOrganizationLogin(organization)
	if organization == "" {
		return GitHubDependabotAlertResult{}, GitHubDependabotError{
			Message: "github dependabot organization scope must not be blank",
		}
	}
	firstURL, err := c.organizationAlertsURL(organization)
	if err != nil {
		return GitHubDependabotAlertResult{}, err
	}
	return c.paginateAlerts(ctx, firstURL, maxPages, dependabotOrganizationAlertsOperation)
}

// paginateAlerts walks bounded cursor pages for any Dependabot alert listing
// endpoint, sharing pagination, truncation, and per-call alert clamping so
// the repository and organization paths stay in lockstep. operation names
// the endpoint shape being walked and is stamped onto every page failure.
func (c GitHubDependabotClient) paginateAlerts(
	ctx context.Context,
	firstURL string,
	maxPages int,
	operation string,
) (GitHubDependabotAlertResult, error) {
	if maxPages <= 0 {
		maxPages = defaultRepositoryAlertMaxPages
	}
	token, err := c.resolveToken(ctx, operation)
	if err != nil {
		return GitHubDependabotAlertResult{}, err
	}
	var out GitHubDependabotAlertResult
	nextURL := firstURL
	for page := 1; page <= maxPages; page++ {
		alerts, rateLimit, next, pageTruncated, err := c.listAlertsPage(ctx, nextURL, operation, token)
		out.RateLimit = rateLimit
		if err != nil {
			return GitHubDependabotAlertResult{}, err
		}
		if pageTruncated {
			out.Truncated = true
		}
		out.Alerts = append(out.Alerts, alerts...)
		out.PagesFetched++
		nextURL = next
		if nextURL == "" {
			break
		}
		if page == maxPages {
			out.Truncated = true
		}
	}
	if len(out.Alerts) > c.repositoryLimit*maxPages {
		out.Alerts = out.Alerts[:c.repositoryLimit*maxPages]
		out.Truncated = true
	}
	out.ObservedAt = time.Now().UTC()
	return out, nil
}

func (c GitHubDependabotClient) listAlertsPage(
	ctx context.Context,
	endpoint string,
	operation string,
	token string,
) ([]GitHubDependabotAlert, GitHubRateLimitInfo, string, bool, error) {
	endpoint = strings.TrimSpace(endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, GitHubRateLimitInfo{}, "", false, GitHubDependabotError{
			Message:   "build github dependabot request",
			Operation: operation,
			Cause:     err,
		}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", defaultGitHubDependabotVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, GitHubRateLimitInfo{}, "", false, GitHubDependabotError{
			Message:   "fetch github dependabot alerts",
			Operation: operation,
			Cause: transport.HTTPError{
				Provider: ProviderGitHubDependabot,
				Message:  "request failed",
				Cause:    err,
			},
		}
	}
	defer func() { _ = resp.Body.Close() }()
	rateLimit := parseGitHubRateLimit(resp.Header)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		errorBody, bodyComplete := readGitHubErrorBody(resp.Body)
		httpErr := transport.HTTPError{
			Provider:   ProviderGitHubDependabot,
			StatusCode: resp.StatusCode,
			Message:    http.StatusText(resp.StatusCode),
			RetryAfter: rateLimit.RetryAfter,
		}
		failure := GitHubDependabotError{
			StatusCode: resp.StatusCode,
			Message:    "fetch github dependabot alerts",
			RateLimit:  rateLimit,
			Operation:  operation,
			Cause:      httpErr,
		}
		failure.markAlertsDisabled(errorBody, bodyComplete)
		// An alert-read 401 under GitHub App auth is an expired hourly
		// installation token, not a revoked credential: it stays retryable
		// so the next claim mints fresh, deliberately unlike the static
		// 401 which denies terminally until the operator rotates the PAT.
		if resp.StatusCode == http.StatusUnauthorized && c.appAuth &&
			failure.FailureClass() == GitHubDependabotFailureAuthDenied {
			failure.FailureClassOverride = GitHubDependabotFailureRetryable
		}
		return nil, rateLimit, "", false, failure
	}
	var alerts []GitHubDependabotAlert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		return nil, rateLimit, "", false, GitHubDependabotError{
			Message:   "decode github dependabot alerts",
			Operation: operation,
			Cause:     err,
		}
	}
	// A page larger than the bound drops provider alerts: the page is
	// truncated, and paginateAlerts carries that onto the result so the
	// host never mistakes the clamped page for a complete read.
	if len(alerts) > c.repositoryLimit {
		alerts = alerts[:c.repositoryLimit]
		return alerts, rateLimit, nextDependabotAlertsURL(endpoint, resp.Header.Get("Link")), true, nil
	}
	return alerts, rateLimit, nextDependabotAlertsURL(endpoint, resp.Header.Get("Link")), false, nil
}

func (c GitHubDependabotClient) repositoryAlertsURL(repository string) (string, error) {
	owner, repo, ok := strings.Cut(repository, "/")
	if !ok || owner == "" || repo == "" {
		return "", fmt.Errorf("github dependabot repository must be owner/name")
	}
	parsed, err := transport.ParseBaseURL("github dependabot", c.baseURL)
	if err != nil {
		return "", fmt.Errorf("github dependabot base_url is invalid")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/repos/" +
		url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/dependabot/alerts"
	query := parsed.Query()
	query.Set("per_page", fmt.Sprint(c.repositoryLimit))
	query.Set("state", githubDependabotOpenAlertState)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (c GitHubDependabotClient) organizationAlertsURL(organization string) (string, error) {
	parsed, err := transport.ParseBaseURL("github dependabot", c.baseURL)
	if err != nil {
		return "", fmt.Errorf("github dependabot base_url is invalid")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/orgs/" +
		url.PathEscape(organization) + "/dependabot/alerts"
	query := parsed.Query()
	query.Set("per_page", fmt.Sprint(c.repositoryLimit))
	query.Set("state", githubDependabotOpenAlertState)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// resolveToken returns the Bearer credential for one listing call. A
// configured provider mints it fresh on every call so sequential claims never
// reuse an hourly installation token; otherwise the static configured token
// is used.
func (c GitHubDependabotClient) resolveToken(ctx context.Context, operation string) (string, error) {
	if c.tokenProvider == nil {
		return c.token, nil
	}
	token, err := c.tokenProvider(ctx)
	if err != nil {
		return "", classifyMintError(err, operation)
	}
	if strings.TrimSpace(token) == "" {
		return "", GitHubDependabotError{
			Message:              "github app token provider returned no token",
			Operation:            operation,
			FailureClassOverride: GitHubDependabotFailureAuthDenied,
		}
	}
	return token, nil
}

// MintTransientError marks a host token-mint failure as retryable. The
// host wraps transient mint errors (outlasted transients, rate limits) in
// this type; RateLimited selects the rate_limited class and RetryAfter
// carries bounded retry guidance. Any other mint error is a terminal
// denial (unknown installation or bad key), matching the in-tree table.
type MintTransientError struct {
	RetryAfter  time.Duration
	RateLimited bool
	Cause       error
}

// Error returns a bounded mint-failure string safe for logs and status.
func (e *MintTransientError) Error() string {
	if e == nil || e.Cause == nil {
		return "github app installation token mint failed transiently"
	}
	return "github app installation token mint failed transiently: " + strings.TrimSpace(e.Cause.Error())
}

// Unwrap returns the underlying mint cause when present.
func (e *MintTransientError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// classifyMintError maps a token-provider failure onto the bounded alert
// failure vocabulary without carrying credentials: an unknown installation
// or bad key is a terminal denial, a *MintTransientError (outlasted
// transient or rate limit) stays retryable, and a cancelled context stays
// retryable.
func classifyMintError(err error, operation string) GitHubDependabotError {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return GitHubDependabotError{
			Message:              "mint github app installation token",
			Operation:            operation,
			FailureClassOverride: GitHubDependabotFailureRetryable,
			Cause:                err,
		}
	}
	var transient *MintTransientError
	if errors.As(err, &transient) {
		class := GitHubDependabotFailureRetryable
		if transient.RateLimited {
			class = GitHubDependabotFailureRateLimited
		}
		return GitHubDependabotError{
			Message:              "mint github app installation token",
			Operation:            operation,
			FailureClassOverride: class,
			RateLimit:            GitHubRateLimitInfo{RetryAfter: transient.RetryAfter},
			Cause:                err,
		}
	}
	return GitHubDependabotError{
		Message:              "mint github app installation token",
		Operation:            operation,
		FailureClassOverride: GitHubDependabotFailureAuthDenied,
		Cause:                err,
	}
}
