// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/eshu-hq/eshu-sdk/collector/transport"
)

// GitHubDependabotError is a bounded provider error. It deliberately omits
// repositories, tokens, URLs, and raw response bodies from Error(). Operation
// names the bounded endpoint token for the call that failed; it never
// carries a repository, organization, URL, or credential, and stays blank
// for validation failures that never reached a provider endpoint.
type GitHubDependabotError struct {
	StatusCode int
	Message    string
	RateLimit  GitHubRateLimitInfo
	Operation  string
	// FailureClassOverride, when set to a GitHubDependabotFailure* constant,
	// replaces the status-derived class. It carries mode-specific mappings
	// a status cannot express: an alert-read 401 under GitHub App auth is an
	// expired installation token (retryable), and a mint failure has no
	// alert status at all.
	FailureClassOverride string
	// AlertsDisabled marks a 403, with no rate-limit signal, whose JSON body
	// says Dependabot alerts are disabled for the repository. It never
	// carries the message. FailureClass reports not_found for it: a disabled
	// alert surface is a property of the target, not of the credential.
	AlertsDisabled bool
	Cause          error
}

// FailureOperation returns the bounded endpoint token for the failed call,
// or "" when the failure carries none.
func (e GitHubDependabotError) FailureOperation() string {
	return e.Operation
}

// Error returns a bounded provider failure message safe for logs and status.
func (e GitHubDependabotError) Error() string {
	message := strings.TrimSpace(e.Message)
	if message == "" {
		message = "github dependabot request failed"
	}
	if e.StatusCode != 0 {
		return fmt.Sprintf("%s: status %d", message, e.StatusCode)
	}
	return message
}

// Unwrap returns the underlying provider or transport cause when present.
func (e GitHubDependabotError) Unwrap() error {
	return e.Cause
}

// FailureClass returns the bounded workflow retry class for this provider
// failure.
func (e GitHubDependabotError) FailureClass() string {
	if e.FailureClassOverride != "" {
		return e.FailureClassOverride
	}
	switch {
	case e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden:
		if e.RateLimit.RetryAfter != 0 ||
			(e.RateLimit.RemainingKnown && e.RateLimit.Remaining == 0) {
			return GitHubDependabotFailureRateLimited
		}
		if e.StatusCode == http.StatusForbidden && e.AlertsDisabled {
			// A disabled Dependabot surface is a property of the target, not
			// of the credential: it classifies as not_found.
			return GitHubDependabotFailureNotFound
		}
		return GitHubDependabotFailureAuthDenied
	case e.StatusCode == http.StatusTooManyRequests:
		return GitHubDependabotFailureRateLimited
	case e.StatusCode == http.StatusNotFound:
		return GitHubDependabotFailureNotFound
	case e.StatusCode >= http.StatusInternalServerError:
		return GitHubDependabotFailureRetryable
	case e.StatusCode != 0:
		return GitHubDependabotFailureTerminal
	default:
		return GitHubDependabotFailureRetryable
	}
}

// TerminalFailure reports whether the failure should stop retrying the
// current work item until configuration changes.
func (e GitHubDependabotError) TerminalFailure() bool {
	switch e.FailureClass() {
	case GitHubDependabotFailureAuthDenied, GitHubDependabotFailureNotFound, GitHubDependabotFailureTerminal:
		return true
	default:
		return false
	}
}

func normalizeOrganizationLogin(organization string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(organization), "/"))
}

func normalizeRepositoryFullName(repository string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(repository), "/"), "/")
	if len(parts) != 2 {
		return ""
	}
	owner := strings.ToLower(strings.TrimSpace(parts[0]))
	repo := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parts[1]), ".git"))
	if owner == "" || repo == "" {
		return ""
	}
	return owner + "/" + repo
}

func parseGitHubRateLimit(header http.Header) GitHubRateLimitInfo {
	info := GitHubRateLimitInfo{}
	if remaining, err := strconv.Atoi(strings.TrimSpace(header.Get("X-RateLimit-Remaining"))); err == nil {
		info.Remaining = remaining
		info.RemainingKnown = true
	}
	if reset, err := strconv.ParseInt(strings.TrimSpace(header.Get("X-RateLimit-Reset")), 10, 64); err == nil && reset > 0 {
		info.Reset = time.Unix(reset, 0).UTC()
	}
	info.RetryAfter = transport.ParseRetryAfterHeader(header.Get("Retry-After"))
	return info
}

func nextDependabotAlertsURL(currentEndpoint string, raw string) string {
	current, err := url.Parse(currentEndpoint)
	if err != nil {
		return ""
	}
	for _, link := range strings.Split(raw, ",") {
		if !strings.Contains(link, `rel="next"`) {
			continue
		}
		start := strings.Index(link, "<")
		end := strings.Index(link, ">")
		if start < 0 || end <= start {
			continue
		}
		next, err := url.Parse(strings.TrimSpace(link[start+1 : end]))
		if err != nil || next.Scheme != current.Scheme || next.Host != current.Host {
			continue
		}
		query := next.Query()
		query.Set("state", githubDependabotOpenAlertState)
		next.RawQuery = query.Encode()
		return next.String()
	}
	return ""
}

// readGitHubErrorBody reads a bounded provider error body. A body that is
// missing, unreadable, or over the bound reports incomplete so callers never
// decide on a truncated signal.
func readGitHubErrorBody(body io.Reader) (data []byte, ok bool) {
	data, err := io.ReadAll(io.LimitReader(body, maxGitHubErrorBodyBytes+1))
	if err != nil || len(data) > maxGitHubErrorBodyBytes {
		return nil, false
	}
	return data, true
}

// githubBodySaysAlertsDisabled reports whether a complete JSON error body
// has a string "message" naming disabled Dependabot alerts. The message text
// is only compared, never stored or returned.
func githubBodySaysAlertsDisabled(data []byte) bool {
	var envelope struct {
		Message any `json:"message"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return false
	}
	message, ok := envelope.Message.(string)
	return ok && strings.Contains(strings.ToLower(message), githubAlertsDisabledMessage)
}

// markAlertsDisabled records the disabled-surface signal on a complete,
// rate-limit-free 403 body. Any other shape leaves the failure untouched.
func (e *GitHubDependabotError) markAlertsDisabled(body []byte, complete bool) {
	if e.StatusCode != http.StatusForbidden || !complete {
		return
	}
	if e.RateLimit.RetryAfter != 0 ||
		(e.RateLimit.RemainingKnown && e.RateLimit.Remaining == 0) {
		return
	}
	e.AlertsDisabled = githubBodySaysAlertsDisabled(body)
}
