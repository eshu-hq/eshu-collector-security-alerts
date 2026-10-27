// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"time"

	"github.com/eshu-hq/eshu-sdk/collector"
)

// MetricsRecorder is the host-wired seam for collector telemetry. The
// in-tree producer records eshu_dp_security_alert_* signals on core-owned
// instruments; those instruments stay core-owned after extraction. The
// extracted producer records the same call sites against this minimal
// interface so a host can adapt them to its own signals. A nil recorder
// disables recording. DiscardMetrics returns the no-op recorder.
type MetricsRecorder interface {
	// RecordFetch records one bounded provider request and its latency.
	RecordFetch(provider string, statusClass string, latency time.Duration)
	// RecordRateLimited records provider-throttled requests.
	RecordRateLimited(provider string, count int)
	// RecordFactsEmitted records emitted facts by kind.
	RecordFactsEmitted(provider string, counts map[string]int64)
	// RecordTruncatedReads records provider reads that hit max_pages before
	// the provider stream ended. The operation is a bounded endpoint token,
	// never a repository, organization, URL, or credential.
	RecordTruncatedReads(provider string, operation string, count int)
	// RecordFanoutOutcome records one allowlisted repository handled by an
	// org fan-out, labeled by its closed outcome.
	RecordFanoutOutcome(provider string, outcome string, count int)
}

type discardMetrics struct{}

// DiscardMetrics returns the no-op MetricsRecorder.
func DiscardMetrics() MetricsRecorder {
	return discardMetrics{}
}

func (discardMetrics) RecordFetch(string, string, time.Duration)   {}
func (discardMetrics) RecordRateLimited(string, int)               {}
func (discardMetrics) RecordFactsEmitted(string, map[string]int64) {}
func (discardMetrics) RecordTruncatedReads(string, string, int)    {}
func (discardMetrics) RecordFanoutOutcome(string, string, int)     {}

func (s *ClaimedSource) metrics() MetricsRecorder {
	if s == nil || s.recorder == nil {
		return DiscardMetrics()
	}
	return s.recorder
}

func (s *ClaimedSource) recordFetch(target TargetConfig, statusClass string, startedAt time.Time) {
	s.metrics().RecordFetch(target.Provider, statusClass, time.Since(startedAt))
}

func (s *ClaimedSource) recordRateLimit(target TargetConfig, class string) {
	if class != GitHubDependabotFailureRateLimited {
		return
	}
	s.metrics().RecordRateLimited(target.Provider, 1)
}

func (s *ClaimedSource) recordFacts(target TargetConfig, facts []collector.Fact) {
	if len(facts) == 0 {
		return
	}
	counts := map[string]int64{}
	for _, fact := range facts {
		counts[fact.Kind]++
	}
	s.metrics().RecordFactsEmitted(target.Provider, counts)
}

// recordTruncatedRead counts one provider read that hit max_pages before the
// provider stream ended.
func (s *ClaimedSource) recordTruncatedRead(target TargetConfig, operation string) {
	s.metrics().RecordTruncatedReads(target.Provider, operation, 1)
}

// recordFanoutOutcome counts one allowlisted repository handled by the org
// fan-out, labeled by its closed outcome.
func (s *ClaimedSource) recordFanoutOutcome(target TargetConfig, outcome string) {
	s.metrics().RecordFanoutOutcome(target.Provider, outcome, 1)
}
