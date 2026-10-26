// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/transport"
)

// Shard and retirement markers. The extracted producer never expands shards
// or answers retirement claims: cross-claim position and retirement stay
// host-owned (see README "Deferred to the host"). A configured scope_id
// carrying a marker is rejected at construction; a claim naming one fails
// closed as an unconfigured scope.
const (
	shardMarker      = "#shard-"
	retirementMarker = "#retire"
)

// maxOrganizationFanoutRepositories caps the bounded per-repository reads
// one org claim may issue after a truncated org read. With the org read
// itself, one claim sends at most max_pages x (1 + cap) provider page
// requests. Repositories past the cap keep their org-window facts with the
// cap-reached coverage reason.
const maxOrganizationFanoutRepositories = 100

// Fanout outcome vocabulary. A repository's own read outcome is stamped on
// the host-visible metrics seam; incomplete reasons ride the fact payload.
const (
	fanoutOutcomeComplete       = "complete"
	fanoutOutcomeTruncated      = "truncated"
	fanoutOutcomeFailed         = "failed"
	fanoutOutcomeRateLimited    = "rate_limited"
	fanoutOutcomeSkippedCap     = "skipped_cap"
	fanoutOutcomeStopped        = "stopped"
	fanoutOutcomeAlertsDisabled = "alerts_disabled"
)

// SourceConfig describes one producer instance: its collector identity, its
// targets, and the host-wired seams.
type SourceConfig struct {
	CollectorInstanceID string
	Targets             []TargetConfig
	// ClientFactory builds provider clients; nil selects the production
	// GitHub client so tests drive the source without a network.
	ClientFactory ClientFactory
	// Now supplies observed-at timestamps; nil selects time.Now.
	Now func() time.Time
	// Metrics receives the host-wired recorder; nil disables recording.
	Metrics MetricsRecorder
}

// TargetConfig describes one provider security-alert target. A repository
// target (Scope=="repository", the default) polls a single allowlisted
// repository. An organization target (Scope=="org") polls one organization
// and fans the result out into per-repository facts.
//
// AuthMode selects the credential shape: AuthModeTokenEnv (the default) uses
// the static Token resolved once at startup, AuthModeHostMinted uses the
// static Token the satellite receives per claim from the host, while
// AuthModeGitHubApp mints an installation token per claim through the
// host-supplied TokenProvider. The shapes never mix on one target, and a
// minted token is never stored here.
type TargetConfig struct {
	Provider                string
	Scope                   string
	ScopeID                 string
	Repository              string
	Organization            string
	Token                   string
	AuthMode                string
	GitHubAppID             string
	GitHubAppInstallationID string
	GitHubAppPrivateKey     string
	TokenProvider           func(ctx context.Context) (string, error)
	AllowedRepositories     []string
	APIBaseURL              string
	RepositoryAlertLimit    int
	MaxPages                int
	SourceURI               string
}

// IsOrganizationScope reports whether the target polls the organization-wide
// Dependabot alerts endpoint.
func (t TargetConfig) IsOrganizationScope() bool {
	return t.Scope == TargetScopeOrganization
}

// RepositoryAllowed reports whether the normalized repository full name is
// explicitly allowlisted for this target.
func (t TargetConfig) RepositoryAllowed(fullName string) bool {
	return repositoryAllowed(fullName, t.AllowedRepositories)
}

// ClientFactory builds provider clients for validated targets.
type ClientFactory func(TargetConfig) (RepositoryAlertClient, error)

// RepositoryAlertClient is the bounded provider surface Collect needs.
type RepositoryAlertClient interface {
	ListRepositoryAlertsPages(ctx context.Context, repository string, maxPages int) (GitHubDependabotAlertResult, error)
	ListOrganizationAlertsPages(ctx context.Context, organization string, maxPages int) (GitHubDependabotAlertResult, error)
}

type targetRuntime struct {
	config TargetConfig
	client RepositoryAlertClient
}

// ClaimedSource resolves host claims into source facts. It owns target
// validation, normalization, envelope construction, and source-local failure
// classification only: admission, projection, persistence, claim mutation,
// fencing, and the status read stay core-owned. Every Collect call enforces
// the core-issued producer grant first and fails closed without one.
type ClaimedSource struct {
	collectorInstanceID string
	targets             map[string]targetRuntime
	now                 func() time.Time
	recorder            MetricsRecorder
}

// NewClaimedSource validates configuration and builds a claim-driven
// source. Disabled targets are ignored before client construction; a target
// list with no enabled target fails closed.
func NewClaimedSource(config SourceConfig) (*ClaimedSource, error) {
	collectorID := strings.TrimSpace(config.CollectorInstanceID)
	if collectorID == "" {
		return nil, fmt.Errorf("security alert collector instance ID is required")
	}
	factory := config.ClientFactory
	if factory == nil {
		factory = defaultClientFactory
	}
	targets := make(map[string]targetRuntime, len(config.Targets))
	for i, target := range config.Targets {
		validated, err := validateTarget(target)
		if err != nil {
			return nil, fmt.Errorf("target %d: %w", i, err)
		}
		if _, exists := targets[validated.ScopeID]; exists {
			return nil, fmt.Errorf("duplicate security alert target scope_id %q", validated.ScopeID)
		}
		client, err := factory(validated)
		if err != nil {
			return nil, fmt.Errorf("target %d client: %w", i, err)
		}
		targets[validated.ScopeID] = targetRuntime{config: validated, client: client}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one security alert target is required")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &ClaimedSource{
		collectorInstanceID: collectorID,
		targets:             targets,
		now:                 now,
		recorder:            config.Metrics,
	}, nil
}

// Collect binds one host claim to its configured target, fetches bounded
// live metadata, and returns a collector-sdk/v1alpha1 Result. Authorization
// is host-enforced at emission, so Collect carries no grant material.
// Provider failures return a transport.ProviderFailure for host claim
// disposition; the producer never decides retryable-vs-terminal claim fate
// itself.
func (s *ClaimedSource) Collect(
	ctx context.Context,
	claim collector.Claim,
) (collector.Result, error) {
	if strings.TrimSpace(claim.InstanceID) != s.collectorInstanceID {
		return collector.Result{}, fmt.Errorf(
			"security alert work item collector_instance_id %q does not match source %q",
			claim.InstanceID,
			s.collectorInstanceID,
		)
	}
	if claim.CollectorKind != "" && claim.CollectorKind != CollectorKind {
		return collector.Result{}, fmt.Errorf("security alert source cannot collect %q work items", claim.CollectorKind)
	}
	// Strict source_system binding: the SDK host validator requires every
	// fact's source_ref.source_system to equal the claim's, and this
	// producer only emits security_alert evidence. A foreign or blank value
	// can never be admitted, so it fails closed here instead of at commit.
	if claim.SourceSystem != CollectorKind {
		return collector.Result{}, fmt.Errorf("security alert source cannot collect %q source_system claims", claim.SourceSystem)
	}
	if strings.TrimSpace(claim.GenerationID) == "" {
		return collector.Result{}, fmt.Errorf("security alert work item generation_id is required")
	}
	target, ok := s.targets[strings.TrimSpace(claim.Scope.ID)]
	if !ok {
		return collector.Result{}, transport.NewProviderFailure(
			ProviderGitHubDependabot, transport.FailureRetryable, false,
			fmt.Errorf("security alert target scope_id is not configured"),
		)
	}

	startedAt := time.Now()
	collection, err := s.collectTarget(ctx, target)
	if err != nil {
		failure := classifiedProviderFailure(err)
		s.recordFetch(target.config, string(failure.FailureClass()), startedAt)
		s.recordRateLimit(target.config, string(failure.FailureClass()))
		return collector.Result{}, failure
	}
	s.recordFetch(target.config, "success", startedAt)

	observedAt := collection.observedAt.UTC()
	if observedAt.IsZero() {
		observedAt = s.now().UTC()
	}
	facts, err := s.envelopes(claim, target.config, collection)
	if err != nil {
		return collector.Result{}, err
	}
	s.recordFacts(target.config, facts)
	return s.result(claim, target.config, collection, observedAt, facts), nil
}

// result assembles the wire Result. A partial or truncated read stays a
// partial Result with a warning status so the host never mistakes bounded
// evidence for complete evidence; the SDK validator requires that status.
func (s *ClaimedSource) result(
	claim collector.Claim,
	target TargetConfig,
	collection alertCollection,
	observedAt time.Time,
	facts []collector.Fact,
) collector.Result {
	state := collector.ResultComplete
	var statuses []collector.Status
	if collection.truncated {
		state = collector.ResultPartial
		statuses = []collector.Status{{
			Class:        collector.StatusWarning,
			Partial:      true,
			WarningCount: len(collection.incompleteReasonSet()),
			FactCount:    len(facts),
		}}
	}
	return collector.Result{
		ProtocolVersion: collector.ProtocolVersionV1Alpha1,
		State:           state,
		Claim:           claim,
		Generation: collector.Generation{
			ID:            claim.GenerationID,
			ObservedAt:    observedAt,
			FreshnessHint: securityAlertFreshnessHint(securityAlertFreshnessInputFor(target, collection)),
		},
		Facts:    facts,
		Statuses: statuses,
	}
}

// collectTarget turns the target's first provider read into the merged
// collection. Only an org read that hit max_pages fans out; every other
// read is returned as is.
func (s *ClaimedSource) collectTarget(
	ctx context.Context,
	target targetRuntime,
) (alertCollection, error) {
	result, err := s.fetchTarget(ctx, target)
	if err != nil {
		return alertCollection{}, err
	}
	if result.Truncated {
		s.recordTruncatedRead(target.config, readOperation(target.config))
	}
	if !target.config.IsOrganizationScope() || !result.Truncated {
		return singleReadCollection(result), nil
	}
	return s.fanOutOrganization(ctx, target, result)
}

func (s *ClaimedSource) fetchTarget(
	ctx context.Context,
	target targetRuntime,
) (GitHubDependabotAlertResult, error) {
	var result GitHubDependabotAlertResult
	var err error
	if target.config.IsOrganizationScope() {
		result, err = target.client.ListOrganizationAlertsPages(ctx, target.config.Organization, target.config.MaxPages)
	} else {
		result, err = target.client.ListRepositoryAlertsPages(ctx, target.config.Repository, target.config.MaxPages)
	}
	if err != nil {
		// One provider request produces one fetch observation: Collect
		// records the classified failure, so recording here too would
		// double-count every failed fetch.
		return GitHubDependabotAlertResult{}, err
	}
	return result, nil
}

// fanOutOrganization issues one bounded per-repository read, in allowlist
// order from the top, for each allowlisted repository of the target
// organization, up to maxOrganizationFanoutRepositories. Reads run
// sequentially on purpose: they share one credential and one provider
// rate-limit budget. A not_found read, or a 403 the provider marked as
// Dependabot alerts disabled, is reported and the fan-out continues; the
// first read that fails any other way stops it instead of spending more of
// the budget. Only a cancelled claim context fails the whole claim.
//
// Single-claim split: the in-tree census additionally persists a cross-claim
// cursor so the next claim resumes behind a failed repository. The extracted
// producer owns no database handles, so every claim starts at the top and
// the host owns continuation (see README "Deferred to the host").
func (s *ClaimedSource) fanOutOrganization(
	ctx context.Context,
	target targetRuntime,
	org GitHubDependabotAlertResult,
) (alertCollection, error) {
	repositories := organizationFanoutRepositories(target.config)
	orgCoverage := repositoryAlertCollectionCoverageFromResult(org)
	collection := alertCollection{
		observedAt:         org.ObservedAt,
		pagesFetched:       orgCoverage.pagesFetched,
		coverage:           orgCoverage,
		repositoryCoverage: make(map[string]repositoryAlertCollectionCoverage, len(repositories)),
		fanoutOutcomes:     make(map[string]string, len(repositories)),
	}
	if len(repositories) == 0 {
		// An allowlist with no repository of the organization yields the
		// truncated single read, its digest, and the org-window page-limit
		// coverage instead of a complete-looking claim.
		return singleReadCollection(org), nil
	}
	reads := make(map[string]GitHubDependabotAlertResult, len(repositories))
	// stopOutcome is set by the first read failure that is neither not_found
	// nor an alerts-disabled 403: it is the outcome every later repository
	// records instead of being read.
	stopOutcome := ""
	for i, repository := range repositories {
		var outcome string
		var coverage repositoryAlertCollectionCoverage
		switch {
		case i >= maxOrganizationFanoutRepositories:
			outcome = fanoutOutcomeSkippedCap
		case stopOutcome != "":
			outcome = stopOutcome
		default:
			result, err := target.client.ListRepositoryAlertsPages(ctx, repository, target.config.MaxPages)
			switch {
			case err != nil && ctx.Err() != nil:
				// A cancelled claim fails the whole claim: returning the
				// provider error lets Collect classify it for host
				// disposition instead of reporting a partial success
				// with zero facts on a claim that did not run.
				return alertCollection{}, err
			case err != nil:
				outcome, stopOutcome = fanoutFailureOutcome(err)
			default:
				reads[repository] = result
				coverage = repositoryAlertCollectionCoverageFromResult(result)
				collection.pagesFetched += coverage.pagesFetched
				outcome = fanoutOutcomeComplete
				if result.Truncated {
					outcome = fanoutOutcomeTruncated
					s.recordTruncatedRead(target.config, dependabotRepositoryAlertsOperation)
				}
			}
		}
		if reason := fanoutOutcomeReason(outcome); reason != "" {
			coverage = orgCoverage
			coverage.extraReasons = []string{reason}
		}
		collection.repositoryCoverage[repository] = coverage
		collection.fanoutOutcomes[repository] = outcome
		s.recordFanoutOutcome(target.config, outcome)
	}
	for _, outcome := range collection.fanoutOutcomes {
		if outcome != fanoutOutcomeComplete {
			collection.truncated = true
			break
		}
	}
	collection.alerts = mergeFanoutAlerts(target.config, repositories, reads, collection.fanoutOutcomes, org.Alerts)
	return collection, nil
}

// envelopes assembles one SDK fact per alert of the merged collection.
// ctx.ScopeID is always the target's committed generation scope; for org
// targets ctx.RepositoryID carries the per-repo scope so payload
// repository_id and stable keys use the canonical per-repository value the
// host reducer expects.
func (s *ClaimedSource) envelopes(
	claim collector.Claim,
	target TargetConfig,
	collection alertCollection,
) ([]collector.Fact, error) {
	envs := make([]collector.Fact, 0, len(collection.alerts))
	for _, alert := range collection.alerts {
		ctx := EnvelopeContext{
			ScopeID:             target.ScopeID,
			GenerationID:        claim.GenerationID,
			CollectorInstanceID: s.collectorInstanceID,
			ObservedAt:          collection.observedAt,
			SourceURI:           safeSourceURI(firstNonBlank(target.SourceURI, alert.HTMLURL)),
		}
		if target.IsOrganizationScope() {
			// Derive the per-repository scope from the alert's repository
			// object. Alerts whose repository cannot be resolved are skipped
			// rather than misattributed to the org scope.
			repoScopeID := organizationAlertScopeID(alert)
			if repoScopeID == "" {
				continue
			}
			// Honor the operator-declared allowlist: only fan out alerts for
			// explicitly allowed repositories.
			if !target.RepositoryAllowed(organizationAlertFullName(alert)) {
				continue
			}
			ctx.RepositoryID = repoScopeID
		}
		fact, err := NewRepositoryAlertFact(ctx, alert)
		if err != nil {
			return nil, err
		}
		if fact.Kind != KindRepositoryAlert {
			return nil, fmt.Errorf("security alert runtime refusing unsupported fact_kind %q", fact.Kind)
		}
		if err := CheckSchemaVersion(fact.Kind, fact.SchemaVersion); err != nil {
			return nil, err
		}
		if target.IsOrganizationScope() {
			if name := organizationAlertRepositoryName(alert); name != "" {
				fact.Payload["repository_name"] = name
			}
		}
		annotateRepositoryAlertCollectionCoverage(fact.Payload, collection.coverageFor(alert))
		envs = append(envs, fact)
	}
	return envs, nil
}
