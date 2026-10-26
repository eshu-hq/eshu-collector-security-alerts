# eshu-collector-security-alerts

Extracted security-alert collector producer for [eshu-hq/eshu#8866](https://github.com/eshu-hq/eshu/issues/8866)
(collector-security-alerts extraction, part of epic #6707). Emission half only:
this repository fetches bounded live GitHub Dependabot alert metadata and returns a
`collector-sdk/v1alpha1` Result per host claim. Core keeps admission, projection,
persistence, claim mutation, fencing, and the status read.

Refs eshu-hq/eshu#8866. This repository does not close that issue: cutover stays gated
by #4047 with production acceptance NOT_CHECKED, and no pair is a
qualified consumer/core combination yet (see SDK Compatibility in
eshu-hq/eshu docs).

## Pins

Exact published pins from `eshu-hq/eshu-sdk` — never `@latest`, no
`replace` or workspace directives:

| Module | Pin |
|---|---|
| `github.com/eshu-hq/eshu-sdk/collector` | `v0.1.0-rc.3` |
| `github.com/eshu-hq/eshu-sdk/factschema` | `v0.1.0-rc.5` |

Verify resolution before any pin bump:

```bash
GOPROXY=proxy.golang.org go list -m github.com/eshu-hq/eshu-sdk/collector@v0.1.0-rc.3
GOPROXY=proxy.golang.org go list -m github.com/eshu-hq/eshu-sdk/factschema@v0.1.0-rc.5
```

## Layout

- `securityalert/` — the producer: bounded Dependabot REST fetch
  (`client.go`, per-repository and organization endpoints, pagination,
  allowlist-first, `Authorization: Bearer` transport), one envelope
  constructor (`envelope.go`), claim-to-Result fan-out (`source.go`),
  single-claim org fan-out with stop semantics (`source.go`), URL
  sanitization (`redaction.go`), package identity normalization
  (`identity.go`), coverage annotation and freshness digest
  (`coverage.go`), kind/schema admission (`schema.go`), claim-ID minting
  (`claimid.go`), and a host-wired metrics seam (`metrics.go`).
- `grant/` — fail-closed stub enforcing the core-issued producer grant
  draft (`producer-grant.manifest.DRAFT.yaml` in eshu-hq/eshu,
  `go/cmd/collector-security-alerts`) at every emission. Until core issues
  a grant, the zero Grant is denied and `Collect` fails closed before any
  provider contact.

## Parity evidence

- Census mirror: `securityalert/extraction_prep_mirror_test.go` ports the
  in-tree extraction PREP mirror (admission at 1.0.0, determinism,
  URL-sanitization sentinel, fail-closed hostile inputs).
  `TestExtractionPrepClaimIDNamespace` ports the `security-alert-claim-`
  namespace case.
- Stable keys: `identity.StableID(kind, identity)` shares the in-tree
  scheme and is byte-stable with it. Independent oracle: the golden test
  pins the exact stable key and wire payload emitted by the in-tree
  constructor for the canonical fixture
  (`TestGoldenStableKeyAndPayload`).
- Contract payloads: `securityalert/v1` struct fields are identical
  between the in-tree `sdk/go/factschema` source and the pinned module,
  and the same `EncodeSecurityAlertRepositoryAlert` entry point merges
  payloads with producer-computed keys winning, as in-tree.
- SDK self-check: `TestCollectEmitsValidatorCleanResult` and
  `TestCollectPartialReadStaysPartial` run emitted Results through the
  published SDK's own `collector.NewValidator(...).ValidateResult`,
  including its sensitive-payload-key gate.
- Generation binding: the SDK Fact carries no per-fact generation or
  fencing fields, so generation travels via `SourceRef.generation_id`
  and the Result generation (with the freshness digest), and fencing
  travels at the claim level (`claim.fencing_token`).

## Deferred to the host

The extracted producer owns no database, graph, or reducer handles.
These in-tree behaviors stay host-owned at cutover and are documented,
not ported:

- Cross-claim org fan-out cursor and read-state persistence (#8943,
  #8946): every satellite claim starts at the top of the allowlist; the
  host owns continuation and the durable cursor.
- Shard expansion and retirement claims (#9019): a configured
  `scope_id` carrying a shard or retirement marker is rejected at
  construction, and a claim naming one fails as an unconfigured scope.
  The host plans shard scopes and drives retirement through grant
  revocation, never through a satellite claim.
- GitHub App installation-token minting: the satellite threads a
  host-supplied `TokenProvider`; the host mints (wrapping transient
  failures in `MintTransientError`) and the satellite maps the decision
  table. Static-PAT targets need no provider.
- Claim acquisition, lease TTL, heartbeats, dead letters, and the status
  read: the host service wires them at cutover (the in-tree
  `go/cmd/collector-security-alerts/service.go` equivalent).
- Telemetry: `MetricsRecorder` is the host-wired seam; a nil recorder
  disables recording. Only the unit tests call `newClaimID` here; the
  host service wires it to claim acquisition at cutover.
