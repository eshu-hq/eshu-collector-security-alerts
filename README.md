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
- Authorization is host-enforced at emission: the host issues the
  core-owned-kind producer grant and denies kinds without one. The
  satellite carries no authorization material and performs no grant
  re-check.
- `contract.go`, `request.go`, `config.go`, `handler.go`, `failure.go` —
  the SDK adapter: the manifest-matched contract (`Contract()`), the stdio
  request boundary (`ParseRequest`), activation parsing (targets plus the
  shared host-level limits stanza), and the claim-to-Result mapping
  (`Handler.Handle`), including the fail-closed config and deadline paths.
- `cmd/collector/` — the entrypoint: stdio serve plus the `seed`
  subcommand that installs the binary and manifest.
- `manifest.yaml` — the component manifest (`dev.eshu.collector.security_alerts`
  at `0.1.2`); `Dockerfile` — the static distroless image;
  `config.example.yaml` — the activation shape.

## Parity evidence

- Census mirror: `securityalert/extraction_prep_mirror_test.go` ports the
  in-tree extraction PREP mirror (admission at 1.0.0, determinism,
  URL-sanitization sentinel, fail-closed hostile inputs).
  `TestExtractionPrepClaimIDNamespace` ports the `security-alert-claim-`
  namespace case.
- Stable keys: `identity.StableID(kind, identity)` shares the in-tree
  scheme and is byte-stable with it. Self-consistency pin: the golden test
  pins the transcribed stable key and wire payload for the canonical fixture
  (`TestGoldenStableKeyAndPayload`); the in-tree oracle source is cited in
  that test, and the vectors stay in sync by hand until regeneration is
  automated.
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
  construction, and a claim naming one fails as terminal
  `invalid_config` (`target_scope_mismatch`).
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

## Running

The collector runs through the Eshu component-extension host with the
`process` runner. The host writes one bounded `collector-sdk/v1alpha1`
request to stdin and reads one result from stdout. The collector gets no
Postgres, graph, queue, lease, or workflow handle.

```bash
go run ./cmd/collector < request.json > result.json
```

A bad activation fails closed as terminal
`invalid_config` before any provider contact. A claim arriving with no lease time left fails
retryable as `claim_deadline_exceeded`. `github_app` targets are not served
over stdio: installation-token minting is host-owned and no mint callback
crosses the request boundary, so they fail closed at config parse.
One activation serves one feed. An activation plans exactly one scope, its
`host.scope.id`, so `config.targets` holds exactly one target and that target's
`scope_id` equals the claim scope. A target for any other scope, host-minted or
static, is never collected, so the whole activation fails closed as terminal
`invalid_config` with the bounded reason `target_scope_mismatch` and the count
of mismatched targets, never a scope id, repository, or credential. The SDK
status has no free-text field, so the reason refines the failure class inside
the one bounded token: the single failure status reads
`invalid_config.target_scope_mismatch`, and the host records it verbatim in
`last_failure_class` and `last_failure_message`. Every config reason does the
same (`invalid_config.missing_host_token`, `invalid_config.host_token_scope_mismatch`,
`invalid_config.malformed_host_token`); the diagnostic line keeps `failure_class`
and `reason` separate. Anything that matches `failure_class="invalid_config"`
exactly must match the prefix `invalid_config(\..*)?` instead. To collect a
second repository, add a second activation with its own instance id and scope.
Static-PAT (`token_env`) targets need no provider. `host_minted` targets
spend the per-claim `host_github_app_token` stanza (`{token, scope_id}`)
the host delivers at the top level of the activation config: the token lands
only on `host_minted` targets, and a missing, empty, or claim-scope-mismatched
stanza fails closed as terminal `invalid_config` before any provider contact.

The collector writes one JSON diagnostic line per claim to stderr for local
runs and tests; the host's process runner drops the text. The line carries
claim identity and the failure vocabulary only: never a token, URL, or
provider body.

## Image and seeding

The image holds one static binary that installs itself, so an init container
needs no shell:

```bash
collector seed --dest /component [--image-ref ghcr.io/eshu-hq/eshu-collector-security-alerts@sha256:<digest>]
```

writes `/component/collector` (mode 0755) and `/component/manifest.yaml`.
`--image-ref REF` (or the `COLLECTOR_IMAGE_REF` environment variable; the flag
wins) stamps the deployed digest-pinned reference into the manifest's artifact
entry, because an image cannot embed its own digest. The repository manifest
keeps the all-zero placeholder digest permanently (`manifest_test.go` fails on
a real one), because it is embedded in the binary and a committed digest could
only describe an older build.

## Cutover identity

Replacing the in-tree security-alert collector with this one must not re-key
a single fact. These activation values have to equal what the in-tree
collector uses for the same feed:

| Activation value | Must equal the in-tree value | If it differs |
| --- | --- | --- |
| `host.scope.id` | the in-tree target's `scope_id` | every stable key changes: the feed is ingested as a new scope |
| `host.scope.kind` | `security_alert` | the scope no longer matches the in-tree scope kind |
| `host.sourceSystem` | the in-tree source system, `security_alert` | `source_ref` changes on every fact |

The activation instance id is the exception: it must differ from any live
in-tree instance id, and the cutover record keeps the old-to-new mapping.
`collector_instance_id` in the payload is the one field that changes.

The collector copies `scope_id`, `collector_instance_id`, and `source_system`
from the claim the host sends; it has no setting of its own for them.

Before enabling an activation, read the values from the live in-tree
collector instance configuration and write them into the activation. Do not
copy the placeholders in `config.example.yaml`. Run only one of the two
collectors per feed. The activation needs its own instance id, because the
in-tree instance stays registered until it is deactivated. Facts keep their
stable keys because scope and generation own them.

## Producer grants

The emitted kind is core-owned, so the host refuses it without a live
producer grant. The host issues and enforces the grant at emission; the
activation carries no authorization material (see `config.example.yaml`).
A grant's scope is the collector kind (`security_alert`), not a feed. Core
issues the grant at cutover (one per kind):

```sh
eshu component grant dev.eshu.collector.security-alerts --component-home "$HOME_DIR" \
  --version 0.1.2 --kind security_alert.repository_alert --schema-version 1.0.0 \
  --scope security_alert --expires-in 720h
```

This repository never mints one.

## Releasing

`.github/workflows/release.yml` runs only when a tag `vMAJOR.MINOR.PATCH[-pre]`
is pushed. Nothing runs on a pull request or a branch push, and the workflow
deploys nothing.

The workflow refuses to publish unless the tag points at the protected
`main` head, so a `v*` tag cut from any other commit publishes nothing. As
defense in depth, restrict who can create `v*` tags with a tag ruleset
limited to maintainers.

1. Set `metadata.version` in `manifest.yaml` to the version you are releasing
   and merge that change to `main`. Then tag the merge commit and push the tag.
   The workflow refuses to publish unless the tag equals `v` plus that version
   (a `-pre-release` suffix on the tag is allowed when the manifest version has
   none), and it checks this before it builds or pushes anything.
2. The workflow builds `linux/amd64` (the only platform the manifest declares),
   pushes `ghcr.io/eshu-hq/eshu-collector-security-alerts:<tag>`, writes the
   digest to the job summary, signs the digest with cosign (keyless), and
   attaches a SLSA build-provenance attestation and an SPDX SBOM attestation.
   It needs no secret beyond the job's `GITHUB_TOKEN`.
3. Copy the `ghcr.io/eshu-hq/eshu-collector-security-alerts@sha256:<digest>`
   reference from the job summary into the activation's `seed.image`. The
   deployment stamps it into the manifest with `collector seed --image-ref`.

<!-- fork-proof: fork PR lane-selection probe -->
