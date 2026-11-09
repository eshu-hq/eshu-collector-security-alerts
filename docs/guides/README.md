# Guides

Step-by-step help for the jobs you'll actually do with this collector. Each one assumes you've skimmed [getting started](../getting-started/README.md).

## Seed it into a component folder

The published image is `ghcr.io/eshu-hq/eshu-collector-security-alerts`. It holds one static binary with no shell, and the binary can install itself into a component folder, which is how a startup (init) container usually sets it up:

```bash
collector seed --dest /component [--image-ref ghcr.io/eshu-hq/eshu-collector-security-alerts@sha256:<digest>]
```

That writes `/component/collector` (mode 0755) and `/component/manifest.yaml`. The `--image-ref` flag, or the `COLLECTOR_IMAGE_REF` environment variable when the flag is absent, stamps the exact deployed image reference into the manifest. The flag wins when both are set. This step exists because an image can't contain its own digest, so the manifest in this repository keeps an all-zero placeholder digest on purpose. A bad image reference fails before any file is written. The [deployment diagram](../diagrams/README.md#deployment-and-seed) draws the whole flow.

## Operate it day to day

The main signal is the failure class on the claim result, and it's worth reading the dotted reason rather than just the prefix. `invalid_config.target_scope_mismatch` means the activation's one target doesn't serve the claimed scope, so fix the activation. `invalid_config.missing_host_token` means a `host_minted` claim arrived without its token. `claim_deadline_exceeded` is retryable and suggests large feeds need more time. A rate-limit class carries a suggested wait. `invalid_evidence` means GitHub sent data that can't become a fact. The host records the failure class verbatim, so that dotted reason is how the cause reaches you. Anything matching on failure classes should match the `invalid_config` prefix, not the exact string.

The collector also writes one JSON diagnostic line per claim to standard error, with claim identity, failure class, operation, and the bounded reason. Never a token, web address, or provider body. The host drops that text and keeps only a byte count, so the line helps only in a local run or in tests.

This collector emits no metrics and declares no metric prefix in its manifest. A recorder seam exists in code for host wiring (`securityalert.MetricsRecorder`), but with no recorder wired, nothing is recorded. Treat the claim's failure class as your operator signal.

## Troubleshoot a failing feed

If a feed never produces facts, check the scope pairing first: the one target's `scope_id` must equal `host.scope.id`, or every claim fails as `invalid_config.target_scope_mismatch` before any GitHub contact. If big organization feeds keep coming back `partial`, you're hitting `repository_alert_limit`, `max_pages`, or the 100 follow-up cap, so raise `process.stdout_limit_bytes` alongside your limits as the example config does. If a static token starts failing terminally, rotate it. A `host_minted` token is fresh each claim, so that flavour of failure stays retryable instead.

## Release a new version

Releases run from `.github/workflows/release.yml` on every push to `main` and on version tags (`vMAJOR.MINOR.PATCH`, with an optional pre-release suffix). Nothing runs for a pull request, and the workflow deploys nothing. A `main` push publishes the moving `main`, `latest`, and `sha-<full-sha>` image tags. Use moving tags only where floating is intended, and pin real deployments to digests.

To publish a version: set `metadata.version` in `manifest.yaml`, merge to `main`, then tag that commit `v<version>` and push the tag. A tag on any other commit, or one that doesn't match the manifest version, publishes nothing. The workflow builds `linux/amd64`, pushes the image, writes the digest to the job summary, signs it with cosign (keyless), and attaches build-provenance and SBOM attestations. Copy the `@sha256:<digest>` reference from the job summary into the activation's seed image.

Extraction background: [eshu-hq/eshu#8866](https://github.com/eshu-hq/eshu/issues/8866).
