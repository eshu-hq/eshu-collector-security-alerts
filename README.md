# eshu-collector-security-alerts

Status: pre-release. Do not rely on it in production yet.

This collector reads GitHub Dependabot security alerts for one repository (or one organization) and hands Eshu a checked summary of what it found.

Eshu is the core system. A collector is a small helper program: it reads one outside system, turns what it finds into facts (small, typed records), and gives those facts back to Eshu. Dependabot is GitHub's built-in service that warns when a repository uses a software package with a known flaw. This collector only reads those alerts. It never changes anything in GitHub.

A claim is one unit of work Eshu sends the collector. An activation is one configured copy of this collector, set up to serve one alert feed.

## What it collects

One run covers one alert feed, named by the claim. Through bounded GitHub REST calls it lists Dependabot alerts for one allowlisted repository, or for one organization (then it fans the result out into per-repository facts, with a bounded per-repository follow-up read when the organization read was cut short).

It returns 1 fact kind, at schema `1.0.0` with confidence `reported` (GitHub said so; Eshu did not check it directly):

| Fact kind | One fact describes |
| --- | --- |
| `security_alert.repository_alert` | one Dependabot alert on one repository |

Web addresses are cleaned before anything leaves the collector, and each fact notes how complete its read was (for example, whether paging or the organization follow-up was cut short). Facts also carry a freshness digest so Eshu can spot duplicate work.

A run ends as `complete` or `partial` (some alerts were read, the rest cut short by a limit), `retryable` (try again later — for example after a rate limit, or when the claim arrived with no time left), or `terminal` (stop; a person must fix something first). A failed run returns no facts.

## How data flows

```mermaid
flowchart LR
  A["GitHub Dependabot alerts"] --> B["This collector"] --> C["Eshu host process"] --> D["Eshu core"]
```

Text version: GitHub Dependabot alerts → this collector → Eshu host process (checks and stores the result) → Eshu core. The collector never talks to Eshu's database directly.

## When to use it, and when not to

Use it when Eshu needs current Dependabot alert state for repositories you name, read on a schedule Eshu controls. Do not use it to dismiss or fix alerts, to read code-scanning or secret-scanning alerts (it reads Dependabot alerts only), or as a general GitHub API tool. One activation serves one feed (see Configuration); add one activation per repository feed you need.

## How Eshu runs it

Eshu's component host starts this program for one claim at a time: it sends one bounded `collector-sdk/v1alpha1` request on standard input (stdin) and reads one result from standard output (stdout). Requests are capped at 1 MiB.

```bash
collector --sdk-stdio   # serve one claim from stdin
go run ./cmd/collector < request.json > result.json   # local run from a checkout
```

The collector gets no database, graph, queue, lease, or workflow handle. The host builds the final fact envelope (the wrapper Eshu stores), checks the result, and owns claims and commits. Permission to publish facts is also checked by the host; the collector carries no authorization material and does no permission check of its own.

The published image is `ghcr.io/eshu-hq/eshu-collector-security-alerts`. It holds one static binary with no shell, and the binary can install itself into a component folder (how a startup, or init, container sets it up):

```bash
collector seed --dest /component [--image-ref ghcr.io/eshu-hq/eshu-collector-security-alerts@sha256:<digest>]
```

This writes `/component/collector` (mode 0755) and `/component/manifest.yaml`. `--image-ref` (or the `COLLECTOR_IMAGE_REF` environment variable; the flag wins) stamps the exact deployed image reference into the manifest, because an image cannot contain its own digest. The manifest in this repository keeps an all-zero placeholder digest on purpose (a test fails on a real one, since the manifest is embedded in the binary).

## Configuration

Copy `config.example.yaml`. It has three parts: `host` names the job identity Eshu plans, `process` says how Eshu starts the binary, and `config` holds this collector's own settings. One activation serves one feed: `config.targets` holds exactly one target, and that target's `scope_id` must equal `host.scope.id` (the claim scope). A target naming any other scope fails the whole activation as terminal `invalid_config.target_scope_mismatch` — it would otherwise be silently never collected. To collect a second repository, add a second activation with its own instance ID and scope.

| Target key | Meaning |
| --- | --- |
| `provider` | `github_dependabot` (the only provider) |
| `scope` | `repository` (default) or `org` for an organization-wide read |
| `scope_id` | The claim scope this target serves; part of every stored fact key, so choose it once and keep it. Scope IDs carrying shard or retirement markers are refused — the host plans those, never this collector |
| `repository` / `organization` | The `owner/repo` to read, or the organization login for an `org` target |
| `auth_mode` | `token_env` (default) or `host_minted`. See Credentials |
| `token_env` | For `token_env` targets: name of the environment variable holding the GitHub token |
| `allowed_repositories` | The only repositories this target may read; anything else is refused |
| `api_base_url` | GitHub API address, for example `https://api.github.com` |
| `repository_alert_limit`, `max_pages` | Most alerts to return per repository read; most pages to fetch |
| `source_uri` | Optional provenance address recorded on facts |

`config.limits` carries the shared host-level caps (`maxRecordsPerClaim`, `maxPayloadBytes`, `maxResultBytes`, `claimTimeoutSeconds`); the host enforces them. A large organization read can pass the host's default 4 MiB output cap, so raise `process.stdout_limit_bytes` together with your per-claim expectations, as the example does.

Unknown config keys are rejected. A bad activation fails the claim as terminal `invalid_config` before any GitHub contact, with a bounded reason attached to the failure class (for example `invalid_config.target_scope_mismatch`, `invalid_config.missing_host_token`). Anything that matches on the failure class should match the prefix `invalid_config`, not the exact string.

## Credentials

Secrets never go in the config file. Two credential shapes are served, and they never mix on one target:

- `token_env` (default): a static GitHub token (personal access token). `token_env` names an environment variable the worker process already has — for example, `token_env: GITHUB_TOKEN` means "read the token from the variable called `GITHUB_TOKEN`." It is resolved once when the claim is parsed and sent as `Authorization: Bearer`.
- `host_minted`: the host mints a fresh GitHub App installation token per claim and delivers it at the top level of the config as `host_github_app_token: {token, scope_id}`. Leave `token_env` and every `github_app_*_env` entry empty. A missing, empty, or wrong-scope stanza fails closed as terminal `invalid_config` before any GitHub contact. Because the token is fresh each claim, an expired-token answer stays retryable (the next claim mints anew), while a static token failure is terminal until a person rotates it.

Direct `github_app` targets are not served by this binary: minting installation tokens is host-owned and no mint callback crosses the request boundary, so such a target fails at config parse. Use `host_minted` for GitHub App setups.

Token values never appear in facts, logs, or status messages; errors name the variable or key, never the value.

## Time and size limits

Eshu gives each claim a deadline. The collector stops starting new GitHub calls shortly before it (the smaller of 2 seconds or 5% of the time left) and returns `retryable` with failure class `claim_deadline_exceeded` and no facts, instead of being killed mid-request or storing a half-finished read. A claim that arrives with no time left fails the same way at once, before any GitHub call. Read size is bounded by `repository_alert_limit`, `max_pages`, and — for organization targets — a cap of 100 follow-up repository reads per claim; repositories past a cap keep their facts with a note that coverage was cut short, and the run reports `partial` where the code marks it so.

## What operators see

The main signal is the failure class on the claim result, such as `invalid_config.target_scope_mismatch` (fix the activation), `claim_deadline_exceeded` (retryable; give large feeds more time), a rate-limit class with a suggested wait, or `invalid_evidence` (GitHub sent data that cannot become a fact). The host records the failure class verbatim, so the dotted reason is how the cause reaches an operator.

The collector also writes one JSON diagnostic line per claim to standard error (stderr) with claim identity, failure class, operation, and the bounded reason — never a token, web address, or provider body. The host drops that text (it keeps only a byte count), so the line helps only in a local run or in tests.

This collector emits no metrics and declares no metric prefix in its manifest. A metrics recorder seam exists in code for host wiring (`securityalert.MetricsRecorder`); with no recorder wired, nothing is recorded. Treat the claim's failure class as the operator signal.

## Keeping the same identity when you switch

If this collector replaces Eshu's built-in security-alert collector for a feed, these setup values must match the old ones, or Eshu will treat the same feed as new data:

| Setup value | Rule |
| --- | --- |
| `host.scope.id` | Must equal the old target's scope ID, or every stored key changes |
| `host.scope.kind` | Must be `security_alert` |
| `host.sourceSystem` | Must be `security_alert`, or the source label changes on every fact |

The activation instance ID must instead differ from any live built-in instance ID; only the `collector_instance_id` field inside the payload changes, and stored keys do not. The collector copies scope, instance, and source system from the claim the host sends; it has no setting of its own for them. Read the real values from the live built-in setup — never copy the placeholders in `config.example.yaml` — and run only one of the two collectors per feed.

## Permission to publish facts

The one fact kind belongs to Eshu core, so the host refuses it without a producer grant (written permission for this component to publish that kind). The grant scope is the collector kind, not a feed. Eshu core issues the grant, for example:

```sh
eshu component grant dev.eshu.collector.security-alerts --component-home "$HOME_DIR" \
  --version 0.1.3 --kind security_alert.repository_alert --schema-version 1.0.0 \
  --scope security_alert --expires-in 720h
```

This repository never mints a grant, and the activation carries no authorization material.

## Eshu dependencies

Exact versions from `go.mod`. Do not substitute another SDK line.

| Module | Version |
| --- | --- |
| Go | `1.26.10` |
| `github.com/eshu-hq/eshu-sdk/collector` | `v0.2.0-rc.2` |
| `github.com/eshu-hq/eshu-sdk/factschema` | `v0.1.0-rc.12` |
| `gopkg.in/yaml.v3` | `v3.0.1` |

The component ID is `dev.eshu.collector.security_alerts`, version `0.1.3`, collector kind `security_alert`. It declares support for Eshu core `>=0.0.5 <0.2.0` and speaks `collector-sdk/v1alpha1` over the process adapter (see `manifest.yaml`). Check that range against your core version before enabling it; a mismatch makes the host refuse the component.

## What it never does

- It never writes to GitHub — no dismissing alerts, no comments, no setting changes — and it never stores anything itself.
- It never reads a repository outside `allowed_repositories`, and it never mints GitHub App tokens (the host does; the code only spends a token handed to it).
- It never expands shard scopes or answers retirement claims, and it keeps no position between claims: every claim starts at the top of the allowlist, and continuation state stays host-owned.
- It never imports Eshu core internals, and it never puts tokens, raw web addresses with credentials, or provider bodies into facts, logs, or status messages.

The code mirrors the built-in collector's behavior byte-for-byte where it matters: stable fact keys and wire payloads are pinned by golden tests so switching collectors does not re-key a single fact, and emitted results are checked in tests against the pinned SDK's own validator.

## Build, test, and release

```bash
make ci     # lint + test + race; the full local check CI runs
make lint   # vet, golangci-lint, format check, tidy check, 500-line cap
make build  # compile only
make test   # build + full test suite
make race   # race suite + coverage floor
```

Releases run from `.github/workflows/release.yml` on every push to `main` and on version tags (`vMAJOR.MINOR.PATCH`, optional pre-release suffix). Nothing runs for a pull request, and the workflow deploys nothing. A `main` push publishes the moving `main`, `latest`, and `sha-<full-sha>` image tags — use moving tags only where floating is intended and pin real deployments to digests. To publish a version: set `metadata.version` in `manifest.yaml`, merge to `main`, then tag that commit `v<version>` and push the tag. A tag on any other commit, or a tag that does not match the manifest version, publishes nothing. The workflow builds `linux/amd64`, pushes `ghcr.io/eshu-hq/eshu-collector-security-alerts`, writes the digest to the job summary, signs it with cosign (keyless), and attaches build-provenance and SBOM attestations. Copy the `@sha256:<digest>` reference from the job summary into the activation's seed image.

## Docs and related projects

- `config.example.yaml` — full setup example with comments. `manifest.yaml` — component identity, fact list, and core range. `securityalert/` — the producer package (fetch, envelope, identity, cleanup).
- [Eshu core](https://github.com/eshu-hq/eshu) — the host that runs this collector. Extraction background: [eshu-hq/eshu#8866](https://github.com/eshu-hq/eshu/issues/8866).
- [eshu-sdk](https://github.com/eshu-hq/eshu-sdk) — shared SDK modules.
- [eshu-deploy](https://github.com/eshu-hq/eshu-deploy) — deployment examples and reference setups.

## Contributing

See `CONTRIBUTING.md`. In short: run `make ci` before pushing; it runs the same lint, test, and race checks as CI (install `golangci-lint` v2.12.2 first, as that file shows).
