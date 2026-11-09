# Concepts

This page explains what this collector is for and how it behaves, in plain words. If you want the pictures, they're all on the [diagrams page](../diagrams/README.md), and section headings below link to the matching one.

## The short story

Eshu is the core system. A collector is a small helper program: it reads one outside source, turns what it finds into facts (small, typed records), and gives those facts back to Eshu. The [system context diagram](../diagrams/README.md#system-context) shows where this one sits.

Dependabot is GitHub's built-in service that warns when a repository uses a software package with a known flaw. A claim is one unit of work Eshu sends the collector, and an activation is one configured copy of it, set up to serve one alert feed.

One run covers one alert feed, named by the claim. Through bounded GitHub REST calls it lists Dependabot alerts for one allowlisted repository. Or, for an organization target, it reads across the organization and fans the result out into per-repository facts, with a bounded per-repository follow-up read when the organization read was cut short. That follow-up is capped at 100 repository reads per claim, and repositories past a cap keep their facts with a note that coverage was cut short.

The one-feed-per-activation rule trips people up, so here's the shape of it. `config.targets` holds exactly one target, and that target's `scope_id` must equal the claim scope the host plans. A target naming any other scope fails the whole activation as terminal `invalid_config.target_scope_mismatch`, because otherwise it would be silently never collected. Want a second repository? Add a second activation with its own instance ID and scope. The full key list is in [the configuration reference](../reference/configuration.md), and [config.example.yaml](../../config.example.yaml) is the file to copy.

If you're switching a feed over from Eshu's built-in security-alert collector, identity matters. `host.scope.id` must equal the old target's scope ID or every stored key changes, `host.scope.kind` must be `security_alert`, and `host.sourceSystem` must be `security_alert` or the source label changes on every fact. The activation instance ID must instead differ from any live built-in one. Only the `collector_instance_id` field inside the payload changes then, and stored keys don't. Read the real values from the live built-in setup rather than copying placeholders, and run only one of the two collectors per feed.

## How a run can end

A run ends as `complete` or `partial` (some alerts were read, the rest cut short by a limit), `retryable` (try again later, for example after a rate limit or when the claim arrived with no time left), or `terminal` (stop, a person must fix something first). A failed claim returns no facts. Note this is about the claim, not about any single alert: an alert whose state is open or dismissed is ordinary data and becomes a fact either way. Requests are capped at 1 MiB.

## The facts, in one breath

This collector returns its facts at schema `1.0.0` with confidence `reported`, which means the source said so and Eshu hasn't checked it directly. Every fact carries where it came from: source system, scope, generation, a stable key, a cleaned source address, and a source record ID. The full list lives in [the fact kinds reference](../reference/facts.md), which mirrors `manifest.yaml`.

## A worked example

This example is pinned by a golden test, so every value below is checkable in the repo. Open [securityalert/envelope_golden_test.go](../../securityalert/envelope_golden_test.go) and look at `goldenFixtureAlert`: alert number 42 on `example-org/example-repo`, state `open`, for the npm package `@scope/left-pad` in `package-lock.json`. Its advisory is `GHSA-abcd-1234` (also CVE-2026-0001), severity `critical`, vulnerable below version `1.2.3` and patched at `1.2.3`.

Feed that alert through a claim for the scope `security-alert:github:example-org/example-repo` (the fixture's `goldenFixtureContext`) and exactly one fact comes back: a `security_alert.repository_alert` fact whose payload carries the package, the advisory IDs, the CVSS score and EPSS figures from GitHub, and the alert's own state and timestamps. The test pins both the stable key (`goldenStableKey`) and the exact wire bytes (`goldenPayload`), so the same alert always produces byte-identical output. That's what makes switching from the built-in collector safe: not a single stored fact gets re-keyed.

## What it never does

It never writes to GitHub. No dismissing alerts, no comments, no setting changes. And it stores nothing itself, since the host validates and commits. It never reads a repository outside `allowed_repositories`, and it never mints GitHub App tokens. The host mints those; this code only spends a token handed to it.

It never expands shard scopes or answers retirement claims, and it keeps no position between claims. Every claim starts at the top of the allowlist, and continuation state stays host-owned. It never imports Eshu core internals, and it never puts tokens, raw web addresses with credentials, or provider bodies into facts, logs, or status messages.

The code mirrors the built-in collector's behavior byte-for-byte where it matters. Stable fact keys and wire payloads are pinned by golden tests, and emitted results are checked in tests against the pinned SDK's own validator.
