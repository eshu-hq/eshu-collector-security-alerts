# Contributing to eshu-collector-security-alerts

## Checks

`make ci` is the whole local contract: it runs the `lint`, `test`, and
`race` lanes CI runs (same commands, same coverage floor). CI needs Go plus
golangci-lint v2.12.2 (the same binary Eshu uses):

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
make ci
```

## Lint set

`.golangci.yml` is the org set (a copy of `eshu-hq/.github` v1): `govet`,
`staticcheck` (which subsumes `gosimple` in v2), `ineffassign`, `unused`,
`errcheck`, with the `gofumpt` formatter. It runs on the whole repo: no
baselines, no new-code-only mode. Every exclusion needs a reason and a
linked open issue on the same lines.

Two hard rules:

- No static gates, with one named exception: the 500-line cap on `.go`
  files, enforced by a plain `wc -l` step (`make cap`). No committed
  counts, no parity files, no allowlist without a linked child issue.
- No hidden debt: fix findings, do not scope them away.

## Coverage

The `race` lane uploads a coverprofile and fails below `COVERAGE_FLOOR`
(currently 66.1, the measured baseline). The floor may only rise; the
finish line is 90% of statements. Never lower the target, exclude
packages silently, or delete assertions to move the number.

## CI lanes

`.github/workflows/ci.yml` selects lanes per PR from changed paths
(`changes` job): Go sources run `lint`, `test`, `race`; `manifest.yaml`
and other test-read fixtures run `test` only; shell scripts run `shell`
only (plus `test` when a test executes the script; no scripts exist today);
`Dockerfile` runs `image` (build, no push); `go.mod`/`go.sum`
changes add `govulncheck`; pushes to `main` and the weekly schedule add
`govulncheck` and advisory `gosec` (SARIF to the Security tab). Workflow
changes run `actionlint` plus the Go lanes. `ci-complete` is the only
context the ruleset requires: it passes when needed lanes passed and
fails when one failed; legitimately skipped lanes are fine.

All actions are SHA-pinned; PR lanes use `contents: read`, need no
secrets, and cancel superseded runs per PR. Releasing is documented in
the README ("Releasing"); `release.yml` triggers are out of scope for
CI changes.
