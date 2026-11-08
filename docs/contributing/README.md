# Contributing

Thanks for helping. The full rules live in [eshu-collector-security-alerts's CONTRIBUTING.md](../../CONTRIBUTING.md) at the repository root, and that file wins if anything here ever disagrees with it. This page is just the friendly on-ramp.

## Set yourself up

You'll need Go at the version pinned in `go.mod` (currently `1.26.10`) and `golangci-lint` v2.12.2. The root [CONTRIBUTING.md](../../CONTRIBUTING.md) shows the install command. Docker only matters if you want to exercise the image lane locally.

## Check your work

One command runs the whole local contract:

```bash
make ci   # lint + test + race, the same checks CI runs
```

Useful pieces on their own: `make build` (compile only), `make test`, `make race` (which also enforces the coverage floor), and `make lint`. You'll want `golangci-lint` v2.12.2 installed first, as the root CONTRIBUTING.md shows.

Please run it before you push. The test suite is the product contract here, so if a test is in your way, that usually means the change needs rethinking rather than the test needing weakening.

## House rules worth knowing

Credentials always travel by environment reference, never as inline values, and they never get logged. Keep Go files under the 500-line cap the lint lane enforces. And if you touch the fact list, update [the facts reference](../reference/facts.md) and `manifest.yaml` together, since one mirrors the other.
