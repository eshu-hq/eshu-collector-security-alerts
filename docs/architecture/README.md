# Architecture

## Where it sits in Eshu

This collector is a satellite. It runs outside Eshu core, as its own little program, and the two meet at exactly one narrow seam: the host starts it per claim, talks `collector-sdk/v1alpha1` over stdin and stdout, and takes responsibility for everything after the result comes back. The [system context diagram](../diagrams/README.md#system-context) shows that seam, and the [claim lifecycle](../diagrams/README.md#claim-lifecycle) shows a single exchange across it.

That narrowness is the point. The collector can be wrong, slow, or downright broken, and the worst it can do is fail a claim. It can't write to Eshu's stores, because nothing here knows how.

## What it's made of

The producer package is `securityalert/`: it holds the GitHub client, the envelope builder that turns an alert into a fact, identity and stable-key derivation, and address cleanup. `cmd/collector` is the entry point and the seed command. The collector gets no database, graph, queue, lease, or workflow handle. The host builds the final fact envelope, checks the result, owns claims and commits, and also checks permission to publish. The collector carries no authorization material and does no permission check of its own. The one fact kind belongs to Eshu core, so publishing needs a producer grant at scope `security_alert`, for example `eshu component grant dev.eshu.collector.security-alerts --version 0.1.3 --kind security_alert.repository_alert --schema-version 1.0.0 --scope security_alert`. This repository never mints a grant.

## Tech stack

The binary is a static, pure-Go build. The [Dockerfile](../../Dockerfile) compiles `./cmd/collector` with `CGO_ENABLED=0` and `-trimpath` on `golang:1.26.10-alpine`, then copies the result onto a distroless static base (`gcr.io/distroless/static-debian12:nonroot`) with no shell and no package manager. It runs as user `65532`, and the entrypoint serves one claim from stdin by default (`--sdk-stdio`), with `seed --dest DIR` as the self-install path an init container uses.

## Versions it pins

Exact versions from `go.mod`. Please don't substitute another SDK line.

| Module | Version |
| --- | --- |
| Go | `1.26.10` |
| `github.com/eshu-hq/eshu-sdk/collector` | `v0.2.0-rc.2` |
| `github.com/eshu-hq/eshu-sdk/factschema` | `v0.1.0-rc.12` |
| `gopkg.in/yaml.v3` | `v3.0.1` |

The component ID is `dev.eshu.collector.security_alerts`, version `0.1.3`, collector kind `security_alert`. It declares support for Eshu core `>=0.0.5 <0.2.0` and speaks `collector-sdk/v1alpha1` over the process adapter, all recorded in [manifest.yaml](../../manifest.yaml). Check that range against your core version before enabling it. A mismatch makes the host refuse the component.
