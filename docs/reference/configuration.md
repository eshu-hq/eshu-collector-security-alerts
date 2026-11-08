# Configuration

Start by copying [config.example.yaml](../../config.example.yaml) from the repository root. That file is the canonical, commented example, so this page explains it rather than repeating it. If the two ever disagree, believe the example file and tell us.

The file has three parts. `host` names the job identity Eshu plans, `process` says how Eshu starts the binary, and `config` holds this collector's own settings. One activation serves one feed: `config.targets` holds exactly one target, and that target's `scope_id` must equal `host.scope.id` (the claim scope). A target naming any other scope fails the whole activation as terminal `invalid_config.target_scope_mismatch`, because it would otherwise be silently never collected. To collect a second repository, add a second activation with its own instance ID and scope.

| Target key | Meaning |
| --- | --- |
| `provider` | `github_dependabot` (the only provider) |
| `scope` | `repository` (default) or `org` for an organization-wide read |
| `scope_id` | The claim scope this target serves; part of every stored fact key, so choose it once and keep it. Scope IDs carrying shard or retirement markers are refused, since the host plans those, never this collector |
| `repository` / `organization` | The `owner/repo` to read, or the organization login for an `org` target |
| `auth_mode` | `token_env` (default) or `host_minted`. See Credentials below |
| `token_env` | For `token_env` targets: name of the environment variable holding the GitHub token |
| `allowed_repositories` | The only repositories this target may read; anything else is refused |
| `api_base_url` | GitHub API address, for example `https://api.github.com` |
| `repository_alert_limit`, `max_pages` | Most alerts to return per repository read; most pages to fetch |
| `source_uri` | Optional provenance address recorded on facts |

`config.limits` carries the shared host-level caps (`maxRecordsPerClaim`, `maxPayloadBytes`, `maxResultBytes`, `claimTimeoutSeconds`), and the host enforces them. One practical note: a large organization read can pass the host's default 4 MiB output cap, so raise `process.stdout_limit_bytes` together with your per-claim expectations, as the example does.

Unknown config keys are rejected. A bad activation fails the claim as terminal `invalid_config` before any GitHub contact, with a bounded reason attached to the failure class, for example `invalid_config.target_scope_mismatch` or `invalid_config.missing_host_token`. Anything that matches on the failure class should match the prefix `invalid_config`, not the exact string.

## Credentials

Secrets never go in the config file. Two credential shapes are served, and they never mix on one target.

With `token_env` (the default), you use a static GitHub token such as a personal access token. `token_env` names an environment variable the worker process already has, so `token_env: GITHUB_TOKEN` means "read the token from the variable called `GITHUB_TOKEN`." It's resolved once when the claim is parsed and sent as `Authorization: Bearer`.

With `host_minted`, the host mints a fresh GitHub App installation token per claim and delivers it at the top level of the config as `host_github_app_token: {token, scope_id}`. Leave `token_env` and every `github_app_*_env` entry empty. A missing, empty, or wrong-scope stanza fails closed as terminal `invalid_config` before any GitHub contact. Because the token is fresh each claim, an expired-token answer stays retryable (the next claim mints anew), while a static token failure is terminal until a person rotates it.

Direct `github_app` targets aren't served by this binary. Minting installation tokens is host-owned and no mint callback crosses the request boundary, so such a target fails at config parse. Use `host_minted` for GitHub App setups. Either way, token values never appear in facts, logs, or status messages. Errors name the variable or key, never the value.

## Time and size limits

Eshu gives each claim a deadline. The collector stops starting new GitHub calls shortly before it (the smaller of 2 seconds or 5% of the time left) and returns `retryable` with failure class `claim_deadline_exceeded` and no facts, instead of being killed mid-request or storing a half-finished read. A claim that arrives with no time left fails the same way at once, before any GitHub call.

Read size is bounded by `repository_alert_limit` and `max_pages`, and for organization targets by a cap of 100 follow-up repository reads per claim. Repositories past a cap keep their facts with a note that coverage was cut short, and the run reports `partial` where the code marks it so.
