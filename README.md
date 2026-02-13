# aivault

Standalone Rust CLI for local vault lifecycle, secret management, and capability-to-secret bindings.

## Current status

`aivault` currently ships:

- a local CLI (`aivault ...`) for vault and capability binding workflows
- reusable broker runtime types/methods in Rust (`src/broker/*`)
- a CLI-driven proxy execution path (`aivault invoke` / `aivault capability invoke`) that executes real upstream requests through capability + credential policy

`aivault` does **not** yet ship a network daemon with HTTP routes like `POST /aivault/proxy` or `GET /aivault/ws`.
Those proxy contracts are modeled and tested at the broker runtime layer today, and can be exposed by adding a server adapter.

## Why this exists

`aivault` extends a proven vault runtime foundation with a product-agnostic operator CLI. It is designed to reintegrate into host runtimes without forcing host-specific defaults.

## Commands

- `aivault status`
- `aivault init --provider <macos-keychain|env|file|passphrase> ...`
- `aivault unlock --passphrase <value>`
- `aivault lock`
- `aivault rotate-master [--new-key <base64>] [--new-passphrase <value>]`
- `aivault audit [--limit <n>] [--before-ts-ms <ms>]`
- `aivault secrets list/create/update/rotate/delete/...` (legacy capability-binding surface remains)
- `aivault oauth setup --provider ... --auth-url ... --client-id ... --redirect-uri ... [--scope ...]`
- `aivault credential create <id> --provider ... --secret-ref vault:secret:<id> --auth ... --host ...`
- `aivault credential list`
- `aivault credential delete <id>`
- `aivault capability create <id> --credential <credential-id> --method ... --path ... [--host ...]`
- `aivault capability list`
- `aivault capability delete <id>`
- `aivault capability policy set --capability <id> [--rate-limit-per-minute ...] [--max-request-body-bytes ...] [--max-response-body-bytes ...] [--response-block ...]`
- `aivault capability describe <id>` (aliases: `args`, `shape`, `inspect`)
- `aivault capability invoke <id> ...` (alias: `call`)
- `aivault invoke <id> ...` (top-level alias of `capability invoke`)
- `aivault resolve --secret-ref vault:secret:<id> [--raw]`
- `aivault resolve-team --secret-ref vault:secret:<id> --workspace-id ... --team ... [--raw]`

## Quickstart (CLI)

You can call into `aivault` directly via CLI right now:

```bash
# Optional: isolate local testing data
export AIVAULT_DIR="$(mktemp -d)"

# Inspect vault status (auto-initializes in a fresh dir)
aivault status

# Create a secret
aivault secrets create \
  --name OPENAI_API_KEY \
  --value sk-test \
  --scope global

# Resolve it back (replace <secret-id> with returned secretId)
aivault resolve --secret-ref vault:secret:<secret-id> --raw
```

Capability binding flow:

```bash
# Bind capability -> secret
aivault capabilities bind \
  --capability openai/transcription \
  --secret-ref vault:secret:<secret-id> \
  --scope global

# Resolve capability to secret value
aivault capabilities resolve \
  --capability openai/transcription \
  --raw
```

OAuth setup helper (consent/exchange stays outside broker):

```bash
aivault oauth setup \
  --provider google \
  --auth-url https://accounts.google.com/o/oauth2/v2/auth \
  --client-id <client-id> \
  --redirect-uri http://127.0.0.1:8787/callback \
  --scope gmail.readonly
```

## Make proxied requests (CLI)

This is the minimum end-to-end flow today without running a daemon:

```bash
export AIVAULT_DIR="$(mktemp -d)"

# 1) Store secret material in the vault.
secret_id=$(
  aivault secrets create --name OPENAI_API_KEY --value sk-test --scope global \
  | sed -n 's/.*"secretId": "\([^"]*\)".*/\1/p'
)

# 2) Create broker credential policy (provider/auth/hosts + secretRef).
aivault credential create openai \
  --provider openai \
  --secret-ref "vault:secret:$secret_id" \
  --auth header \
  --host postman-echo.com

# 3) Create capability policy.
aivault capability create openai/get \
  --credential openai \
  --method GET \
  --path /get

# 4) See what call args are required/optional for this capability.
aivault capability describe openai/get

# 5) Execute proxied request through capability policy.
aivault invoke openai/get --path '/get?foo=bar'

# Alternate: pass full request JSON from a file.
cat > /tmp/request.json <<'JSON'
{"method":"GET","path":"/get?foo=bar","headers":[]}
JSON
aivault capability invoke openai/get --request-file /tmp/request.json
```

This returns JSON containing planned request details and the proxied upstream response (status/headers/body).

## HTTP contract status

If you want to call using:

- `POST /aivault/proxy`
- `GET /aivault/ws`
- `/v/{credential}/...`

those contracts are implemented at the broker runtime model level, but this repo still needs a network adapter/daemon to expose those routes.
Use `aivault invoke` (or `aivault capability invoke`) today for real request execution without a daemon.

## Calling broker runtime directly (Rust)

If you need proxy planning behavior today, call broker APIs in-process:

```rust
use aivault::broker::{Broker, RequestAuth, ProxyEnvelope};

let mut broker = Broker::default();
let envelope = Broker::parse_envelope(r#"{"capability":"x","request":{"method":"GET","path":"/v1"}}"#)?;
let planned = broker.execute_envelope(&RequestAuth::Proxy("token".into()), envelope, "127.0.0.1".parse()?);
```

The network adapter layer (HTTP/WS server exposing `/aivault/proxy`, `/v/{credential}/...`, `/aivault/ws`) is planned but not included yet in this repo.

## Quality checks

- `make lint` runs `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features -- -D warnings`
- `make test` runs `cargo test --all-targets --all-features`
- `make check` runs `cargo check --all-targets --all-features`
- `make ci` runs the full local CI chain (`lint` + `test`)

### E2E test suites

- Local CLI e2e (no external network, always run): `cargo test --test e2e_cli_local`
- Local TLS listener e2e (deterministic real proxy round-trip against in-process HTTPS listener): `cargo test --test e2e_cli_local_tls`
- Network CLI e2e (real upstream HTTPS calls, opt-in): `AIVAULT_E2E_NETWORK=1 cargo test --test e2e_cli_invoke`

For local TLS listener testing, the CLI supports development-only HTTP client overrides:

- `AIVAULT_DEV_RESOLVE` with `host=ip:port` pairs (comma-separated)
- `AIVAULT_DEV_CA_CERT_PATH` pointing to a PEM CA/root certificate
- `AIVAULT_DEV_ALLOW_NON_DEFAULT_PORTS=1` to allow explicit `host:port` authorities
- `AIVAULT_DEV_HTTP1_ONLY=1` to force HTTP/1.1 for simple local listeners

These are intended for local/e2e testing only.

GitHub Actions runs the same checks on push and pull requests via `/Users/rob/aivault/.github/workflows/ci.yml`.

## Storage defaults

By default, the vault runtime uses:

- `AIVAULT_DIR` when set
- otherwise `~/.aivault/data/vault`

Provider defaults:

- key env var: `AIVAULT_KEY`
- disk audit disable flag: `AIVAULT_DISABLE_DISK_LOGS`
- keychain service default: `aivault`

Inside the vault root:

- `vault.json` for provider and KEK metadata
- `secrets/*.json` for encrypted secret records
- `audit/*.jsonl` for append-only audit events
- `capabilities.json` for capability-to-secret bindings
- `broker.json` for credential/capability/policy records used by `aivault credential ...` and `aivault capability ...`

## Reintegration notes

The repository keeps extraction boundaries stable:

- `src/vault/*` is the reusable vault runtime core
- `src/app.rs`, `src/cli.rs`, and `src/capabilities.rs` are CLI/operator orchestration layers

This allows host-specific adapters to be added without forking vault internals.
