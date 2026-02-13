# aivault — Zero-Trust Credentials For Any Code

## What it looks like

Store your API key once:

```bash
aivault credential create openai --secret sk-abc123
```

Now any code on your machine — a skill, a coding agent, a script you built on the fly, anything — can transcribe audio, generate images, or run chat completions without ever seeing your key:

```bash
curl -sS "$AIVAULT_BASE_URL/aivault/proxy" \
  -H "Authorization: Bearer $AIVAULT_TOKEN" \
  -d '{
    "capability": "openai/transcription",
    "request": {
      "method": "POST",
      "path": "/v1/audio/transcriptions",
      "multipart": { "model": "whisper-1" },
      "multipartFiles": [{ "field": "file", "path": "/tmp/meeting.wav" }]
    }
  }'
```

The caller says _what_ it wants to do (`openai/transcription`). A local broker handles auth, enforces policy, and proxies the call. The code never touches `OPENAI_API_KEY`.

Add Gmail:

```bash
aivault credential create google --secret <oauth-json>
```

Now `google/gmail-read`, `google/calendar-read`, `google/drive-read` all work. Same pattern for AWS, Notion, Slack, Stripe — one credential per provider, all capabilities light up. This works the same whether the caller is a skill, a coding agent deploying to Vercel, a one-off script scraping Reddit, or a multi-step workflow chaining together APIs you've never combined before.

## The problem this solves

Skills have this problem worst today: you want a skill to call OpenAI, so you set `OPENAI_API_KEY` in the environment. You want it to check Gmail, so you put OAuth tokens in env too. Every key for every provider ends up in the same process environment, and every skill can see all of them.

But skills are just the most visible example. The same problem exists everywhere code touches API keys:

- A coding agent needs your Vercel token to deploy and your GitHub token to push. Both sit in env vars. The agent has access to both even when it only needs one.
- You ask an agent to do marketing research and it needs X/Twitter and Reddit API keys. Those keys live next to your Stripe key and your AWS credentials.
- You build a quick script on the fly to pull data from Notion and push it to Slack. That script runs in an environment with access to every secret you've ever set.

That used to be fine pre-LLMs when you wrote all the code yourself. It's not fine anymore when:

- An LLM has filesystem access and wrote the script that you're running.
- A prompt injection causes unexpected code to execute.
- You installed a community skill you haven't fully audited.
- A coding agent generates and executes code with access to every key on your machine.
- Your agent runs dozens of tasks with access to email, payments, cloud storage, and databases — all with keys sitting in env vars.

Any compromised script can `echo $OPENAI_API_KEY`, read `~/.aws/credentials`, or exfiltrate OAuth tokens to an external server. There's no isolation. And the exfiltration doesn't have to be obvious:

- A script posts your key to `api.openai.com.exfil.io` — looks close enough to the real thing that it sails through code review.
- An obfuscated payload hex-encodes or base64-encodes the outbound URL so the actual destination isn't human-readable. This is the same pattern crypto wallet drainers use — the code looks like noise, the reviewer skips it, and the keys are gone.
- A redirect chain starts at a legitimate-looking URL and bounces through 302s to a collection endpoint. Nothing in the source code reveals the final destination.
- A script `curl`s your key to a URL assembled at runtime from string fragments — no single line of code contains the full exfiltration target.

None of these require a sophisticated attacker. An LLM can generate any of them on a bad day, and a prompt injection can trigger them anytime.

`aivault` fixes this by putting a broker between any code and the APIs it needs. The code never sees the real key — it gets a scoped token that can only talk to the local broker. If it exfiltrates that token, it doesn't matter, because the token is worthless outside the local broker. The broker holds the real keys, enforces what each capability is allowed to do, and only proxies requests to an explicit allow-list of hosts — so none of the above attacks work even if the code is fully compromised.

This applies to everything: skills, coding agents, user-built scripts, just-in-time apps, multi-step workflows — anything that runs on a machine and needs to call an API. One vault, one proxy, zero trust.

## Design goals

- Any code — skills, agents, scripts, apps — makes authenticated API calls without seeing any credential material.
- One credential per provider in the simple case — store your OpenAI key once and all OpenAI capabilities work. Multiple credentials per provider (e.g. `openai-work` and `openai-personal`) are also first-class.
- Every common auth mechanism (API keys, OAuth 2.0, AWS Sig V4, HMAC, Basic, client certs) works through the same broker contract.
- A pre-loaded registry of well-known providers means zero policy authoring for common APIs.
- Custom APIs work with user-defined credentials and capabilities.
- Requests look as close to the real API as possible. Passthrough mode means a base URL swap is the only code change (e.g. `https://api.openai.com/...` -> `http://localhost:19790/v/openai/...`) and the request body is byte-for-byte identical to the upstream API.
- The standard is portable — any agent runtime, coding tool, or script runner can implement it.
- Local-first. No cloud dependency.

## Non-goals

- Prevent compromise of a fully compromised host OS.
- Prevent exfiltration of non-secret data that policy explicitly allows.
- Guarantee safety if code can read provider keys directly from env/files (the point is to stop putting keys there).
- Build provider-specific endpoints for every operation.

## Core Model

Three entities.

### Credential

A credential is one account with one provider. It has two jobs:

1. **`provider`** — links this credential to the registry (which capabilities exist, what auth strategy to use, which hosts are allowed). Many credentials can share the same provider.
2. **`id`** — uniquely identifies this account. Determines the secret keyspace. No two credentials share an id.

Simple case — one account per provider:

```json
{
  "id": "openai",
  "provider": "openai"
}
```

That's it. When a registry exists, the broker inherits `auth` and `hosts` from the registry's provider definition. The broker stores the secret material internally, keyed by credential id. Every `openai/*` capability works.

Multi-account case — same provider, different keys:

```json
[
  { "id": "openai-work", "provider": "openai" },
  { "id": "openai-personal", "provider": "openai" }
]
```

Both credentials share the same `provider: "openai"`, so they get the same auth strategy, hosts, and capabilities from the registry. But they're different credentials with different ids, so they hold different secrets.

The caller disambiguates by passing `"credential"` alongside `"capability"`:

```json
{
  "capability": "openai/transcription",
  "credential": "openai-work",
  "request": { ... }
}
```

If only one credential exists for a provider, the caller can omit `"credential"` and the broker resolves it automatically.

Custom credential — no registry, explicit config:

When the provider isn't in the registry, or you need to override hosts/auth, you provide them on the credential directly:

```json
{
  "id": "my-internal-api",
  "provider": "my-internal-api",
  "auth": {
    "type": "header",
    "headerName": "X-API-Key",
    "valueTemplate": "{{secret}}"
  },
  "hosts": ["api.internal.example.com"]
}
```

OAuth example:

```json
{
  "id": "google",
  "provider": "google"
}
```

Registry supplies: `auth` (oauth2/refresh_token, tokenEndpoint), `hosts` (gmail.googleapis.com, www.googleapis.com, etc.). The broker stores `{clientId, clientSecret, refreshToken}` keyed by credential id `google`.

Multi-account Google:

```json
[
  { "id": "google-work", "provider": "google" },
  { "id": "google-personal", "provider": "google" }
]
```

AWS example:

```json
{ "id": "aws-prod",    "provider": "aws" }
{ "id": "aws-staging", "provider": "aws" }
```

Registry supplies: `auth` (aws-sigv4), `hosts` pattern. Each credential has its own secret, keyed by its id (`aws-prod`, `aws-staging`).

A caller says:

```json
{ "capability": "aws/s3-read", "credential": "aws-staging", "request": { ... } }
```

#### How `provider` resolution works

When a credential is created:

1. If a registry entry exists for the credential's `provider`, the broker uses the registry's `auth`, `hosts`, and capabilities as defaults.
2. If the credential provides its own `auth` or `hosts`, those override the registry values for this credential.
3. If no registry entry matches, the credential MUST provide `auth` and `hosts` explicitly.

This means the registry defines _what OpenAI looks like_ once. Individual credentials just say "I'm an OpenAI account" and optionally override specifics (e.g. a different base URL for Azure OpenAI).

#### Secret storage

The broker stores and retrieves secret material by credential id. There is no indirection, no aliasing, and no way to point one credential at another credential's secret.

- Credential ids MUST be unique within a broker instance, so secrets are guaranteed non-conflicting.
- One credential id = one secret slot. Creating credential `evil-proxy` gives you an empty slot named `evil-proxy`. It cannot read from slot `openai`.
- How the broker organizes its storage internally (file paths, vault mount paths, keychain entries, etc.) is an implementation detail, not part of the spec.
- The registry never stores or references secret material.

#### Host patterns

- Credentials SHOULD list exact hosts (recommended, simplest, safest).
- For Core conformance, credential host entries MUST be exact hosts (no wildcards).
- For Core conformance, wildcard host patterns MUST be treated as invalid input (fail closed).
- Implementations MAY support wildcard hosts of the form `*.example.com` (single leading label wildcard only). If supported:
  - Wildcards MUST NOT match the apex host (`*.example.com` does not match `example.com`).
  - Wildcards MUST be interpreted as a suffix match on dot-boundaries (not a regex).
  - Implementations SHOULD normalize hosts to lowercase and handle international domains consistently (e.g. punycode).

Host matching rules:

- If the host entry does not start with `*.` then it MUST be an exact match only.
- Suffix matching without an explicit wildcard (e.g. allowing `sub.example.com` because `example.com` is listed) MUST NOT be supported.

### Capability

A capability is a named operation you can perform with a provider. It constrains which methods, hosts, and paths are allowed.

Capabilities bind to **providers**, not to specific credentials or callers. Any credential with `"provider": "openai"` can use any `openai/*` capability.

Note: capability IDs MUST be unique within a broker instance. This does NOT require that capability path prefixes are disjoint (overlap is allowed).

For Core conformance, capabilities MUST declare `allow.hosts` and it MUST contain exactly 1 host. (This keeps host selection deterministic and makes the capability ID effectively specify the upstream base URL.)

Registry capability (bound to provider):

```json
{
  "id": "openai/transcription",
  "provider": "openai",
  "allow": {
    "hosts": ["api.openai.com"],
    "methods": ["POST"],
    "pathPrefixes": ["/v1/audio/transcriptions"]
  }
}
```

User-defined capability (no registry; still bound to a provider):

```json
{
  "id": "my-api/users",
  "provider": "my-internal-api",
  "allow": {
    "hosts": ["api.internal.example.com"],
    "methods": ["GET", "POST"],
    "pathPrefixes": ["/v2/users"]
  }
}
```

A single provider backs many capabilities:

| Capability             | Methods           | Path prefixes              |
| ---------------------- | ----------------- | -------------------------- |
| `openai/transcription` | POST              | `/v1/audio/transcriptions` |
| `openai/chat`          | POST              | `/v1/chat/completions`     |
| `openai/images`        | POST              | `/v1/images/generations`   |
| `openai/embeddings`    | POST              | `/v1/embeddings`           |
| `openai/tts`           | POST              | `/v1/audio/speech`         |
| `openai/files`         | GET, POST, DELETE | `/v1/files`                |
| `openai/responses`     | GET, POST         | `/v1/responses`            |

The credential provides `auth` and a ceiling host allow-list (`hosts`). The capability provides the host actually used for the operation (`allow.hosts`).

For Core conformance, `allow.hosts` MUST be present and MUST contain exactly 1 host (even for single-host providers). This makes host selection deterministic and prevents spoofing.

### Capability Registry

The standard defines an optional capability registry format. Implementations MAY ship a registry for well-known providers to eliminate per-user policy authoring for common APIs.

When an implementation ships a registry and a user creates a credential with `"provider": "openai"`, all `openai/*` capabilities from the registry can be available immediately.

Registry entries are capability definitions without a `credential` field (the runtime binds them to the user's credential at activation time):

```json
{
  "id": "openai/transcription",
  "provider": "openai",
  "allow": {
    "hosts": ["api.openai.com"],
    "methods": ["POST"],
    "pathPrefixes": ["/v1/audio/transcriptions"]
  }
}
```

Users can define custom capabilities for providers not in the registry, or to create narrower grants than the defaults.

Implementations that do not ship a registry are still conforming: users simply create credentials and capabilities explicitly.

## How Activation Works

One credential per provider. All capabilities for that provider light up. No per-capability setup.

Multiple accounts for the same provider:

```bash
aivault credential create openai-work     --provider openai --secret sk-work-key
aivault credential create openai-personal  --provider openai --secret sk-personal-key
```

Both get all `openai/*` capabilities. Different credential ids, different secrets. Callers disambiguate with `"credential": "openai-work"` in the request.

Custom APIs (no registry):

```bash
aivault credential create my-api \
  --provider my-api \
  --auth-type header \
  --header-name X-API-Key \
  --value-template '{{secret}}' \
  --hosts api.example.com \
  --secret my-api-key-value

aivault capability create my-api/users \
  --provider my-api \
  --methods GET POST \
  --paths /v2/users
```

## Caller Contract

Any code that needs to make an authenticated API call — a skill, a coding agent, a script, an app — is a "caller." Callers receive two env vars:

- `AIVAULT_BASE_URL` — the broker base URL
- `AIVAULT_TOKEN` — scoped capability token for this execution

The runtime (agent framework, skill runner, script launcher) is responsible for minting the token and injecting these env vars before the code runs. The caller doesn't need to know how the vault works — it just makes requests.

### Proxy request (`POST /aivault/proxy`)

The caller passes a **capability ID** and the HTTP request it wants to make. The broker resolves the capability to a credential, validates the request against the capability's allow-list, injects auth, and proxies the call.

The caller does NOT provide an upstream URL. The capability ID determines which upstream host(s) are permitted, and the broker constructs the final upstream URL. This is a core security property: envelope mode MUST be immune to host/scheme spoofing by callers.

Required fields:

- `capability` — which operation to perform (e.g. `openai/transcription`)
- `request.method` — HTTP method
- `request.path` — HTTP path (MUST start with `/`). MAY include a query string (e.g. `/v1/files?purpose=assistants`).

Optional fields:

- `request.headers` — additional headers (broker strips reserved headers; auth headers are broker-controlled)
- `request.body` — string body (often JSON)
- `request.multipart` — key/value fields for multipart requests
- `request.multipartFiles` — array of `{field, path}` for multipart file uploads (broker reads the file and builds the multipart)
- `request.bodyFilePath` — read a local file and stream it as the request body
- `credential` — which credential to use (only needed when multiple credentials exist for the same provider)

Multipart note: callers SHOULD NOT set `Content-Type: multipart/form-data`. The broker constructs the multipart body and sets the correct `Content-Type` including a boundary.

Invalid fields (fail closed):

- `request.url` — if present, the broker MUST reject the request with `policy_violation` (do not "discard and continue").

#### Proxy envelope shape (normative)

This spec is intentionally small. The broker MUST accept the following JSON shape. For Core conformance, implementations MUST reject unknown fields (fail closed).

```json
{
  "capability": "openai/transcription",
  "credential": "openai-work",
  "request": {
    "method": "POST",
    "path": "/v1/audio/transcriptions",
    "headers": [{ "name": "accept", "value": "application/json" }],
    "multipart": { "model": "whisper-1" },
    "multipartFiles": [{ "field": "file", "path": "/tmp/meeting.wav" }]
  }
}
```

Notes:

- The broker constructs the upstream scheme/host/port from policy. For Core conformance, the scheme is `https` (or `wss` for WebSocket) unless an operator explicitly permits otherwise for a configured local service.
- At most one of `body`, `multipart`(+`multipartFiles`), or `bodyFilePath` SHOULD be present. If more than one is present, the broker MUST reject the request (fail closed). If none are present, the request body is empty.
- `request.headers` is optional. The broker MUST strip reserved headers and MUST reject caller-supplied auth-class headers for managed credentials.

### Proxy response

The broker returns the upstream HTTP status code, forwards upstream headers (excluding hop-by-hop and broker-managed headers), and streams the upstream response body without buffering. Streaming responses (SSE/chunked) work automatically — no special endpoint needed.

## Broker Resolution Chain

1. Caller sends request (e.g. `{ "capability": "openai/transcription", "request": { ... } }`).
2. Broker looks up capability `openai/transcription` → provider `openai`.
3. Broker resolves which credential to use:
   a. If the request includes `"credential": "openai-work"`, use that credential (must match the capability's provider).
   b. If the proxy token is scoped to a specific credential, use that.
   c. If only one credential exists for provider `openai`, use it (unambiguous default).
   d. If multiple credentials exist and none of the above disambiguate, return error `credential_ambiguous`.
4. Broker assembles policy from credential + capability:
   a. Credential provides `auth` and `hosts` (upper-bound host allow-list).
   b. Capability provides `allow.hosts`, `allow.methods`, `allow.pathPrefixes`.
   c. Effective allowed hosts are the intersection of (credential hosts) and (capability allow.hosts). If empty, fail closed.
5. Broker validates the request method + path against the capability's allow-list and selects the upstream host from `allow.hosts` (Core: exactly one host).
6. Broker resolves the secret using the credential id (or `secretRef` override if present).
7. Broker applies the credential's auth strategy and proxies the request.

The resolution chain means:

- Callers that don't care about accounts just say `"capability": "openai/transcription"` and it works when there's one credential.
- Callers that need a specific account add `"credential": "openai-work"`.
- Runtimes can also pin credentials via token scoping (e.g. an execution scoped to `openai-work` never needs to specify it per-request).

## Token Model

Two separate auth classes:

1. **Operator token**: vault/secret management, credential CRUD, capability CRUD.
2. **Proxy token**: broker endpoint only, short TTL. Minted by the runtime before code executes. Optionally scoped by:
   - **Capability IDs** — a token scoped to `["openai/transcription"]` cannot call `openai/chat`.
   - **Credential ID** — a token scoped to `"openai-work"` will always resolve to that credential, eliminating ambiguity. Callers don't need to pass `"credential"` per request.
  - **Workspace/groupId** — implementation-specific context.

Credential scoping on tokens is the recommended way to handle multi-account providers. The runtime mints a token pinned to a credential; the caller just says `"capability": "openai/transcription"` and the token handles the rest.

Do not reuse a single gateway bearer token for both proxy and secret-admin endpoints.

### Local-only binding (default)

The broker is intended to run on localhost and MUST NOT be exposed to the public internet by default.

- Implementations MUST bind to loopback by default (e.g. `127.0.0.1` / `::1`).
- Implementations MUST reject proxy requests from non-loopback clients unless an operator explicitly opts in to remote access.

This is what makes stolen proxy tokens practically worthless outside the machine: the broker is not reachable.

### Minimal operator APIs (normative)

This spec does not mandate a specific storage backend, but it DOES require an authenticated operator API surface so that executing code cannot mutate policy or retrieve secrets.

Normative minimum endpoints (names are illustrative; exact paths may differ, but capabilities MUST exist):

- Credentials: create/list/get/update/delete.
- Capabilities: create/list/get/update/delete.
- Proxy tokens: mint short-lived proxy tokens for an execution context.

Recommended canonical endpoints:

- `POST/GET /aivault/credentials`
- `GET/PATCH/DELETE /aivault/credentials/:id`
- `POST/GET /aivault/capabilities`
- `GET/PATCH/DELETE /aivault/capabilities/:id`
- `POST /aivault/tokens/proxy`

#### Proxy token mint (normative)

Implementations MUST provide a way for a trusted runtime to mint short-lived proxy tokens without exposing operator credentials to untrusted code. The simplest approach is an operator-authenticated mint endpoint that returns an opaque bearer token.

Recommended request/response shapes:

`POST /aivault/tokens/proxy` request:

```json
{
  "capabilities": ["openai/transcription"],
  "credential": "openai-work",
  "ttlMs": 600000,
  "context": { "workspaceId": "default", "groupId": "dev" }
}
```

Response:

```json
{
  "token": "avp_...",
  "expiresAtMs": 1739400000000
}
```

Rules:

- The returned proxy token MUST be usable only for broker/proxy endpoints (not operator endpoints).
- If `credential` is provided, the broker MUST enforce that every listed capability is valid for that credential's provider.
- Tokens SHOULD be opaque and validated server-side (no requirement for self-contained JWTs).

### Operator secrets (recommended)

Many runtimes need "normal vault" secrets to operate the local system itself (not just to proxy outbound API calls). Examples include:

- gateway auth tokens
- messaging channel tokens (e.g. Telegram bot token)
- OAuth setup payloads/config (e.g. an OAuth JSON blob used during setup)

This spec supports that by allowing an operator-controlled secret store alongside credentials/capabilities. Requirements:

- Secret CRUD MUST require operator auth (operator token).
- Proxy tokens MUST NOT be able to read, create, update, or revoke operator secrets.
- Operator secrets MAY be "system-managed" (operator-visible metadata + rotate/revoke controls, but not editable by executing code).

Recommended (optional) endpoints for operator secret management:

- `POST/GET /aivault/secrets`
- `GET/PATCH/DELETE /aivault/secrets/:id`
- `POST /aivault/secrets/:id/rotate`

## Auth Strategies

The auth strategy is a property of the credential, not the capability. The caller never knows which strategy is being used.

### `header` — Static key injected as an HTTP header

Covers: OpenAI, Anthropic, Deepgram, ElevenLabs, Sendgrid, most API-key services.

Vault stores: the API key as a single secret string.

```json
{
  "auth": {
    "type": "header",
    "headerName": "Authorization",
    "valueTemplate": "Bearer {{secret}}"
  }
}
```

`valueTemplate` examples: `"Bearer {{secret}}"`, `"{{secret}}"`, `"Basic {{secret}}"`. Custom header names like `xi-api-key` for ElevenLabs.

### `query` — Static key injected as a URL query parameter

Covers: some map APIs, legacy REST APIs.

```json
{
  "auth": {
    "type": "query",
    "paramName": "api_key"
  }
}
```

### `basic` — HTTP Basic authentication

Covers: JIRA, webhooks, some REST APIs.

Vault stores: `{"username": "...", "password": "..."}` as a JSON object.

```json
{
  "auth": {
    "type": "basic"
  }
}
```

### `oauth2` — OAuth 2.0 with automatic token lifecycle

Covers: Gmail, Google Calendar, Google Drive, Notion, Slack, Spotify, GitHub, Dropbox, Salesforce, HubSpot, Microsoft Graph.

Vault stores: `{"clientId": "...", "clientSecret": "...", "refreshToken": "...", "tokenEndpoint": "..."}` as a JSON object.

Broker action: checks cached access token, refreshes if expired, stores updated tokens back to Vault, injects `Authorization: Bearer <access_token>`.

```json
{
  "auth": {
    "type": "oauth2",
    "grantType": "refresh_token",
    "tokenEndpoint": "https://oauth2.googleapis.com/token",
    "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
  }
}
```

For service-to-service (client credentials grant):

```json
{
  "auth": {
    "type": "oauth2",
    "grantType": "client_credentials",
    "tokenEndpoint": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    "scopes": ["https://graph.microsoft.com/.default"]
  }
}
```

The initial OAuth consent flow (authorization code exchange) happens outside the broker — through a setup UI or CLI command — and stores the refresh token in Vault.

### `aws-sigv4` — AWS Signature Version 4 request signing

Covers: S3, DynamoDB, Lambda, SES, SQS, every AWS service.

Vault stores: `{"accessKeyId": "...", "secretAccessKey": "...", "region": "..."}`. Optional `sessionToken` for assumed roles.

```json
{
  "auth": {
    "type": "aws-sigv4",
    "service": "s3",
    "region": "us-east-1"
  }
}
```

### `hmac` — HMAC request signing

Covers: Stripe webhooks, Twilio, some payment and notification APIs.

```json
{
  "auth": {
    "type": "hmac",
    "algorithm": "sha256",
    "headerName": "X-Signature",
    "valueTemplate": "sha256={{signature}}"
  }
}
```

### `mtls` — Client certificate authentication

Covers: banking APIs, enterprise integrations, Apple push notifications.

Vault stores: `{"cert": "...", "key": "..."}` as PEM-encoded strings.

```json
{
  "auth": {
    "type": "mtls"
  }
}
```

### Strategy extensibility

New auth types can be added without changing the proxy contract. Implementations SHOULD treat unknown `auth.type` values as an error and fail closed.

## Policy Enforcement

The broker MUST:

- Fail closed on missing/empty hosts, methods, or pathPrefixes.
- Treat empty allow-lists as invalid input (do not interpret empty as "allow all"). If you need "allow all paths", express it explicitly with `pathPrefixes: ["/"]`.
- Normalize paths and reject traversal attempts.
- For Core conformance: allow only `https` (HTTP) and `wss` (WebSocket). Support for `http`/`ws` MAY exist as an extension for explicitly configured local services.
- For Core conformance: allow only default ports for the scheme. Non-default ports MAY exist as an extension.
- For Core conformance: block private IPs, link-local, loopback, and cloud metadata endpoints (SSRF). Operator-defined exceptions MAY exist as an extension.
- These scheme/port/SSRF rules apply to upstream targets. The broker itself may be served over plain HTTP on localhost.
- Redirects: the broker MUST NOT follow redirects in a way that can exfiltrate auth to a new host. Implementations MAY either:
  - block redirects entirely (simple, safe), or
  - follow redirects while re-validating every hop against policy and stripping auth headers before following to a new host.
- Strip reserved headers (auth, hop-by-hop, framing).
- MUST NOT forward caller-supplied auth headers for managed credentials (implementations MAY reject such requests).
  Policy is assembled from credential + capability.
  - The credential provides `auth` and an upper-bound host allow-list (`hosts`).
  - The capability provides `allow.hosts`, `allow.methods`, and `allow.pathPrefixes`.
  - The effective allowed hosts are the intersection of credential hosts and capability hosts.
  - The effective policy MUST fail closed if that intersection is empty.

Notes:

- For WebSocket proxying, treat the upstream upgrade request as `GET` for purposes of method enforcement.
- If a capability is intended for WebSocket use, its `pathPrefixes` MUST constrain the WebSocket upstream `path` the same way it constrains HTTP paths.

Reserved headers (normative minimum):

- auth: `authorization`, `proxy-authorization`
- host: `host`
- hop-by-hop: `connection`, `keep-alive`, `te`, `trailer`, `transfer-encoding`, `upgrade`
- framing: `content-length`
- websocket upgrade: `sec-websocket-*` (the broker manages upgrade headers)

## Transport Modes

Two modes, from most explicit to most transparent. They coexist — use whichever fits the caller.

### Envelope mode (`POST /aivault/proxy`)

The caller sends a JSON envelope with `capability`, optional `credential`, and a `request` object. The broker resolves credentials, validates policy, constructs the upstream URL, injects auth, and proxies the call.

Envelope mode is the most explicit mode — best for programmatic use where you want fine-grained capability scoping and maximum anti-spoofing.

Streaming responses (SSE/chunked) work automatically because the broker streams upstream bytes back to the caller.

### Passthrough mode (`/v/{credential}/...`)

The caller makes a request that looks identical to the upstream API, but points at the broker instead:

```
# Instead of:
POST https://api.openai.com/v1/chat/completions

# Hit the broker:
POST http://localhost:19790/v/openai/v1/chat/completions
```

The broker strips the `/v/{credential}` prefix, resolves the credential (here `openai`), matches the remaining method + path against capabilities for that credential's provider, injects auth, and proxies to the real upstream.

Upstream host selection (passthrough):

- The broker MUST select the upstream host from the matched capability's `allow.hosts`.
- For Core conformance, `allow.hosts` contains exactly one host, so upstream host selection is deterministic.

An LLM that knows how to call OpenAI's API just swaps the base URL. No new envelope format to learn, no wrapper objects, no SDK changes. For multi-account providers, the credential segment disambiguates: `/v/openai-work/v1/chat/completions` vs `/v/openai-personal/v1/chat/completions`.

Capability matching in passthrough mode is automatic: the broker matches the HTTP method + path against registered capabilities for that credential's provider. If no capability matches, the request is rejected.

Proxy token interaction (passthrough):

- The broker MUST evaluate the request against the set of capabilities granted by the proxy token.
- The request is allowed if it matches at least one granted capability (method + path + host policy).
- For audit labeling, the broker SHOULD record the most specific matching capability (longest matching `pathPrefix`) and MAY also record the full set of matches.

### Which mode to use

| Mode        | Code changes       | Capability scoping   | Best for                                          |
| ----------- | ------------------ | -------------------- | ------------------------------------------------- |
| Envelope    | New request format | Explicit per-request | Vault-aware SDKs, fine-grained capability control |
| Passthrough | Base URL swap only | Inferred from path   | Drop-in API replacement, LLM-generated code       |

Both modes enforce the same policy, use the same credentials, and produce the same audit trail. The difference is ergonomics.

### WebSocket proxy (`GET /aivault/ws`)

The caller opens a WebSocket to the broker. First client message is a JSON connect frame:

```json
{
  "capability": "deepgram/realtime",
  "path": "/v1/listen"
}
```

The broker constructs the upstream WebSocket URL from the capability's `allow.hosts` and the provided `path` (default scheme `wss`). It validates host + path against policy, opens the upstream WebSocket with injected auth, and proxies frames bidirectionally.

Invalid fields (fail closed):

- `targetUrl` — if present in the connect frame, the broker MUST reject the connection with `policy_violation`.

### Broker errors

```json
{
  "error": "policy_violation",
  "message": "Host 'evil.com' not allowed for capability 'openai/transcription'"
}
```

Error codes: `policy_violation`, `capability_not_found`, `credential_not_found`, `credential_ambiguous`, `vault_unavailable`, `auth_failed`, `upstream_unreachable`, `token_invalid`.

## Registry Structure

```
aivault/
├── spec/
│   └── aivault.md
├── registry/
│   ├── openai.json
│   ├── anthropic.json
│   ├── google.json
│   ├── aws.json
│   ├── notion.json
│   ├── slack.json
│   ├── github.json
│   ├── deepgram.json
│   ├── elevenlabs.json
│   ├── stripe.json
│   ├── twilio.json
│   └── microsoft.json
├── schemas/
│   ├── credential.schema.json
│   ├── capability.schema.json
│   └── proxy-envelope.schema.json
├── tests/
│   ├── policy-enforcement/
│   ├── auth-strategies/
│   └── schema-validation/
└── README.md
```

Each registry file defines one provider: credential template (auth strategy, hosts, setup instructions) and all its capabilities.

Important: the registry is data, not protocol. A conforming broker implementation does not need to ship a registry; it only needs to support the credential/capability model and proxy contract. The registry exists to make common providers turnkey.

### Registry immutability

The registry MUST be immutable to executing code at runtime. Acceptable approaches:

- **Compiled into the binary** (strongest) — Rust `include_str!`, Go `embed`, etc. To change the registry, ship a new version.
- **Read-only assets with integrity checks** — registry files shipped alongside the binary, verified by checksum or signature at load time. Tampering is detected before any data is loaded.
- **Vault-stored** — registry data stored in the vault's encrypted storage, managed through the authenticated operator API.

The constraint is not "must be compiled in" — it's "executing code must not be able to modify it." If an attacker could edit `openai.json` to add `evil.com` to the hosts list, they could proxy your OpenAI key to an attacker-controlled server through a "legitimate" capability.

Custom providers that aren't in the built-in registry are handled through user-defined credentials with explicit `auth` and `hosts` — managed through the authenticated operator API and stored in the vault's encrypted storage, not as plain files on disk.

Registry credential templates do not contain secret material. Secret storage is handled by the broker using the credential id as the lookup key (see Secret storage above).

Example `registry/openai.json`:

```json
{
  "$schema": "../schemas/registry-provider.schema.json",
  "provider": "openai",
  "credential": {
    "auth": {
      "type": "header",
      "headerName": "Authorization",
      "valueTemplate": "Bearer {{secret}}"
    },
    "hosts": ["api.openai.com"],
    "setup": {
      "secretType": "string",
      "description": "OpenAI API key from https://platform.openai.com/api-keys"
    }
  },
  "capabilities": [
    {
      "id": "openai/transcription",
      "description": "Speech-to-text via Whisper",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["POST"],
        "pathPrefixes": ["/v1/audio/transcriptions"]
      }
    },
    {
      "id": "openai/chat",
      "description": "Chat completions (including streaming)",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["POST"],
        "pathPrefixes": ["/v1/chat/completions"]
      }
    },
    {
      "id": "openai/responses",
      "description": "Responses API",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["GET", "POST"],
        "pathPrefixes": ["/v1/responses"]
      }
    },
    {
      "id": "openai/images",
      "description": "Image generation",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["POST"],
        "pathPrefixes": ["/v1/images/generations"]
      }
    },
    {
      "id": "openai/embeddings",
      "description": "Text embeddings",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["POST"],
        "pathPrefixes": ["/v1/embeddings"]
      }
    },
    {
      "id": "openai/tts",
      "description": "Text-to-speech",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["POST"],
        "pathPrefixes": ["/v1/audio/speech"]
      }
    },
    {
      "id": "openai/files",
      "description": "File upload and management",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["GET", "POST", "DELETE"],
        "pathPrefixes": ["/v1/files"]
      }
    }
  ]
}
```

## Custom Capabilities

Users define custom capabilities the same way as registry capabilities: bound to a provider.

```json
{
  "id": "my-api/users",
  "provider": "my-api",
  "allow": {
    "hosts": ["api.example.com"],
    "methods": ["GET", "POST"],
    "pathPrefixes": ["/v2/users"]
  }
}
```

Or via CLI:

```bash
aivault capability create my-api/users \
  --provider my-api \
  --methods GET POST \
  --paths /v2/users
```

## Threat Model

In scope: malicious/compromised code of any kind (skills, agents, scripts, user-built apps), prompt injection, arbitrary host requests, auth header smuggling, config tampering.

Out of scope: full host compromise, data exfiltration within allowed policy, malicious operator (the operator already has the keys).

### Attack scenarios

**1. Secret exfiltration via env vars**

Attack: Code reads `$OPENAI_API_KEY` from the environment and sends it to an external server.

Defense: Provider secrets are never in the caller's environment. The caller only receives `AIVAULT_BASE_URL` and `AIVAULT_TOKEN`. The proxy token is worthless outside the local broker.

**2. Capability escalation**

Attack: Code scoped to `openai/transcription` tries to call `openai/chat` to run up your bill or exfiltrate data through chat completions.

Defense: The broker enforces path constraints per capability, not per credential. Even though both capabilities share the same API key, a token scoped to `openai/transcription` cannot call `/v1/chat/completions`. The broker rejects the request before it ever reaches OpenAI.

**3. Credential cross-read**

Attack: Code creates a new credential `exfil-proxy` with `hosts: ["evil.com"]` and tries to point it at the `openai` credential's secret, then proxies your key to the attacker's server.

Defense: Credential CRUD requires operator auth. Executing code only receives proxy tokens, which cannot create or modify credentials. Even if it could, secret storage is keyed strictly by credential ID — there is no aliasing or indirection. Credential `exfil-proxy` has an empty secret slot named `exfil-proxy`. It cannot read from slot `openai`.

**4. Registry tampering**

Attack: Code modifies a registry file on disk (e.g. adds `evil.com` to `openai.json`'s host list) so the broker will proxy real keys to attacker-controlled servers through "legitimate" capabilities.

Defense: The registry is compiled into the binary at build time. There are no editable registry files on disk at runtime. User-defined credentials and capabilities are stored in the vault's encrypted storage and managed through authenticated operator APIs.

**5. Host spoofing / typosquatting**

Attack: Code sends a proxy request to `api.openai.com.exfil.io` hoping the broker's host matching is loose enough to match `api.openai.com`.

Defense: Host matching is exact (or explicit wildcard with dot-boundary suffix matching). `api.openai.com.exfil.io` does not match `api.openai.com` or `*.openai.com`. The broker rejects the request.

**6. Redirect-chain exfiltration**

Attack: Code requests a legitimate-looking URL that returns a 302 redirect to an attacker-controlled server. The broker follows the redirect, sending auth headers to the attacker.

Defense: The broker either blocks redirects entirely, or follows redirects while re-validating every hop against policy and stripping auth headers before following to a new host. A redirect to `evil.com` is rejected because `evil.com` is not allowed.

**7. Auth header smuggling**

Attack: Code tries to sneak auth material past the broker so the upstream receives attacker-controlled credentials. This goes beyond the obvious `Authorization: Bearer` header — real attempts include case/encoding tricks (`AUTHORIZATION`, whitespace padding), duplicate headers (send it twice, hope one survives), non-standard auth headers that specific APIs also accept (`X-Auth-Token`, `X-Authorization`), and body-level auth (API keys in query params or JSON body fields).

Defense: The broker strips reserved headers using case-insensitive matching, rejects duplicate auth-class headers, and strips any credential-specific auth header declared in the credential's `auth` config (e.g. if a credential uses `X-API-Key`, callers cannot set `X-API-Key`).

For query-param auth, the broker MUST own the auth query parameter value:

- In envelope mode, the caller provides `request.path`; the broker constructs the upstream URL and injects the query auth parameter itself. If the caller includes that parameter in `request.path`, the broker MUST reject the request (fail closed).
- In passthrough mode, the broker MUST remove any existing query parameter matching the credential's query-auth `paramName` (if applicable) and then add the broker-controlled value.

Body-level auth injection is out of scope — the broker does not parse or rewrite request bodies, and APIs that accept auth in request bodies are inherently harder to protect at the proxy layer.

**8. SSRF via proxy**

Attack: Code asks the broker to proxy a request to `http://169.254.169.254/latest/meta-data/` (cloud metadata endpoint) or `http://localhost:8080/admin` (internal service) using a credential's auth.

Defense: For Core conformance, the broker blocks private IPs, link-local addresses, loopback, and cloud metadata endpoints, and only allows `https` (and `wss` for WebSocket). Extensions MAY allow operator-defined exceptions for explicitly configured local services. The executing code cannot override these defaults — only the operator can open that door.

**9. Local file exfiltration via multipart**

Attack: Code tells the broker to read `~/.ssh/id_rsa` and send it to an attacker-controlled server via a multipart upload.

Defense: The host allow-list. The file can only be sent to hosts the credential authorizes (e.g. `api.openai.com`), not to attacker-controlled servers. Whether the broker reads the file or the caller reads it and passes the bytes through — the same data goes to the same constrained set of hosts. Filesystem access control (restricting which paths can be read) is outside the broker's scope and up to the runtime environment.

**10. Token theft across executions**

Attack: Code saves its `AIVAULT_TOKEN` to disk for use in a later execution, or passes it to another process.

Defense: Proxy tokens have short TTLs and are scoped to a single execution context. A stolen token expires quickly and cannot be used outside the scoped capabilities/credentials it was minted for. Runtimes that sandbox execution can further restrict filesystem write access to prevent persisting tokens, but this is outside the broker's scope.

## Security Requirements

### Secret isolation

1. Provider secrets MUST NOT be present in caller env vars.
2. Provider secrets MUST NOT be stored in caller-accessible files.
3. Broker MUST resolve and inject auth server-side from Vault.
4. Secret storage MUST be keyed strictly by credential ID. No aliasing, no indirection, no cross-credential references or retrieval.

### Policy enforcement

5. Proxy requests MUST identify capabilities by well-known or user-defined ID (envelope mode), or the broker MUST infer the capability from the request shape (passthrough mode).
6. Broker MUST enforce host/method/path constraints per capability.
7. Broker MUST NOT forward caller-supplied auth headers for managed credentials.
8. Redirects: the broker MUST NOT follow redirects in a way that can exfiltrate auth to a new host. Implementations MAY block redirects entirely, or follow them with per-hop re-validation and auth stripping.
9. For Core conformance: broker MUST block private IPs, link-local, loopback, and cloud metadata endpoints (SSRF). Operator-defined exceptions MAY exist as an extension.
10. For Core conformance: broker MUST allow only `https` (HTTP) and `wss` (WebSocket). Support for `http`/`ws` MAY exist as an extension for explicitly configured local services.
11. The broker MAY read files from disk on behalf of callers (for multipart uploads, streaming request bodies). Filesystem access control is outside the broker's scope — the host allow-list constrains where file contents can be sent regardless of how they enter the request.

### Auth and tokens

12. Broker access MUST use scoped proxy tokens, not broad admin auth.
13. Proxy tokens SHOULD be short-lived, scoped to a single execution context.
14. Proxy tokens SHOULD be scopeable to specific capability IDs and/or credential IDs.
15. Credential/capability/secret CRUD MUST require operator auth. Proxy tokens MUST NOT be able to create, modify, or delete credentials, capabilities, or operator secrets.

### Config integrity

16. The provider registry MUST be immutable at runtime. Implementations SHOULD compile it into the binary.
17. User-defined credentials, capabilities, and operator secrets MUST be stored in encrypted vault storage, managed through authenticated operator APIs — not as plain files on disk.
18. Broker MUST be localhost-only by default (bind loopback and reject non-loopback clients unless explicitly enabled by an operator).

### Audit

19. All broker calls MUST be auditable (capability used, credential resolved, host contacted, timestamp, caller context).

## Implementation Plan

### Phase 1: Core broker (+ optional registry)

- Credential and capability as separate entities.
- (Optional) ship registry for: OpenAI, Anthropic, Deepgram, ElevenLabs, Notion.
- Envelope mode: `POST /aivault/proxy` with `capability` + `request.path` (no caller-supplied upstream URL).
- Passthrough mode: `/v/{credential}/...` with capability inference from method + path.
- `header`, `query`, `basic` auth strategies.
- Scoped proxy tokens.
- Core policy: exact host allow-lists only, `allow.hosts` required (exactly one host), localhost-only binding by default.

### Phase 2: OAuth + more providers

- `oauth2` auth strategy with refresh and caching.
- OAuth setup flow (UI/CLI consent + token exchange).
- (Optional) registry: Google (Gmail, Calendar, Drive), Slack, GitHub, Spotify, Microsoft Graph.

### Phase 3: Signing + WebSocket

- `aws-sigv4` and `hmac` auth strategies.
- `GET /aivault/ws` WebSocket proxy.
- (Optional) registry: AWS (S3, SES, SQS), Stripe, Twilio, Deepgram real-time.

### Phase 4: Advanced

- `mtls` auth strategy.
- Per-capability rate/size limits.
- Response body filtering.

## Conformance Levels

To keep adoption simple, `aivault` defines additive conformance levels. Implementers can ship a secure core quickly and add convenience features later.

- `Core`: credentials + capabilities, envelope mode (`POST /aivault/proxy` with `request.path`), passthrough mode (`/v/{credential}/...`), `allow.hosts` required (exactly one host), allow-list enforcement, reserved header stripping, SSRF protections, localhost-only binding by default, structured broker errors.
- `Registry` (optional): ability to load provider registry files and activate provider capabilities based on `credential.provider`.
- `OAuth2`: `oauth2` auth strategy with refresh and caching.
- `WebSocket`: `GET /aivault/ws` with connect frame (`capability` + `path`) + frame relay.
- `Signing`: `aws-sigv4` and `hmac` auth strategies.
- `mTLS`: `mtls` auth strategy.

## Success Criteria

- User stores one API key per provider. All capabilities for that provider light up.
- Any code — skills, agents, scripts, apps — uses well-known capability IDs (`openai/transcription`, `google/gmail-read`) without auth config.
- Adding a new provider to the registry is a JSON file, not a code change.
- Custom APIs work with user-defined credentials + capabilities using the same contract.
- Code scoped to one capability cannot use another, even under the same credential.
- A coding agent deploying to Vercel can't read your Gmail. A script pulling from Notion can't touch your Stripe keys. Zero trust by default.
- Envelope mode is immune to URL spoofing: callers provide only `request.path`, and the broker determines the upstream scheme/host/port from policy.
- The broker is localhost-only by default (not internet-exposed).
- The standard remains portable.

## Section Coverage Checklist (Story-Linked)

Legend: `[x]` covered by implemented/tested user story evidence, `[ ]` missing or not yet story-backed.

### What it looks like

- [x] Credential creation/provider binding flow is covered by [`vault-credential-provider-binding`](./user-stories/vault.json) and [`token-operator-crud-surface`](./user-stories/tokens.json).
- [x] Caller contract via `AIVAULT_BASE_URL` and `AIVAULT_TOKEN` is covered by [`env-caller-env-vars-contract`](./user-stories/proxy-envelope.json).
- [x] Envelope-mode URL control (caller gives path, broker owns upstream) is covered by [`env-reject-caller-url-field`](./user-stories/proxy-envelope.json) and [`transport-envelope-upstream-derived-from-policy`](./user-stories/transport.json).

### The problem this solves

- [x] Secret isolation from caller env/files and server-side auth injection is covered by [`sec-stolen-proxy-token-limited-by-scope-and-ttl`](./user-stories/security-policy.json), [`vault-secret-slot-isolation`](./user-stories/vault.json), and [`token-operator-secret-crud-isolated-from-proxy`](./user-stories/tokens.json).
- [x] Capability-scoped execution instead of broad account auth is covered by [`token-proxy-scope-capability-and-credential`](./user-stories/tokens.json) and [`transport-passthrough-token-scope-evaluation`](./user-stories/transport.json).

### Design goals

- [x] One-credential-per-provider default activation is covered by [`vault-provider-activation-default`](./user-stories/vault.json).
- [x] User-defined capabilities/providers under the same enforcement model is covered by [`cap-user-defined-capabilities`](./user-stories/capabilities.json), [`reg-custom-provider-explicit-auth-hosts`](./user-stories/registry.json), and [`reg-custom-capabilities-same-schema`](./user-stories/registry.json).
- [x] Zero-trust outcomes are covered by [`conf-success-criteria-zero-trust-outcomes`](./user-stories/conformance.json).

### Non-goals

### Core Model

- [x] Credential/capability/provider model baseline is covered by [`vault-credential-provider-binding`](./user-stories/vault.json) and [`cap-provider-binding`](./user-stories/capabilities.json).

#### Credential

- [x] Multi-account provider disambiguation is covered by [`vault-credential-multi-account-disambiguation`](./user-stories/vault.json).
- [x] Credential overrides over provider defaults are covered by [`vault-credential-provider-resolution-overrides`](./user-stories/vault.json).

#### How `provider` resolution works

- [x] Registry default resolution is covered by [`reg-provider-based-capability-activation`](./user-stories/registry.json).
- [x] Fail-closed explicit auth/hosts for non-registry providers is covered by [`reg-custom-provider-explicit-auth-hosts`](./user-stories/registry.json).

#### Secret storage

- [x] Credential-id-keyed secret isolation is covered by [`vault-secret-slot-isolation`](./user-stories/vault.json).
- [x] Credential ID uniqueness enforcement is covered by [`vault-credential-id-uniqueness`](./user-stories/vault.json).

#### Host patterns

- [x] Core exact-host enforcement is covered by [`vault-host-pattern-core-exact-match`](./user-stories/vault.json).
- [x] Wildcard boundary/apex behavior is covered by [`sec-host-wildcard-dot-boundary-rules`](./user-stories/security-policy.json).
- [x] Punycode/IDN normalization behavior is covered by [`sec-host-punycode-normalization`](./user-stories/security-policy.json).

#### Capability

- [x] Capability ID uniqueness with overlap allowance is covered by [`cap-id-uniqueness-with-overlap`](./user-stories/capabilities.json).
- [x] Core single-host `allow.hosts` enforcement is covered by [`cap-core-single-upstream-host`](./user-stories/capabilities.json).
- [x] Method/path contract is covered by [`cap-method-and-path-prefix-contract`](./user-stories/capabilities.json).

#### Capability Registry

- [x] Registry optionality and activation behavior are covered by [`reg-optional-conformance`](./user-stories/registry.json) and [`reg-provider-based-capability-activation`](./user-stories/registry.json).
- [x] Registry contains no secret material and retains provider-bound capability schema via [`reg-no-secret-material-in-registry`](./user-stories/registry.json) and [`reg-capability-shape-without-credential-field`](./user-stories/registry.json).

### How Activation Works

- [x] Default provider activation and multi-account disambiguation are covered by [`vault-provider-activation-default`](./user-stories/vault.json) and [`vault-credential-multi-account-disambiguation`](./user-stories/vault.json).
- [x] Scope-aware capability binding/resolution is covered by [`cap-foundation-bind-and-unbind-by-scope`](./user-stories/capabilities.json) and [`cap-foundation-resolution-precedence`](./user-stories/capabilities.json).

### Caller Contract

- [x] Caller env contract is covered by [`env-caller-env-vars-contract`](./user-stories/proxy-envelope.json).

#### Proxy request (`POST /aivault/proxy`)

- [x] Required fields and caller URL rejection are covered by [`env-required-request-fields`](./user-stories/proxy-envelope.json) and [`env-reject-caller-url-field`](./user-stories/proxy-envelope.json).
- [x] Single body mode fail-closed behavior is covered by [`env-single-body-mode-enforcement`](./user-stories/proxy-envelope.json).
- [x] Multipart `Content-Type` ownership is covered by [`env-multipart-content-type-owned-by-broker`](./user-stories/proxy-envelope.json).

#### Proxy envelope shape (normative)

- [x] Unknown-field rejection and shape validation are covered by [`env-reject-unknown-fields`](./user-stories/proxy-envelope.json) and [`env-required-request-fields`](./user-stories/proxy-envelope.json).
- [x] Reserved/auth header caller controls are covered by [`sec-reserved-and-auth-class-header-controls`](./user-stories/security-policy.json).

#### Proxy response

- [x] Streaming response forwarding is covered by [`env-streaming-response-forwarding`](./user-stories/proxy-envelope.json).
- [x] Response header filtering is covered by [`transport-response-header-filtering`](./user-stories/transport.json).

### Broker Resolution Chain

- [x] Credential resolution ordering is covered by [`env-credential-resolution-order`](./user-stories/proxy-envelope.json) and [`token-credential-pin-auto-resolution`](./user-stories/tokens.json).
- [x] Full ordered chain has end-to-end evidence via [`env-broker-resolution-chain-e2e`](./user-stories/proxy-envelope.json).
- [x] `secretRef` override behavior is covered in capability binding resolution via [`cap-foundation-secretref-override`](./user-stories/capabilities.json).

### Token Model

- [x] Operator/proxy auth class separation is covered by [`token-operator-and-proxy-class-separation`](./user-stories/tokens.json).
- [x] Scoped/TTL proxy-token behavior is covered by [`token-proxy-scope-capability-and-credential`](./user-stories/tokens.json) and [`token-proxy-ttl-and-context`](./user-stories/tokens.json).

#### Local-only binding (default)

- [x] Loopback-default and non-loopback rejection are covered by [`token-localhost-default-enforcement`](./user-stories/tokens.json).

#### Minimal operator APIs (normative)

- [x] Operator-authenticated credential/capability CRUD and mint surface are covered by [`token-operator-crud-surface`](./user-stories/tokens.json) and [`token-mint-proxy-endpoint`](./user-stories/tokens.json).
- [x] Proxy-token isolation from operator routes is covered by [`token-proxy-broker-endpoints-only`](./user-stories/tokens.json) and [`token-operator-secret-crud-isolated-from-proxy`](./user-stories/tokens.json).

#### Proxy token mint (normative)

- [x] Mint endpoint + opaque tokens + provider compatibility enforcement are covered by [`token-mint-proxy-endpoint`](./user-stories/tokens.json), [`token-opaque-server-side-validation`](./user-stories/tokens.json), and [`token-mint-validates-capability-provider-compatibility`](./user-stories/tokens.json).

#### Operator secrets (recommended)

- [x] Operator-secret CRUD isolation from proxy tokens is covered by [`token-operator-secret-crud-isolated-from-proxy`](./user-stories/tokens.json).
- [x] System-managed secret subclass behavior is covered by [`token-operator-system-managed-secrets`](./user-stories/tokens.json).

### Auth Strategies

- [x] `header` auth strategy is covered by [`auth-header-injection`](./user-stories/auth-strategies.json).
- [x] `query` auth strategy is covered by [`auth-query-injection`](./user-stories/auth-strategies.json) and [`sec-query-auth-param-owned-by-broker`](./user-stories/security-policy.json).
- [x] `basic` auth strategy is covered by [`auth-basic-injection`](./user-stories/auth-strategies.json).
- [x] `oauth2` refresh + cache + `client_credentials` + scopes are covered by [`auth-oauth2-refresh-and-cache`](./user-stories/auth-strategies.json), [`auth-oauth2-client-credentials-grant`](./user-stories/auth-strategies.json), and [`auth-oauth2-scopes-applied`](./user-stories/auth-strategies.json).
- [x] OAuth consent/setup boundary outside broker is covered by [`auth-oauth2-consent-outside-broker`](./user-stories/auth-strategies.json).
- [x] `aws-sigv4` + optional session token are covered by [`auth-aws-sigv4-signing`](./user-stories/auth-strategies.json) and [`auth-aws-session-token-optional`](./user-stories/auth-strategies.json).
- [x] `hmac` strategy + canonical signing input are covered by [`auth-hmac-signing`](./user-stories/auth-strategies.json) and [`auth-hmac-canonical-signature-input`](./user-stories/auth-strategies.json).
- [x] `mtls` is covered by [`auth-mtls-client-cert`](./user-stories/auth-strategies.json).
- [x] Unknown strategy fail-closed extensibility behavior is covered by [`auth-unknown-type-fails-closed`](./user-stories/auth-strategies.json).

### Policy Enforcement

- [x] Fail-closed validation, traversal rejection, and explicit allow-all path semantics are covered by [`sec-fail-closed-empty-policy-inputs`](./user-stories/security-policy.json), [`sec-path-normalization-traversal-rejection`](./user-stories/security-policy.json), and [`sec-path-prefix-root-explicit-allow-all`](./user-stories/security-policy.json).
- [x] Scheme/port/SSRF and redirect controls are covered by [`sec-scheme-port-ssrf-guards`](./user-stories/security-policy.json) and [`sec-redirect-auth-exfiltration-guard`](./user-stories/security-policy.json).
- [x] Header/auth/query controls and host intersection are covered by [`sec-reserved-and-auth-class-header-controls`](./user-stories/security-policy.json), [`sec-reserved-header-normative-minimum`](./user-stories/security-policy.json), [`sec-query-auth-param-owned-by-broker`](./user-stories/security-policy.json), and [`sec-effective-host-intersection-fail-closed`](./user-stories/security-policy.json).
- [x] WebSocket policy parity controls are covered by [`transport-websocket-upgrade-method-enforced-as-get`](./user-stories/transport.json) and [`transport-websocket-upstream-derived-from-capability`](./user-stories/transport.json).

### Transport Modes

#### Envelope mode (`POST /aivault/proxy`)

- [x] Envelope mode URL derivation and policy application are covered by [`transport-envelope-upstream-derived-from-policy`](./user-stories/transport.json) and [`env-required-request-fields`](./user-stories/proxy-envelope.json).

#### Passthrough mode (`/v/{credential}/...`)

- [x] Base URL swap, credential extraction, capability inference, and token scope checks are covered by [`transport-passthrough-base-url-swap`](./user-stories/transport.json), [`transport-passthrough-credential-segment-extraction`](./user-stories/transport.json), [`transport-passthrough-capability-inference`](./user-stories/transport.json), and [`transport-passthrough-token-scope-evaluation`](./user-stories/transport.json).
- [x] Upstream host derivation from policy and query-auth param ownership are covered by [`transport-passthrough-host-derived-from-capability`](./user-stories/transport.json) and [`sec-query-auth-param-owned-by-broker`](./user-stories/security-policy.json).

#### Which mode to use

- [x] Both envelope and passthrough contracts are covered by [`transport-envelope-upstream-derived-from-policy`](./user-stories/transport.json) and [`transport-passthrough-base-url-swap`](./user-stories/transport.json).

#### WebSocket proxy (`GET /aivault/ws`)

- [x] Connect frame, target URL rejection, policy-derived upstream URL, and GET-method enforcement are covered by [`transport-websocket-connect-frame`](./user-stories/transport.json), [`transport-websocket-reject-target-url`](./user-stories/transport.json), [`transport-websocket-upstream-derived-from-capability`](./user-stories/transport.json), and [`transport-websocket-upgrade-method-enforced-as-get`](./user-stories/transport.json).

#### Broker errors

- [x] Structured error schema and full core enumeration are covered by [`transport-structured-broker-errors`](./user-stories/transport.json) and [`transport-error-code-enumeration`](./user-stories/transport.json).

### Registry Structure

- [x] Registry schema/activation behavior is covered by [`reg-provider-based-capability-activation`](./user-stories/registry.json), [`reg-capability-shape-without-credential-field`](./user-stories/registry.json), and [`reg-no-secret-material-in-registry`](./user-stories/registry.json).
- [x] User-defined config encrypted-vault handling is covered by [`vault-foundation-envelope-encryption-at-rest`](./user-stories/vault.json) and [`token-operator-secret-crud-isolated-from-proxy`](./user-stories/tokens.json).
- [x] JSON-only provider extensibility is covered by [`reg-json-only-provider-extensibility`](./user-stories/registry.json).

#### Registry immutability

- [x] Runtime immutability is covered by [`reg-runtime-immutability`](./user-stories/registry.json).

### Custom Capabilities

- [x] Custom capabilities use the same provider-bound schema and enforcement path as registry capabilities via [`cap-user-defined-capabilities`](./user-stories/capabilities.json) and [`reg-custom-capabilities-same-schema`](./user-stories/registry.json).

### Threat Model

- [x] Threat-model controls are implemented and tested across env/file exfiltration, SSRF, header smuggling, and token theft via [`sec-body-file-path-host-constrained-egress`](./user-stories/security-policy.json), [`sec-scheme-port-ssrf-guards`](./user-stories/security-policy.json), [`sec-reserved-and-auth-class-header-controls`](./user-stories/security-policy.json), and [`sec-stolen-proxy-token-limited-by-scope-and-ttl`](./user-stories/security-policy.json).

#### Attack scenarios

- [x] Attack scenarios are mapped to tested controls in security-policy stories, especially [`sec-query-auth-param-owned-by-broker`](./user-stories/security-policy.json), [`sec-effective-host-intersection-fail-closed`](./user-stories/security-policy.json), and [`sec-broker-call-audit-records`](./user-stories/security-policy.json).

### Security Requirements

#### Secret isolation

- [x] Requirements 1/3/4 are covered by [`env-caller-env-vars-contract`](./user-stories/proxy-envelope.json), [`vault-secret-slot-isolation`](./user-stories/vault.json), and [`vault-credential-id-uniqueness`](./user-stories/vault.json).
- [x] Requirement 2 is covered by [`sec-secrets-not-in-caller-accessible-files`](./user-stories/security-policy.json).

#### Policy enforcement

- [x] Requirements 5-11 are covered by [`transport-passthrough-capability-inference`](./user-stories/transport.json), [`cap-method-and-path-prefix-contract`](./user-stories/capabilities.json), [`sec-reserved-and-auth-class-header-controls`](./user-stories/security-policy.json), [`sec-redirect-auth-exfiltration-guard`](./user-stories/security-policy.json), [`sec-scheme-port-ssrf-guards`](./user-stories/security-policy.json), and [`sec-body-file-path-host-constrained-egress`](./user-stories/security-policy.json).

#### Auth and tokens

- [x] Requirements 12-15 are covered by [`token-operator-and-proxy-class-separation`](./user-stories/tokens.json), [`token-proxy-ttl-and-context`](./user-stories/tokens.json), [`token-proxy-scope-capability-and-credential`](./user-stories/tokens.json), and [`token-operator-secret-crud-isolated-from-proxy`](./user-stories/tokens.json).

#### Config integrity

- [x] Requirements 16-18 are covered by [`reg-runtime-immutability`](./user-stories/registry.json), [`vault-foundation-envelope-encryption-at-rest`](./user-stories/vault.json), and [`token-localhost-default-enforcement`](./user-stories/tokens.json).

#### Audit

- [x] Requirement 19 is covered by [`sec-broker-call-audit-records`](./user-stories/security-policy.json).

### Implementation Plan

#### Phase 1: Core broker (+ optional registry)

- [x] Phase 1 items are covered by core domain stories, especially [`conf-core-level-minimum`](./user-stories/conformance.json), [`transport-envelope-upstream-derived-from-policy`](./user-stories/transport.json), [`transport-passthrough-base-url-swap`](./user-stories/transport.json), and [`reg-optional-conformance`](./user-stories/registry.json).

#### Phase 2: OAuth + more providers

- [x] OAuth2 runtime behavior is covered by [`conf-oauth2-level`](./user-stories/conformance.json), [`auth-oauth2-refresh-and-cache`](./user-stories/auth-strategies.json), and [`auth-oauth2-client-credentials-grant`](./user-stories/auth-strategies.json).
- [x] OAuth setup tooling flow is covered by [`auth-oauth2-setup-tooling-flow`](./user-stories/auth-strategies.json).

#### Phase 3: Signing + WebSocket

- [x] Phase 3 items are covered by [`conf-signing-level`](./user-stories/conformance.json), [`conf-websocket-level`](./user-stories/conformance.json), [`auth-aws-sigv4-signing`](./user-stories/auth-strategies.json), [`auth-hmac-signing`](./user-stories/auth-strategies.json), and [`transport-websocket-connect-frame`](./user-stories/transport.json).

#### Phase 4: Advanced

- [x] mTLS item is covered by [`conf-mtls-level`](./user-stories/conformance.json) and [`auth-mtls-client-cert`](./user-stories/auth-strategies.json).
- [x] Per-capability rate/size limits are covered by [`adv-capability-rate-and-size-limits`](./user-stories/security-policy.json).
- [x] Response body filtering is covered by [`adv-response-body-filtering`](./user-stories/security-policy.json).

### Conformance Levels

- [x] Core/Registry/OAuth2/WebSocket/Signing/mTLS additive levels are covered by [`conf-core-level-minimum`](./user-stories/conformance.json), [`conf-registry-level-optional`](./user-stories/conformance.json), [`conf-oauth2-level`](./user-stories/conformance.json), [`conf-websocket-level`](./user-stories/conformance.json), [`conf-signing-level`](./user-stories/conformance.json), and [`conf-mtls-level`](./user-stories/conformance.json).

### Success Criteria

- [x] Security and zero-trust outcomes are covered by [`conf-success-criteria-zero-trust-outcomes`](./user-stories/conformance.json).
- [x] "Adding a new provider is JSON-only, no code changes" is covered by [`reg-json-only-provider-extensibility`](./user-stories/registry.json).
