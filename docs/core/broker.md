---
title: Broker
description: The zero-trust proxy runtime that validates and executes proxied requests.
---

The broker is the core runtime that sits between callers and upstream providers. It validates every request against capability policy, resolves credentials, injects auth, and returns sanitized responses.

## Validation pipeline

Every proxied request passes through these stages:

### 1. Capability lookup

The broker finds the capability definition by ID. Capabilities can come from:
- **Built-in registry** — compiled into the binary from `registry/*.json`
- **User-created** — added via `aivault capability create`

### 2. Credential resolution

The broker determines which credential to use for the request:
1. **Explicit** — caller passes `--credential <id>`
2. **Scoped** — workspace/group context narrows to matching credentials
3. **Default** — first credential for the capability's provider

### 3. Policy validation

The request must pass all policy checks:

- **Method**: request method must be in `allow.methods` (e.g. `["POST", "GET"]`)
- **Path**: request path must start with one of `allow.pathPrefixes` (e.g. `["/v1/chat/completions"]`)
- **Host**: the capability's host must match the credential's host list
- **Auth headers**: callers cannot supply auth-class headers (rejected)
- **Path traversal**: `../` and similar sequences are normalized and rejected

### 4. Advanced policy (optional)

If configured via `aivault capability policy set`:
- **Rate limits** — requests per minute
- **Request body size** — maximum bytes
- **Response body size** — maximum bytes
- **Response blocklist** — fields redacted from the response body

### 5. Auth injection

The broker decrypts the secret from the vault and renders the auth template:

| Strategy | Injection point |
|----------|----------------|
| `header` | HTTP header (e.g. `Authorization: Bearer {{secret}}`) |
| `query` | URL query parameter |
| `path` | URL path prefix (e.g. `/bot{{secret}}/getUpdates`) |
| `basic` | HTTP Basic auth header |
| `multi-header` | Multiple HTTP headers from a JSON secret |
| `multi-query` | Multiple query parameters from a JSON secret |
| `oauth2` | Bearer token (auto-refreshed from refresh token) |
| `aws-sigv4` | AWS Signature V4 signed request |
| `hmac` | HMAC signature of request body |
| `mtls` | Mutual TLS client certificate |

See [Auth strategies](/core/auth-strategies) for details on each.

### 6. Request building

The broker constructs the outgoing request:
- **Host**: derived from capability policy (never from caller)
- **Scheme**: always HTTPS
- **Path**: caller-supplied path, validated against policy
- **Headers**: caller-supplied headers minus auth-class headers, plus broker-injected auth
- **Body**: caller-supplied body (JSON, multipart, or raw)
- **Query**: caller-supplied query parameters preserved (plus any auth-injected query params)

### 7. Response sanitization

Before returning the response to the caller:
- Auth-class response headers are stripped (cookies, auth tokens, session IDs)
- Response body is filtered against per-capability blocklists
- In untrusted execution environments, all upstream response headers are stripped from output modes to prevent identifier/cookie leakage through agent context

## Error handling

The broker returns structured errors for policy violations:
- `CapabilityNotFound` — capability ID doesn't exist
- `CredentialNotFound` — no credential matches the provider
- `MethodNotAllowed` — request method not in allow-list
- `PathNotAllowed` — request path doesn't match any prefix
- `HostMismatch` — credential host doesn't match capability host
- `AuthHeaderRejected` — caller tried to supply auth-class headers
- `PathTraversal` — path contains traversal sequences
- `RateLimitExceeded` — per-capability rate limit hit
- `BodyTooLarge` — request or response body exceeds size limit

Next: [Registry](/core/registry)
