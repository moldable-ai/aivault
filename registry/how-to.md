# Adding a Provider to the Registry

How to add or expand a provider's capabilities in the aivault built-in registry.

## Workflow

### 1. Discover the API surface

Fetch the provider's `llms.txt` (or equivalent docs index) to get a structured listing of all endpoints:

```
curl https://developers.openai.com/api/reference/llms.txt
curl https://elevenlabs.io/docs/llms-full.txt
curl https://developers.deepgram.com/llms.txt
```

If no `llms.txt` exists, look for an OpenAPI spec, Swagger UI, or API reference sidebar. The goal is a complete list of endpoint groups with their HTTP methods and path patterns.

### 2. Map endpoints to capabilities

Each capability is a logical API surface an agent might need. Group by function, not by individual endpoint:

| Capability ID | What it covers |
|---|---|
| `openai/chat-completions` | `POST /v1/chat/completions` + `GET` for retrieval |
| `elevenlabs/dubbing` | `POST /v1/dubbing` (create) + `GET` (status/download) + `DELETE` |
| `deepgram/transcription` | `POST /v1/listen` (pre-recorded) + `GET` (WebSocket streaming) |

**Rules of thumb:**

- One capability per logical product area (e.g. "text-to-speech", not one per sub-endpoint).
- Use `pathPrefixes` prefix matching -- `/v1/dubbing` matches `/v1/dubbing`, `/v1/dubbing/{id}`, `/v1/dubbing/{id}/audio`, etc.
- Only include the HTTP methods actually used. `POST`-only APIs stay `POST`-only. CRUD resources get `POST, GET, DELETE` (and `PATCH`/`PUT` where needed).
- If the provider offers WebSocket streaming on the same path as a REST endpoint, add `GET` -- the broker's `execute_ws_connect` hardcodes `method: "GET"` for the WebSocket upgrade handshake and will reject capabilities that don't allow it.
- Capability IDs follow the pattern `provider/kebab-case-name`.

### 3. Decide what to include vs. skip

**Include** (agent-facing capabilities):
- Core product APIs (inference, generation, transcription, etc.)
- Resource management that agents commonly need (voices, files, models)
- Platform features agents interact with (assistants, conversational AI)

**Skip** (admin/infrastructure concerns):
- Org/workspace management, billing, user administration
- Service accounts, API key management, audit logs
- Webhook configuration
- Features not yet publicly available

### 4. Write the JSON file

Create or edit `registry/<provider>.json`. Follow the schema at `registry/schemas/registry-provider.schema.json`.

```json
{
  "$schema": "./schemas/registry-provider.schema.json",
  "provider": "acme",
  "auth": {
    "header": {
      "header_name": "authorization",
      "value_template": "Bearer {{secret}}"
    }
  },
  "hosts": ["api.acme.com"],
  "capabilities": [
    {
      "id": "acme/generate",
      "provider": "acme",
      "allow": {
        "hosts": ["api.acme.com"],
        "methods": ["POST"],
        "pathPrefixes": ["/v1/generate"]
      }
    }
  ]
}
```

**Auth patterns by provider type:**

| Pattern | Example |
|---|---|
| Bearer token | `"authorization"` / `"Bearer {{secret}}"` |
| Custom header | `"xi-api-key"` / `"{{secret}}"` |
| Token prefix | `"authorization"` / `"Token {{secret}}"` |

### 5. Verify

```bash
pnpm lint    # compiles all registry JSON via include_dir! + serde; catches malformed files
pnpm test    # runs full test suite including registry load
```

Registry JSON is embedded at compile time (`include_dir!` in `src/registry.rs`) and deserialized via serde on load. Any structural error -- bad JSON, missing required fields, unknown keys -- will surface as a compile or test failure. There is no separate schema validation script; `pnpm lint` is sufficient.

## Examples

### Single-method, single-path (simplest case)

Text intelligence endpoint -- one POST, one path:

```json
{
  "id": "deepgram/text-intelligence",
  "provider": "deepgram",
  "allow": {
    "hosts": ["api.deepgram.com"],
    "methods": ["POST"],
    "pathPrefixes": ["/v1/read"]
  }
}
```

### REST + WebSocket streaming on the same path

Deepgram transcription supports both pre-recorded (`POST`) and streaming (`GET` for WebSocket upgrade) on the same path prefix:

```json
{
  "id": "deepgram/transcription",
  "provider": "deepgram",
  "allow": {
    "hosts": ["api.deepgram.com"],
    "methods": ["POST", "GET"],
    "pathPrefixes": ["/v1/listen"]
  }
}
```

### Multi-method CRUD resource

Files API -- create, list, retrieve, delete:

```json
{
  "id": "openai/files",
  "provider": "openai",
  "allow": {
    "hosts": ["api.openai.com"],
    "methods": ["POST", "GET", "DELETE"],
    "pathPrefixes": ["/v1/files"]
  }
}
```

### Multiple path prefixes under one capability

Assistants API spans two path families:

```json
{
  "id": "openai/assistants",
  "provider": "openai",
  "allow": {
    "hosts": ["api.openai.com"],
    "methods": ["POST", "GET", "DELETE"],
    "pathPrefixes": ["/v1/assistants", "/v1/threads"]
  }
}
```

### Versioned paths (v1 + v2)

ElevenLabs voices migrated list to v2 but kept v1 for single-voice operations:

```json
{
  "id": "elevenlabs/voices",
  "provider": "elevenlabs",
  "allow": {
    "hosts": ["api.elevenlabs.io"],
    "methods": ["POST", "GET", "DELETE"],
    "pathPrefixes": ["/v1/voices", "/v2/voices"]
  }
}
```

### WebSocket-only capability on a separate host

Deepgram's voice agent lives on a dedicated host (`agent.deepgram.com`) and is WebSocket-only:

```json
{
  "id": "deepgram/voice-agent",
  "provider": "deepgram",
  "allow": {
    "hosts": ["agent.deepgram.com"],
    "methods": ["GET"],
    "pathPrefixes": ["/v1/agent"]
  }
}
```

When a capability uses a different host from the provider's primary API, include both in the top-level `"hosts"` array (e.g. `["api.deepgram.com", "agent.deepgram.com"]`) and scope each capability's `allow.hosts` to the specific host it targets.

## Common mistakes

- **Over-scoping paths**: `/v1/` would match the entire API. Always use the most specific prefix.
- **Missing methods**: Forgetting `DELETE` on resources that support removal. Check each sub-endpoint.
- **Missing `GET` for WebSocket**: If the endpoint supports WebSocket streaming, the capability must include `GET`. The broker enforces `GET` for all WebSocket upgrades; a `POST`-only capability will reject WebSocket connections.
- **Splitting too fine**: Don't create separate capabilities for `/v1/dubbing` and `/v1/dubbing/{id}/audio`. One capability per product area.
- **Including admin endpoints**: Workspace, billing, and API key endpoints shouldn't be capabilities.
