---
title: Registry schema
description: JSON schema reference for registry provider definitions.
---

Each registry provider is a JSON file in `registry/` that conforms to the `registry-provider.schema.json` schema.

## Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider` | string | yes | Unique provider identifier (e.g. `openai`, `stripe`) |
| `vaultSecrets` | object | no | Maps canonical secret names to auth template placeholders |
| `auth` | object/string | yes | Auth strategy configuration |
| `hosts` | string[] | yes | Allowed upstream hosts |
| `capabilities` | object[] | yes | Capability definitions |

## vaultSecrets

Maps the secret names operators use with `secrets create --name` to template placeholders in the auth configuration.

```json
{
  "vaultSecrets": {
    "OPENAI_API_KEY": "secret"
  }
}
```

This means: when someone stores `OPENAI_API_KEY`, it maps to `{{secret}}` in the auth template. For multi-secret providers:

```json
{
  "vaultSecrets": {
    "TRELLO_API_KEY": "api_key",
    "TRELLO_TOKEN": "token"
  }
}
```

## auth

The auth field supports these variants:

### header
```json
{
  "auth": {
    "header": {
      "header_name": "authorization",
      "value_template": "Bearer {{secret}}"
    }
  }
}
```

### query
```json
{
  "auth": {
    "query": {
      "param_name": "key"
    }
  }
}
```

### path
```json
{
  "auth": {
    "path": {
      "prefix_template": "/bot{{secret}}"
    }
  }
}
```

### multi_header
```json
{
  "auth": {
    "multi_header": [
      { "header_name": "DD-API-KEY", "value_template": "{{api_key}}" },
      { "header_name": "DD-APPLICATION-KEY", "value_template": "{{app_key}}" }
    ]
  }
}
```

### multi_query
```json
{
  "auth": {
    "multi_query": [
      { "param_name": "key", "value_template": "{{api_key}}" },
      { "param_name": "token", "value_template": "{{token}}" }
    ]
  }
}
```

### o_auth2
```json
{
  "auth": {
    "o_auth2": {
      "grant_type": "refresh_token",
      "token_endpoint": "https://accounts.spotify.com/api/token",
      "scopes": ["playlist-read-private"]
    }
  }
}
```

### aws_sig_v4
```json
{
  "auth": {
    "aws_sig_v4": {
      "service": "bedrock-runtime",
      "region": "us-east-1"
    }
  }
}
```

### hmac
```json
{
  "auth": {
    "hmac": {
      "algorithm": "sha256",
      "header_name": "x-hub-signature-256",
      "value_template": "sha256={{signature}}"
    }
  }
}
```

### basic / mtls
```json
{ "auth": "basic" }
{ "auth": "mtls" }
```

## hosts

Array of allowed upstream hostnames. Wildcards are supported for per-tenant providers:

```json
{ "hosts": ["api.openai.com"] }
{ "hosts": ["*.myshopify.com"] }
```

## capabilities

Each capability defines:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique capability ID (e.g. `openai/chat-completions`) |
| `provider` | string | yes | Must match the top-level `provider` |
| `allow.hosts` | string[] | yes | Allowed hosts (usually matches top-level `hosts`) |
| `allow.methods` | string[] | yes | Allowed HTTP methods (e.g. `["POST", "GET"]`) |
| `allow.pathPrefixes` | string[] | yes | Allowed path prefixes (e.g. `["/v1/chat/completions"]`) |

```json
{
  "capabilities": [
    {
      "id": "openai/chat-completions",
      "provider": "openai",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["POST", "GET"],
        "pathPrefixes": ["/v1/chat/completions"]
      }
    }
  ]
}
```

## Full example

```json
{
  "$schema": "./schemas/registry-provider.schema.json",
  "provider": "openai",
  "vaultSecrets": {
    "OPENAI_API_KEY": "secret"
  },
  "auth": {
    "header": {
      "header_name": "authorization",
      "value_template": "Bearer {{secret}}"
    }
  },
  "hosts": ["api.openai.com"],
  "capabilities": [
    {
      "id": "openai/chat-completions",
      "provider": "openai",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["POST", "GET"],
        "pathPrefixes": ["/v1/chat/completions"]
      }
    },
    {
      "id": "openai/transcription",
      "provider": "openai",
      "allow": {
        "hosts": ["api.openai.com"],
        "methods": ["POST"],
        "pathPrefixes": ["/v1/audio/transcriptions"]
      }
    }
  ]
}
```

Next: [Operations](/ops)
