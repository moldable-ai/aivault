---
title: Auth strategies
description: How secrets become auth headers, query params, path segments, and more.
---

aivault supports ten auth strategies. For registry-backed providers, the strategy is defined in the registry JSON and applied automatically. For custom providers, you specify the strategy when creating a credential.

## Header

A single HTTP header with a `{{secret}}` template.

**Example providers:** OpenAI (`Bearer`), Anthropic (`x-api-key`), Discord (`Bot`)

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

The broker renders `Bearer {{secret}}` → `Bearer sk-live-...` and injects it as the `authorization` header.

## Query

API key as a URL query parameter.

**Example providers:** Gemini, YouTube Data

```json
{
  "auth": {
    "query": {
      "param_name": "key"
    }
  }
}
```

The broker appends `?key=<secret>` to the request URL.

## Path

Secret injected into the URL path prefix.

**Example providers:** Telegram

```json
{
  "auth": {
    "path": {
      "prefix_template": "/bot{{secret}}"
    }
  }
}
```

The broker prepends `/bot<secret>` to the request path, so a request to `/getUpdates` becomes `/bot<secret>/getUpdates`.

## Basic

HTTP Basic auth (`username:password`).

**Example providers:** Twilio, Mailgun

The secret value should be `username:password`. The broker base64-encodes it and injects `Authorization: Basic <encoded>`.

```bash
aivault credential create my-twilio \
  --provider twilio \
  --secret-ref vault:secret:<id> \
  --auth basic
```

## Multi-header

Multiple HTTP headers from a JSON secret. Each header has its own template that references fields in the secret JSON.

**Example providers:** Datadog (`DD-API-KEY` + `DD-APPLICATION-KEY`)

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

The secret value is a JSON object: `{"api_key": "...", "app_key": "..."}`.

## Multi-query

Multiple query parameters from a JSON secret.

**Example providers:** Trello (`key` + `token`)

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

The secret value is a JSON object: `{"api_key": "...", "token": "..."}`.

## OAuth2

Client credentials or refresh token grant. The broker automatically refreshes expired access tokens.

**Example providers:** Spotify, QuickBooks, Xero, Reddit

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

The secret value is a JSON object: `{"clientId": "...", "clientSecret": "...", "refreshToken": "..."}`.

On each request, the broker:
1. Checks if the cached access token is expired
2. If expired, sends a refresh request to the token endpoint
3. Writes the new tokens back to the vault
4. Injects `Authorization: Bearer <access_token>` into the request

See [OAuth setup](/cli/oauth) for the initial consent/exchange flow.

## AWS SigV4

AWS Signature Version 4 request signing.

**Example providers:** AWS S3, Bedrock

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

The secret value is a JSON object: `{"access_key_id": "...", "secret_access_key": "..."}`.

## HMAC

HMAC signature of the request body, placed in a header.

**Use case:** Webhook verification

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

## mTLS

Mutual TLS client certificate authentication.

**Use case:** Enterprise APIs

The secret value contains the client certificate and key (PEM-encoded). The broker uses them to establish a mutual TLS connection.

## Specifying auth for custom credentials

For registry-backed providers, auth is automatic. For custom providers, specify the strategy when creating a credential:

```bash
# Header auth
aivault credential create my-api \
  --provider my-api \
  --secret-ref vault:secret:<id> \
  --auth header \
  --header-name authorization \
  --value-template "Bearer {{secret}}" \
  --host api.example.com

# Query auth
aivault credential create my-api \
  --provider my-api \
  --secret-ref vault:secret:<id> \
  --auth query \
  --query-param api_key \
  --host api.example.com

# Multi-header auth
aivault credential create my-api \
  --provider my-api \
  --secret-ref vault:secret:<id> \
  --auth multi-header \
  --auth-header "X-API-Key={{api_key}}" \
  --auth-header "X-App-ID={{app_id}}" \
  --host api.example.com
```

Next: [Scopes and isolation](/core/scopes-and-isolation)
