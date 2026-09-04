---
title: OAuth
description: Set up OAuth2 consent flows for providers like Spotify, QuickBooks, and Xero.
---

For providers that use OAuth2 (Spotify, QuickBooks, Xero, Reddit, etc.), the initial consent and code exchange happen **outside** the broker boundary. aivault only handles the refresh/runtime phase.

## oauth setup

Generate a consent URL for an OAuth2 provider.

```bash
aivault oauth setup \
  --provider google \
  --auth-url https://accounts.google.com/o/oauth2/v2/auth \
  --client-id <client-id> \
  --redirect-uri http://127.0.0.1:8787/callback \
  --scope gmail.readonly
```

This returns a consent URL — open it in a browser to authorize the application.

### Options

| Flag | Description |
|------|-------------|
| `--provider` | Provider name |
| `--auth-url` | OAuth2 authorization endpoint |
| `--client-id` | Application client ID |
| `--redirect-uri` | Redirect URI for the callback |
| `--scope` | OAuth2 scopes (repeatable) |
| `--state` | Optional state parameter for CSRF protection |

## Full OAuth2 lifecycle

```
1. Generate consent URL
   ┌─────────────────────────────────────────────┐
   │ aivault oauth setup --provider google \      │
   │   --auth-url https://accounts.google.com/... │
   │   --client-id <id> --redirect-uri <uri>      │
   │                                               │
   │ → Returns consentUrl — open in browser        │
   └─────────────────────────────────────────────┘

2. Exchange auth code for tokens (outside aivault)
   ┌─────────────────────────────────────────────┐
   │ Use your own runtime or curl to exchange     │
   │ the auth code for access + refresh tokens.   │
   └─────────────────────────────────────────────┘

3. Store tokens in vault
   ┌─────────────────────────────────────────────┐
   │ aivault secrets create --name SPOTIFY_OAUTH \ │
   │   --value '{"clientId":"...","clientSecret":  │
   │            "...","refreshToken":"..."}'        │
   │                                               │
   │ → Credential auto-provisioned: spotify        │
   └─────────────────────────────────────────────┘

4. Invoke (automatic token refresh)
   ┌─────────────────────────────────────────────┐
   │ aivault invoke spotify/playlists ...         │
   │                                               │
   │ Broker automatically:                         │
   │ → Checks if access_token is expired           │
   │ → Refreshes via token endpoint if needed      │
   │ → Writes new tokens back to vault             │
   │ → Injects Bearer token into request           │
   └─────────────────────────────────────────────┘
```

The key insight: aivault manages the **runtime token refresh** automatically. You only need to do the initial consent/exchange once. After that, the broker handles refreshing expired tokens transparently on every invoke.

For public/native OAuth clients that use PKCE, omit `clientSecret` from the secret JSON:

```bash
aivault secrets create --name GOOGLE_GMAIL_OAUTH \
  --value-file /path/to/oauth-secret.json \
  --scope workspace --workspace-id personal
```

`--value-file` is preferred for token payloads because the secret value does not appear in the process argument list.

## ChatGPT account refresh and recovery

For `CODEX_OAUTH_JSON`, aivault refreshes only the account selected for the
requested capability. An unusable ChatGPT account does not prevent another
account, API key, or unrelated provider from making requests. Listing credentials
does not refresh tokens; a listed account may still need to reconnect.

The native access lease and broker share a per-account process lock, reread the
stored token after acquiring it, and persist rotated tokens before returning.
Secret-record updates also use a process lock so usage timestamps cannot overwrite
new credentials. A reconnect completed during refresh takes precedence over the
older refresh result.

An upstream API 401 triggers one refresh and one retry, including streamed calls.
Permanent token failures (`refresh_token_expired`, `refresh_token_reused`,
`refresh_token_invalidated`, `invalid_refresh_token`, `invalid_grant`, or an
unclassified token-endpoint 401) report a safe code and ask you to reconnect that
account. The failure is cached in its encrypted credential until reconnection
replaces it. Temporary failures remain retryable. Raw token error bodies are
never included in these diagnostics.

In Moldable, reconnect the affected account from the ChatGPT provider settings.
Reconnecting replaces its tokens and clears the cached refresh failure.

Next: [Security](/security)
