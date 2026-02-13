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

Next: [Security](/security)
