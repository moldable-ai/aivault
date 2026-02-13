---
title: Registry
description: Built-in provider definitions covering 30+ APIs.
---

aivault ships a built-in registry of provider definitions compiled into the binary. These definitions declare which secrets each provider claims, how auth works, and what capabilities are available.

## How it works

Each registry entry in `registry/*.json` defines:
- **`provider`** — unique provider name (e.g. `openai`, `stripe`)
- **`vaultSecrets`** — maps canonical secret names to auth template placeholders
- **`auth`** — the auth strategy and its configuration
- **`hosts`** — allowed upstream hosts
- **`capabilities`** — the API endpoints callers can invoke

When you run `aivault secrets create --name OPENAI_API_KEY`, the system:
1. Matches `OPENAI_API_KEY` against registry `vaultSecrets` entries
2. Finds the `openai` provider
3. **Pins** the secret to that provider (immutable)
4. **Auto-provisions** the `openai` credential with the correct auth strategy
5. **Enables** all capabilities defined in the `openai` registry entry

## Provider catalog

The exact set of registry-backed providers and capabilities is compiled from `registry/*.json` at build time and may change between releases. For the authoritative list for your installed version (including the exact capability IDs), use `aivault capability list` (or `-v` for JSON).

Providers currently in the built-in registry include:

### AI / ML
- OpenAI
- Anthropic
- Gemini
- Replicate
- OpenRouter
- ElevenLabs
- Deepgram

### Communication
- Slack
- Discord
- Twilio
- Telegram

### Productivity
- Notion
- Airtable
- Linear
- Todoist
- Calendly
- Trello

### CRM
- HubSpot
- Intercom

### Email
- Resend
- SendGrid
- Postmark
- Mailgun

### E-commerce / Payments
- Shopify
- Stripe
- Square

### Accounting
- QuickBooks
- Xero

### Social / Media
- X
- Reddit
- Spotify
- YouTube Data

### Dev tools
- GitHub

### Maps / Places
- Google Places

## Browsing the registry

```bash
# List all capabilities (grouped by readiness)
aivault capability list

# Inspect a specific capability
aivault capability describe openai/chat-completions

# Full JSON detail
aivault capability list -v
```

## Per-tenant hosts

Some providers use per-tenant hostnames (e.g. `{store}.myshopify.com`). The registry defines host patterns with wildcards. You bind your specific host when creating a credential:

```bash
aivault credential create my-shopify \
  --provider shopify \
  --secret-ref vault:secret:<id> \
  --host my-store.myshopify.com
```

The broker validates that your host matches the registry's allowed pattern.

## Extending the registry

You can add custom providers locally (see [Custom providers](/registry/custom-providers)), but registry-compiled providers offer stronger security guarantees because they cannot be tampered with at runtime.

The best defense is to contribute missing providers back to the official registry.

Next: [Auth strategies](/core/auth-strategies)
