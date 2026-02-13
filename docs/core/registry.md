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
- **OpenAI** — chat completions, transcription, translation, embeddings, images, TTS, fine-tuning, files, assistants, vector stores, batches, moderations, models, responses
- **Anthropic** — messages, models
- **Gemini** — generate content, models
- **Replicate** — predictions, deployments, models
- **OpenRouter** — chat completions, models
- **ElevenLabs** — text-to-speech, voices, models, sound effects
- **Deepgram** — transcription, models

### Communication
- **Slack** — messages, channels, users, files, reactions, conversations, views, reminders, bookmarks, pins, search, team info, bots, auth test, user groups
- **Discord** — channels, messages, guilds, users, interactions, webhooks
- **Twilio** — messages, calls, accounts
- **Telegram** — messages, updates, webhooks, chat management, stickers, files, bot info

### Productivity
- **Notion** — pages, databases, blocks, search, users, comments
- **Airtable** — records, tables, bases
- **Linear** — GraphQL API
- **Todoist** — tasks, projects, sections, comments, labels
- **Calendly** — events, event types, users, invitees, webhooks
- **Trello** — boards, lists, cards, members, checklists, labels, actions, search, organizations, custom fields, plugins, tokens, notifications, webhooks, batch, types, enterprise

### CRM
- **HubSpot** — contacts, companies, deals, engagements, pipelines
- **Intercom** — contacts, conversations, admins, tags, segments, events

### Email
- **Resend** — send email, domains, API keys, audiences, contacts, broadcasts
- **SendGrid** — send mail, contacts, lists, templates
- **Postmark** — send email, templates, servers, message streams, domains, webhooks
- **Mailgun** — send messages, domains, routes, events, webhooks

### E-commerce / Payments
- **Shopify** — products, orders, customers, inventory
- **Stripe** — charges, customers, subscriptions, payment intents
- **Square** — payments, orders, customers, catalog

### Accounting
- **QuickBooks** — query, invoices, customers, accounts
- **Xero** — invoices, contacts, accounts, bank transactions

### Social / Media
- **X** — tweets, users, search, lists, spaces
- **Reddit** — subreddits, posts, comments, user info, search, me
- **Spotify** — playlists, tracks, search, albums, artists, player
- **YouTube Data** — search, videos, channels, playlists, subscriptions

### Dev tools
- **GitHub** — repos, issues, pull requests, actions, users, search, gists, orgs, git

### Maps / Places
- **Google Places** — place search, details, photos, autocomplete

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
