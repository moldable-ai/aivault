# Services to Support — Registry Coverage Plan

> Survey of the most popular APIs by real-world usage, prioritized by how much
> they connect consumers and businesses to their own data in useful ways.
>
> User stories tracked in `prds/user-stories/registry-services.json`.

## Legend

| Status | Meaning |
|--------|---------|
| **done** | Registry JSON exists and has been verified |
| **todo** | HTTP API with key-based auth — good candidate for a registry entry |
| **skip** | Complex OAuth-only, self-hosted, or not a key-authed HTTP API |

---

## Already in registry (41 providers)

| Provider | File | Category | Auth |
|----------|------|----------|------|
| OpenAI | `openai.json` | AI / ML | Bearer |
| Anthropic | `anthropic.json` | AI / ML | Custom header (`x-api-key`) |
| Gemini (Google) | `gemini.json` | AI / ML | Query param (`key`) |
| OpenRouter | `openrouter.json` | AI / ML | Bearer |
| Replicate | `replicate.json` | AI / ML | Bearer (`Token` prefix) |
| ElevenLabs | `elevenlabs.json` | AI / audio | Custom header (`xi-api-key`) |
| Deepgram | `deepgram.json` | AI / audio | Bearer (dual hosts) |
| GitHub | `github.json` | Dev tools | Bearer |
| Stripe | `stripe.json` | Payments (GET-only) | Bearer |
| Twilio | `twilio.json` | Communication | Basic auth |
| Resend | `resend.json` | Email | Bearer |
| Slack | `slack.json` | Communication | Bearer |
| Discord | `discord.json` | Communication | Custom header (`Bot` prefix) |
| Notion | `notion.json` | Productivity | Bearer |
| Airtable | `airtable.json` | Productivity | Bearer |
| Linear | `linear.json` | Project mgmt | Bearer (dual hosts) |
| HubSpot | `hubspot.json` | CRM / marketing | Bearer |
| Todoist | `todoist.json` | Task mgmt | Bearer |
| Intercom | `intercom.json` | Customer comms | Bearer |
| Calendly | `calendly.json` | Scheduling | Bearer |
| SendGrid | `sendgrid.json` | Email | Bearer |
| Postmark | `postmark.json` | Email | Custom header (`X-Postmark-Server-Token`) |
| Mailgun | `mailgun.json` | Email | Basic auth |
| Shopify | `shopify.json` | E-commerce | Custom header (`X-Shopify-Access-Token`) |
| Square | `square.json` | Payments | Bearer |
| QuickBooks | `quickbooks.json` | Accounting | Bearer (OAuth2 token) |
| Xero | `xero.json` | Accounting | Bearer (OAuth2 token) |
| X | `x.json` | Social | Bearer (app-only) |
| YouTube Data | `youtube.json` | Video | Query param (`key`) |
| Spotify | `spotify.json` | Media | Bearer (OAuth2 token) |
| Telegram | `telegram.json` | Messaging | Bearer (placeholder — needs token-in-path) |
| Reddit | `reddit.json` | Social | Bearer (OAuth2 token) |
| Mistral | `mistral.json` | AI / ML | Bearer |
| Groq | `groq.json` | AI / ML | Bearer |
| Cohere | `cohere.json` | AI / ML | Bearer |
| Perplexity | `perplexity.json` | AI / search | Bearer |
| Fireworks AI | `fireworks.json` | AI / ML | Bearer |
| Together AI | `together.json` | AI / ML | Bearer |
| Hugging Face | `huggingface.json` | AI / ML | Bearer |
| Stability AI | `stability.json` | AI / image gen | Bearer |
| AssemblyAI | `assemblyai.json` | AI / transcription | Custom header (`authorization: raw key`) |

---

## All services — by tier

### Tier 1 — daily workflow (communication, productivity, CRM)

Services people and businesses live inside every day. High data gravity —
once your agent can read/write here, it's indispensable.

| Status | Service | Category | Auth type | API host | Notes |
|--------|---------|----------|-----------|----------|-------|
| done | Slack | Communication | Bearer token | `slack.com` | Messages, channels, files, reactions |
| done | Discord | Communication | Bot token (`Bot {{secret}}`) | `discord.com` | Servers, channels, messages |
| done | Notion | Productivity | Bearer token | `api.notion.com` | Pages, databases, blocks, search |
| done | Airtable | Productivity | Bearer token | `api.airtable.com` | Bases, tables, records, views |
| done | Linear | Project mgmt | Bearer token | `api.linear.app` | Issues, projects, cycles, teams |
| done | Todoist | Task mgmt | Bearer token | `api.todoist.com` | Tasks, projects, labels, comments |
| done | HubSpot | CRM / marketing | Bearer token | `api.hubapi.com` | Contacts, deals, tickets, companies |
| done | Intercom | Customer comms | Bearer token | `api.intercom.io` | Conversations, contacts, articles |
| done | Calendly | Scheduling | Bearer token | `api.calendly.com` | Events, invitees, availability |

### Tier 2 — business operations (email, e-commerce, finance)

Revenue-critical APIs — orders, invoices, payments, customer communication.

| Status | Service | Category | Auth type | API host | Notes |
|--------|---------|----------|-----------|----------|-------|
| done | SendGrid | Email | Bearer token | `api.sendgrid.com` | Send, templates, contacts, stats |
| done | Postmark | Email | API key (`X-Postmark-Server-Token`) | `api.postmarkapp.com` | Send, templates, servers, stats |
| done | Mailgun | Email | Basic auth | `api.mailgun.net` | Send, domains, routes, events |
| todo | Mailchimp | Email marketing | Basic auth (`any:apikey`) | `{dc}.api.mailchimp.com` | Campaigns, audiences, automations (dc-specific host) |
| done | Shopify | E-commerce | Header (`X-Shopify-Access-Token`) | `{store}.myshopify.com` | Orders, products, inventory, customers (store-specific host) |
| done | Square | Payments | Bearer token | `connect.squareup.com` | Payments, orders, inventory, catalog |
| done | QuickBooks | Accounting | Bearer token | `quickbooks.api.intuit.com` | Invoices, expenses, reports, customers |
| done | Xero | Accounting | Bearer token | `api.xero.com` | Invoices, contacts, bank transactions |

### Tier 3 — content, social, media

Where people publish, engage, and build audiences.

| Status | Service | Category | Auth type | API host | Notes |
|--------|---------|----------|-----------|----------|-------|
| done | X | Social | Bearer token (app-only) | `api.x.com` | Tweets, users, search, lists |
| done | Reddit | Social | OAuth Bearer | `oauth.reddit.com` | Posts, comments, subreddits |
| done | Spotify | Media | OAuth client creds | `api.spotify.com` | Playlists, tracks, artists, playback |
| done | YouTube Data | Video | API key (query param) | `www.googleapis.com` | Videos, channels, playlists, search |
| done | Telegram Bot | Messaging | Token in URL path | `api.telegram.org` | Messages, updates, inline queries |

### Tier 4 — monitoring, analytics, support

How businesses understand what's happening and help their customers.

| Status | Service | Category | Auth type | API host | Notes |
|--------|---------|----------|-----------|----------|-------|
| todo | Sentry | Error tracking | Bearer token | `sentry.io` | Issues, events, releases, projects |
| todo | Datadog | Monitoring | API key + app key (headers) | `api.datadoghq.com` | Metrics, events, dashboards, logs |
| todo | Mixpanel | Product analytics | Bearer token | `mixpanel.com` | Events, funnels, retention, users |
| todo | PostHog | Product analytics | API key (header) | `app.posthog.com` | Events, persons, feature flags |
| todo | Zendesk | Support | Bearer token | `{subdomain}.zendesk.com` | Tickets, users, orgs (subdomain-specific) |
| todo | Freshdesk | Support | Basic auth (API key as user) | `{domain}.freshdesk.com` | Tickets, contacts, agents (domain-specific) |

### Tier 5 — infrastructure & dev tools

Important but more developer-facing than consumer/business-facing.

| Status | Service | Category | Auth type | API host | Notes |
|--------|---------|----------|-----------|----------|-------|
| todo | Cloudflare | Infrastructure | Bearer token | `api.cloudflare.com` | DNS, Workers, R2, zones |
| todo | Vercel | Hosting | Bearer token | `api.vercel.com` | Deployments, domains, env vars, projects |
| todo | Netlify | Hosting | Bearer token | `api.netlify.com` | Sites, deploys, forms, DNS |
| todo | GitLab | Dev tools | Header (`PRIVATE-TOKEN`) | `gitlab.com` | Repos, pipelines, issues, MRs |
| todo | Jira / Atlassian | Dev tools | Basic auth (email + token) | `{site}.atlassian.net` | Issues, projects, boards (site-specific) |
| todo | Supabase | BaaS | API key (header `apikey`) | `{project}.supabase.co` | DB, auth, storage (project-specific) |
| todo | Pinecone | Vector DB | API key (`Api-Key` header) | `{index}.pinecone.io` | Vectors, indexes, collections |
| todo | Algolia | Search | API key (`X-Algolia-API-Key`) | `{app}.algolia.net` | Search, indexing, rules |

### Tier 6 — AI providers (infrastructure)

These are the pipes, not the product. Important but low urgency since most
agents already know how to call them directly.

| Status | Service | Category | Auth type | API host |
|--------|---------|----------|-----------|----------|
| done | Mistral | AI / ML | Bearer token | `api.mistral.ai` |
| done | Groq | AI / ML | Bearer token | `api.groq.com` |
| done | Cohere | AI / ML | Bearer token | `api.cohere.com` |
| done | Perplexity | AI / search | Bearer token | `api.perplexity.ai` |
| done | Fireworks AI | AI / ML | Bearer token | `api.fireworks.ai` |
| done | Together AI | AI / ML | Bearer token | `api.together.xyz` |
| done | Hugging Face | AI / ML | Bearer token | `api-inference.huggingface.co` |
| done | Stability AI | AI / image gen | Bearer token | `api.stability.ai` |
| done | AssemblyAI | AI / transcription | Bearer token | `api.assemblyai.com` |

---

## Not applicable for registry (skip)

| Service | Reason |
|---------|--------|
| AWS | Signature V4 — not simple key auth |
| Google Cloud / GCP | Service account JSON → JWT → access token |
| Azure (general) | Complex multi-flow auth |
| Salesforce | Complex OAuth + instance-specific host |
| Facebook / Instagram (Meta) | Complex OAuth only |
| LinkedIn | Complex OAuth only |
| Kubernetes, Terraform, Ansible | File-based auth, not HTTP API key |
| Docker | Unix socket / TCP |
| Databases (PG, Redis, Mongo, etc.) | Connection strings / non-HTTP |
| Self-hosted (Jenkins, Prometheus, Home Assistant, Plex, Hue) | Host is user-defined |
| Midjourney | No public API |

---

## Recommended implementation order

### Wave 1 — communication & productivity ✅

1. **Slack** — Bearer, `slack.com`
2. **Discord** — `Bot {{secret}}`, `discord.com`
3. **Notion** — Bearer, `api.notion.com`
4. **Airtable** — Bearer, `api.airtable.com`
5. **Linear** — Bearer, `api.linear.app`
6. **HubSpot** — Bearer, `api.hubapi.com`
7. **Todoist** — Bearer, `api.todoist.com`
8. **Intercom** — Bearer, `api.intercom.io`
9. **Calendly** — Bearer, `api.calendly.com`

### Wave 2 — email & e-commerce (mostly ✅, Mailchimp remaining)

10. **SendGrid** — Bearer, `api.sendgrid.com`
11. **Postmark** — `X-Postmark-Server-Token`, `api.postmarkapp.com`
12. **Mailgun** — Basic auth, `api.mailgun.net`
13. **Mailchimp** — Basic auth, `{dc}.api.mailchimp.com` (needs per-tenant host)
14. **Shopify** — `X-Shopify-Access-Token`, `{store}.myshopify.com`
15. **Square** — Bearer, `connect.squareup.com`
16. **QuickBooks** — Bearer, `quickbooks.api.intuit.com`
17. **Xero** — Bearer, `api.xero.com`

### Wave 3 — content & social (mostly ✅, Reddit + Cloudinary remaining)

18. **X** — Bearer (app-only), `api.x.com`
19. **Telegram** — token-in-URL-path, `api.telegram.org`
20. **Spotify** — OAuth client creds, `api.spotify.com`
21. **YouTube Data** — API key query param, `www.googleapis.com`
22. **Reddit** — OAuth Bearer, `oauth.reddit.com`

### Wave 4 — monitoring, analytics, support

23. **Sentry** — Bearer, `sentry.io`
24. **PostHog** — API key header, `app.posthog.com`
25. **Datadog** — dual key headers, `api.datadoghq.com`
26. **Zendesk** — Bearer, `{subdomain}.zendesk.com` (needs per-tenant host)

### Wave 5 — infra & dev tools

27. **Cloudflare** — Bearer, `api.cloudflare.com`
28. **Vercel** — Bearer, `api.vercel.com`
29. **GitLab** — `PRIVATE-TOKEN`, `gitlab.com`
30. **Jira / Atlassian** — Basic, `{site}.atlassian.net` (needs per-tenant host)
31. **Supabase** — `apikey` header, `{project}.supabase.co` (needs per-tenant host)

### Wave 6 — AI providers ✅

32-40. Mistral, Groq, Cohere, Perplexity, Fireworks, Together, HuggingFace,
       Stability, AssemblyAI — all Bearer token, batch-added.

---

## Notes on tricky auth patterns

- **Telegram**: Token is part of the URL path (`/bot{token}/sendMessage`), not a
  header. Registry exists with Bearer placeholder; needs token-in-path auth strategy.
- **Shopify / Jira / Zendesk / Mailchimp / Supabase**: Host varies per user
  (store, site, subdomain, project). Registry defines the pattern; user configures
  their specific host at secret-binding time.
- **Datadog / Algolia / Plaid**: Two separate credential values in different
  headers. Needs vault support for multi-field secrets.
- **Spotify / QuickBooks / Xero**: OAuth2 token exchange flow. Registry stores
  Bearer auth for the pre-obtained access token; users handle the OAuth flow externally.
- **Discord**: Bot token uses `Bot {{secret}}` prefix (not `Bearer`). Already
  handled — `value_template` supports this.
- **YouTube Data / Mapbox**: API key as query parameter, same as Gemini. Already
  supported by the `query` auth strategy.
- **Mailchimp**: Datacenter-specific host (`us1.api.mailchimp.com`, etc.).
  Extractable from the API key itself (last 3 chars after the dash).
