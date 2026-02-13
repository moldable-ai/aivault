---
title: Invoke
description: Execute proxied requests through capability policy.
---

The `invoke` command is the primary way to make authenticated API calls through aivault. The broker validates the request, injects auth, and returns the response — the caller never sees the secret.

## invoke

Execute a proxied request and print the raw upstream response.

```bash
aivault invoke <capability-id> [options]
```

This is a top-level shortcut for `aivault capability invoke`.

### Examples

```bash
# JSON body
aivault invoke openai/chat-completions \
  --body '{"model":"gpt-5.2","messages":[{"role":"user","content":"hello"}]}'

# Multipart (file upload)
aivault invoke openai/transcription \
  --multipart-field model=whisper-1 \
  --multipart-file file=/tmp/audio.wav

# Custom method and path
aivault invoke github/repos \
  --method GET \
  --path /repos/owner/repo

# With specific credential
aivault invoke openai/chat-completions \
  --credential my-openai-staging \
  --body '...'

# With workspace/group context
aivault invoke openai/chat-completions \
  --workspace-id my-workspace \
  --group-id my-group \
  --body '...'

# From a request file
aivault invoke openai/chat-completions \
  --request-file /tmp/request.json

# Body from file
aivault invoke openai/chat-completions \
  --body-file-path /tmp/body.json

# Additional headers
aivault invoke openai/chat-completions \
  --header "X-Custom: value" \
  --body '...'
```

## json

Invoke and print the response as parsed JSON.

```bash
aivault json openai/chat-completions \
  --body '{"model":"gpt-5.2","messages":[{"role":"user","content":"hello"}]}'
```

Same as `aivault capability json`.

## markdown

Invoke and print the response converted to markdown. Useful for LLM-friendly output.

```bash
aivault markdown openai/chat-completions \
  --body '{"model":"gpt-5.2","messages":[{"role":"user","content":"hello"}]}'

# With namespace wrapping
aivault markdown openai/chat-completions \
  --namespace data \
  --body '...'
# → <begin data> ... </end data>

# Exclude fields from output
aivault markdown openai/chat-completions \
  --exclude-field usage \
  --body '...'

# Wrap fields containing markdown
aivault markdown openai/chat-completions \
  --wrap-field content \
  --body '...'
```

Alias: `md`

## Invoke options

| Flag | Description |
|------|-------------|
| `--method` | HTTP method (defaults to capability's first allowed method) |
| `--path` | Request path (defaults to capability's first path prefix) |
| `--header` | Additional request header (repeatable) |
| `--body` | Request body (JSON string) |
| `--body-file-path` | Read request body from file |
| `--request` | Full request envelope as JSON |
| `--request-file` | Read full request envelope from file |
| `--multipart-field` | Multipart form field as `name=value` (repeatable) |
| `--multipart-file` | Multipart form file as `name=/path/to/file` (repeatable) |
| `--credential` | Specific credential to use (overrides default resolution) |
| `--workspace-id` | Workspace context for credential resolution |
| `--group-id` | Group context for credential resolution |
| `--client-ip` | Client IP for audit context (default: `127.0.0.1`) |

## Response handling

- **Raw mode** (`invoke`): prints the response body as-is
- **JSON mode** (`json`): parses and pretty-prints as JSON
- **Markdown mode** (`markdown`): converts JSON response to markdown with optional namespace wrapping, field exclusion, and field wrapping

In all modes, upstream response headers are intentionally stripped. In untrusted execution environments, headers can carry identifiers or cookies that leak through agent context.

Next: [OAuth](/cli/oauth)
