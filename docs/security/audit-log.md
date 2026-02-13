---
title: Audit log
description: Append-only event log for compliance and forensics.
---

aivault maintains an append-only audit log that records every secret lifecycle event and proxied invocation. The log is designed for compliance, forensics, and anomaly detection.

## What gets logged

| Event type | Trigger |
|------------|---------|
| Secret created | `aivault secrets create` |
| Secret rotated | `aivault secrets rotate` |
| Secret deleted | `aivault secrets delete` |
| Secret pinned | Auto-pin to registry provider |
| Group attached | `aivault secrets attach-group` |
| Group detached | `aivault secrets detach-group` |
| Capability invoked | `aivault invoke`, `json`, `markdown` |
| Master key rotated | `aivault rotate-master` |

## Viewing the log

```bash
# Last 200 events (default)
aivault audit

# Last 50 events
aivault audit --limit 50

# Events before a specific timestamp
aivault audit --before-ts-ms 1700000000000
```

## Storage

Audit events are stored as newline-delimited JSON (JSONL) files in the vault directory:

```
~/.aivault/data/vault/audit/*.jsonl
```

Each event includes:
- Timestamp (milliseconds since epoch)
- Event type
- Relevant IDs (secret, credential, capability)
- Execution context (workspace, group, client IP)

## Disabling disk logs

For environments where audit logs should not be written to disk (e.g. ephemeral containers), set:

```bash
export AIVAULT_DISABLE_DISK_LOGS=1
```

This suppresses all disk-based audit logging. Events are still processed in-memory for rate limiting and policy enforcement.

## Using audit logs

**Compliance**: the audit log provides a complete record of who accessed what and when, suitable for SOC 2, HIPAA, and similar compliance frameworks.

**Forensics**: if a secret is suspected of being misused, the audit log shows every invocation that used it, including the capability, client IP, and workspace context.

**Anomaly detection**: monitor for unusual patterns — spikes in invocation frequency, requests from unexpected workspace contexts, or capabilities that shouldn't be active.

Next: [Registry](/registry)
