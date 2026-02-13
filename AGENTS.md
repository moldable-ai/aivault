# aivault Development Guidelines

## Project Overview

aivault is a local encrypted vault runtime and CLI for secret lifecycle and capability-to-secret binding workflows.

See `README.md` for CLI usage and quality checks.

## User-Story-Driven Development (Required)

Treat `prds/user-stories/how-to.md` as the required workflow for behavior work, audits, and completion checks.

When implementing or verifying behavior:

1. Identify the affected domain file in `prds/user-stories/*.json` and the relevant story slug(s).
2. If a needed story is missing, add it before claiming implementation coverage.
3. Perform the deep logical trace defined in `prds/user-stories/how-to.md` (entry point -> runtime/adapter/orchestration -> side effect -> user-visible response).
4. Update evidence links and `knownCoverageGaps` based on what is directly proven.
5. Do not mark stories fully implemented when any end-to-end link is inferred rather than proven; mark `partial` and document the gap.
6. Run `pnpm evidence` (or scoped equivalent) before finishing.
7. For human review and sanity checks, render stories with `pnpm stories`:
   - `pnpm stories` to view all domains
   - `pnpm stories -- <domain>` to view a specific domain (for example, `pnpm stories -- vault`)

## Tech Stack

- **Backend**: Rust
- **Package Manager**: pnpm (repo scripts) + cargo (build tooling)

## Development Commands

### Code Quality Checks (Required)

Run these from the repo root before finishing:

```bash
pnpm lint
pnpm check-types
pnpm test
```

### Formatting

```bash
pnpm format
```

### Story/Evidence Validation

```bash
pnpm evidence
pnpm stories
```

## General Rules

- Prefer surgical edits over rewrites.
- Keep changes minimal and aligned with existing patterns.
- Use existing scripts via `pnpm`.
- Avoid string matching or regex matching on error messages to decide retryability.

