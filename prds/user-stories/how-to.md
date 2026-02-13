# How To: User Stories And Evidence (Single JSON Per Domain)

## Before You Start

Before adding anything new:

1. Check `prds/user-stories/*.json` for an existing domain file to extend.
2. Run `pnpm evidence` to catch slug collisions and bad evidence links before editing.
3. Keep `.md` files as narrative companions; JSON is the source of truth.

If the domain already exists, update that file instead of creating a duplicate domain file.

## Canonical File

- Single canonical file per domain: `prds/user-stories/<domain>.json`

Each domain JSON includes:

- sections and user stories
- evidence catalog entries (`evidence[]`)
- per-story evidence links (`evidenceLinks[]`)
- optional `knownCoverageGaps`

## Domain JSON Format

```json
{
  "schemaVersion": 2,
  "domain": "<domain>",
  "title": "<Domain Title>",
  "evidence": [
    {
      "id": "ev-<name>",
      "kind": "tests",
      "automated": true,
      "file": "src/path/file.rs",
      "tests": ["test_name"]
    }
  ],
  "sections": [
    {
      "id": "<section-id>",
      "group": "<Group Label>",
      "title": "<Section Title>",
      "stories": [
        {
          "slug": "<prefix>-<slug>",
          "story": "As a ..., I want ..., so ...",
          "evidenceLinks": ["ev-<name>"]
        }
      ]
    }
  ]
}
```

## Computed Status Rules

`pnpm evidence` computes status per story from the JSON content:

- `missing`: `evidenceLinks` is empty
  - requires non-empty `gapReason`
- `partial`: either story has `partial: true` **or** its slug appears in `knownCoverageGaps[].storySlugs`
  - requires non-empty `gapReason` **or** a `knownCoverageGaps` description for that story
  - should still include evidence links for implemented parts
- `implemented_tested`: has at least one linked evidence item where `automated: true`
- `implemented_untested`: has evidence links, but none of them are `automated: true`

No manual status overrides are allowed.

## Coverage Gap Tracking (Required)

Structural evidence links are not enough by themselves. If a story's linked tests do not directly assert the story's user-visible behavior, record that gap explicitly.

Use `knownCoverageGaps[]` for this:

```json
{
  "knownCoverageGaps": [
    {
      "description": "What is not definitively proven yet",
      "storySlugs": ["group-example-story"],
      "references": ["src/path/file.rs", "test_name_or_symbol"]
    }
  ]
}
```

Rules:

- `description` explains what proof is missing.
- `storySlugs` lists the affected stories in the same domain file.
- `references` points to relevant code/tests/symbols for follow-up.
- Stories referenced by `storySlugs` are computed as `partial` automatically.
- Keep story-level `missing` status explicit (`gapReason` required by validator).

When auditing, ask per story:

1. Does at least one linked automated test assert the behavior directly?
2. If no, is this `partial` (some behavior verified) or `missing` (no verifiable evidence)?
3. Record residual uncertainty in `knownCoverageGaps`.

## Deep Logical Trace (Required)

Evidence links and test names are not sufficient on their own. For each story marked implemented, do a deep logical trace through the real execution path and confirm that the behavior is wired end to end.

Minimum trace checklist per story:

1. Identify the user entry points (HTTP route, websocket event, channel message, CLI/runtime trigger, or UI action).
2. Trace the exact code path through orchestrator/group/tool/runtime layers to the final side effect.
3. Verify guards and approvals along that path (auth, permission checks, routing constraints, gating logic).
4. Confirm persistence and state transitions (write path, read path, and follow-up behavior).
5. Confirm the response/notification path back to the user-facing surface.
6. Cross-check tests against the traced path and record any unproven link as a `knownCoverageGaps` entry.

If any step in the end-to-end chain is inferred but not proven by code or tests, do not mark the story fully implemented; mark it `partial` and document the uncertainty.

## Authoring Rules

- `domain` must match filename (`groups` -> `groups.json`).
- Every story slug must be unique across all domain JSON files.
- Every `evidenceLinks` entry must point to an existing `evidence[].id`.
- Every evidence item must include `id`, `automated`, and either `file` or `files`.
- Use stable slug prefixes (for example `appr-`, `group-`, `ws-`).

## Validation

Run:

```bash
pnpm evidence
```

Validate a single domain:

```bash
pnpm evidence -- groups
```

Validate a single file path:

```bash
pnpm evidence -- prds/user-stories/groups.json
```

Show story-level and known gap details:

```bash
pnpm evidence -- groups --gaps
```

This validates:

- cross-domain slug duplication
- duplicate/invalid evidence IDs
- broken evidence links
- missing `gapReason` for `missing`/`partial` stories
- malformed `knownCoverageGaps` entries (including unknown story slugs)

## Reference Example

- `prds/user-stories/approvals.json`
