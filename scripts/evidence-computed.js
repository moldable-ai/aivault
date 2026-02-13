#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const STORIES_DIR = path.join(ROOT, "prds", "user-stories");
const STATUS_ORDER = [
  "implemented_tested",
  "implemented_untested",
  "partial",
  "missing",
];
const TRACE_PROOF_LEVELS = new Set(["unit", "runtime", "e2e"]);

function readJson(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

function listJsonFiles(dirPath) {
  return fs
    .readdirSync(dirPath)
    .filter((name) => name.endsWith(".json"))
    .filter((name) => name !== "how-to.json")
    .map((name) => path.join(dirPath, name))
    .sort();
}

function resolveTargetToFile(target) {
  const asPath = path.isAbsolute(target) ? target : path.resolve(ROOT, target);
  if (fs.existsSync(asPath) && fs.statSync(asPath).isFile()) {
    return asPath;
  }
  const asDomainFile = path.join(STORIES_DIR, `${target}.json`);
  if (fs.existsSync(asDomainFile) && fs.statSync(asDomainFile).isFile()) {
    return asDomainFile;
  }
  return null;
}

function collectStoryFiles(targets, errors) {
  if (targets.length === 0) {
    return listJsonFiles(STORIES_DIR);
  }

  const resolved = new Set();
  for (const target of targets) {
    const filePath = resolveTargetToFile(target);
    if (!filePath) {
      addError(
        errors,
        `Target "${target}" not found. Pass domain (e.g. "teams") or path to a domain JSON file.`,
      );
      continue;
    }
    const normalized = path.resolve(filePath);
    if (!normalized.startsWith(STORIES_DIR + path.sep)) {
      addError(errors, `Target "${target}" must be under prds/user-stories/.`);
      continue;
    }
    if (path.basename(normalized) === "how-to.json") {
      addError(errors, `Target "${target}" is not a domain stories file.`);
      continue;
    }
    if (!normalized.endsWith(".json")) {
      addError(
        errors,
        `Target "${target}" must be a .json file or a domain name.`,
      );
      continue;
    }
    resolved.add(normalized);
  }

  return Array.from(resolved).sort();
}

function addError(errors, message) {
  errors.push(message);
}

function hasNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function hasEvidenceFileReference(evidence) {
  const hasFile = hasNonEmptyString(evidence.file);
  const hasFiles =
    Array.isArray(evidence.files) &&
    evidence.files.length > 0 &&
    evidence.files.every((entry) => hasNonEmptyString(entry));
  return hasFile || hasFiles;
}

function resolveRepoFile(filePath, relPath, errors, context) {
  if (!hasNonEmptyString(filePath)) {
    addError(errors, `${relPath}: ${context} must include non-empty "file".`);
    return null;
  }
  const absolutePath = path.isAbsolute(filePath)
    ? filePath
    : path.resolve(ROOT, filePath);
  if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) {
    addError(
      errors,
      `${relPath}: ${context} file does not exist: "${filePath}".`,
    );
    return null;
  }
  return absolutePath;
}

function readFileCached(filePath, fileContentCache) {
  if (fileContentCache.has(filePath)) {
    return fileContentCache.get(filePath);
  }
  const content = fs.readFileSync(filePath, "utf8");
  fileContentCache.set(filePath, content);
  return content;
}

function symbolExistsInContent(content, symbol) {
  if (content.includes(symbol)) {
    return true;
  }
  const shortSymbol = symbol.includes("::") ? symbol.split("::").pop() : symbol;
  if (!hasNonEmptyString(shortSymbol)) {
    return false;
  }
  const probes = [
    `fn ${shortSymbol}(`,
    `pub fn ${shortSymbol}(`,
    `${shortSymbol}(`,
  ];
  return probes.some((probe) => content.includes(probe));
}

function validateTraceRefArray({
  relPath,
  story,
  errors,
  field,
  required,
  fileContentCache,
}) {
  const refs = story.trace[field];
  if (!Array.isArray(refs)) {
    addError(
      errors,
      `${relPath}: story "${story.slug}" trace.${field} must be an array.`,
    );
    return;
  }
  if (required && refs.length === 0) {
    addError(
      errors,
      `${relPath}: story "${story.slug}" trace.${field} must be non-empty.`,
    );
    return;
  }

  for (const [index, ref] of refs.entries()) {
    if (!ref || typeof ref !== "object") {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.${field}[${index}] must be an object.`,
      );
      continue;
    }
    if (!hasNonEmptyString(ref.file) || !hasNonEmptyString(ref.symbol)) {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.${field}[${index}] must include non-empty file and symbol.`,
      );
      continue;
    }
    const absolutePath = resolveRepoFile(
      ref.file,
      relPath,
      errors,
      `story "${story.slug}" trace.${field}[${index}]`,
    );
    if (!absolutePath) {
      continue;
    }
    const content = readFileCached(absolutePath, fileContentCache);
    if (!symbolExistsInContent(content, ref.symbol)) {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.${field}[${index}] symbol "${ref.symbol}" not found in "${ref.file}".`,
      );
    }
  }
}

function validateStoryTrace({
  relPath,
  story,
  evidenceById,
  errors,
  fileContentCache,
}) {
  if (!story.trace || typeof story.trace !== "object") {
    addError(errors, `${relPath}: story "${story.slug}" must include trace object.`);
    return;
  }
  if (!TRACE_PROOF_LEVELS.has(story.trace.proofLevel)) {
    addError(
      errors,
      `${relPath}: story "${story.slug}" trace.proofLevel must be one of ${Array.from(TRACE_PROOF_LEVELS).join(", ")}.`,
    );
  }

  validateTraceRefArray({
    relPath,
    story,
    errors,
    field: "entrypoints",
    required: true,
    fileContentCache,
  });
  validateTraceRefArray({
    relPath,
    story,
    errors,
    field: "runtime",
    required: true,
    fileContentCache,
  });
  validateTraceRefArray({
    relPath,
    story,
    errors,
    field: "guards",
    required: false,
    fileContentCache,
  });
  validateTraceRefArray({
    relPath,
    story,
    errors,
    field: "stateEffects",
    required: false,
    fileContentCache,
  });
  validateTraceRefArray({
    relPath,
    story,
    errors,
    field: "userSurface",
    required: true,
    fileContentCache,
  });

  if (!Array.isArray(story.trace.assertions) || story.trace.assertions.length === 0) {
    addError(
      errors,
      `${relPath}: story "${story.slug}" trace.assertions must be a non-empty array.`,
    );
    return;
  }

  for (const [index, assertion] of story.trace.assertions.entries()) {
    if (!assertion || typeof assertion !== "object") {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.assertions[${index}] must be an object.`,
      );
      continue;
    }
    if (
      !hasNonEmptyString(assertion.evidenceId) ||
      !hasNonEmptyString(assertion.test)
    ) {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.assertions[${index}] must include non-empty evidenceId and test.`,
      );
      continue;
    }
    if (!story.evidenceLinks.includes(assertion.evidenceId)) {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.assertions[${index}] evidenceId "${assertion.evidenceId}" is not in evidenceLinks.`,
      );
      continue;
    }

    const evidence = evidenceById.get(assertion.evidenceId);
    if (!evidence) {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.assertions[${index}] references unknown evidence "${assertion.evidenceId}".`,
      );
      continue;
    }
    if (evidence.automated !== true || !Array.isArray(evidence.tests)) {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.assertions[${index}] evidence "${assertion.evidenceId}" must be automated with tests.`,
      );
      continue;
    }
    if (!evidence.tests.includes(assertion.test)) {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.assertions[${index}] test "${assertion.test}" not found in evidence "${assertion.evidenceId}".`,
      );
      continue;
    }

    const files = [];
    if (hasNonEmptyString(evidence.file)) {
      files.push(evidence.file);
    }
    if (Array.isArray(evidence.files)) {
      for (const file of evidence.files) {
        if (hasNonEmptyString(file)) {
          files.push(file);
        }
      }
    }
    let found = false;
    for (const file of files) {
      const absolutePath = resolveRepoFile(
        file,
        relPath,
        errors,
        `story "${story.slug}" trace.assertions[${index}]`,
      );
      if (!absolutePath) {
        continue;
      }
      const content = readFileCached(absolutePath, fileContentCache);
      if (symbolExistsInContent(content, assertion.test)) {
        found = true;
        break;
      }
    }
    if (!found) {
      addError(
        errors,
        `${relPath}: story "${story.slug}" trace.assertions[${index}] test symbol "${assertion.test}" not found in evidence files.`,
      );
    }
  }
}

function computeStoryStatus(story, evidenceById, knownGapReasonsByStory) {
  if (story.partial === true) {
    return "partial";
  }
  if (story.evidenceLinks.length === 0) {
    return "missing";
  }
  if (knownGapReasonsByStory.has(story.slug)) {
    return "partial";
  }
  const hasAutomatedEvidence = story.evidenceLinks.some((id) => {
    const evidence = evidenceById.get(id);
    return Boolean(evidence && evidence.automated === true);
  });
  return hasAutomatedEvidence ? "implemented_tested" : "implemented_untested";
}

function validateDocument(doc, relPath, errors, globalSlugOwner, fileContentCache) {
  if (!doc || typeof doc !== "object") {
    addError(errors, `${relPath}: root must be an object.`);
    return null;
  }
  if (!hasNonEmptyString(doc.domain)) {
    addError(errors, `${relPath}: missing non-empty "domain" string.`);
    return null;
  }
  if (doc.schemaVersion !== 2) {
    addError(errors, `${relPath}: schemaVersion must be 2.`);
    return null;
  }
  if (!Array.isArray(doc.evidence)) {
    addError(errors, `${relPath}: "evidence" must be an array.`);
    return null;
  }
  if (!Array.isArray(doc.sections)) {
    addError(errors, `${relPath}: "sections" must be an array.`);
    return null;
  }

  const evidenceById = new Map();
  for (const [index, evidence] of doc.evidence.entries()) {
    if (!evidence || typeof evidence !== "object") {
      addError(errors, `${relPath}: evidence[${index}] must be an object.`);
      continue;
    }
    if (!hasNonEmptyString(evidence.id)) {
      addError(
        errors,
        `${relPath}: evidence[${index}] must include non-empty "id".`,
      );
      continue;
    }
    if (evidenceById.has(evidence.id)) {
      addError(errors, `${relPath}: duplicate evidence id "${evidence.id}".`);
      continue;
    }
    if (!hasEvidenceFileReference(evidence)) {
      addError(
        errors,
        `${relPath}: evidence "${evidence.id}" must include "file" or non-empty "files".`,
      );
    }
    if (typeof evidence.automated !== "boolean") {
      addError(
        errors,
        `${relPath}: evidence "${evidence.id}" must include boolean "automated".`,
      );
    }
    evidenceById.set(evidence.id, evidence);
  }

  const stories = [];
  const localSlugSet = new Set();
  for (const [sectionIndex, section] of doc.sections.entries()) {
    if (!section || typeof section !== "object") {
      addError(
        errors,
        `${relPath}: sections[${sectionIndex}] must be an object.`,
      );
      continue;
    }
    if (!hasNonEmptyString(section.title)) {
      addError(
        errors,
        `${relPath}: sections[${sectionIndex}] missing non-empty "title".`,
      );
    }
    if (!Array.isArray(section.stories)) {
      addError(
        errors,
        `${relPath}: sections[${sectionIndex}] must include "stories" array.`,
      );
      continue;
    }

    for (const [storyIndex, story] of section.stories.entries()) {
      if (!story || typeof story !== "object") {
        addError(
          errors,
          `${relPath}: sections[${sectionIndex}].stories[${storyIndex}] must be an object.`,
        );
        continue;
      }
      if (!hasNonEmptyString(story.slug)) {
        addError(
          errors,
          `${relPath}: sections[${sectionIndex}].stories[${storyIndex}] missing non-empty "slug".`,
        );
        continue;
      }
      if (!hasNonEmptyString(story.story)) {
        addError(
          errors,
          `${relPath}: story "${story.slug}" must include non-empty "story" text.`,
        );
      }
      if (!Array.isArray(story.evidenceLinks)) {
        addError(
          errors,
          `${relPath}: story "${story.slug}" must include "evidenceLinks" array.`,
        );
        continue;
      }
      if (story.partial !== undefined && typeof story.partial !== "boolean") {
        addError(
          errors,
          `${relPath}: story "${story.slug}" has non-boolean "partial".`,
        );
      }
      if (localSlugSet.has(story.slug)) {
        addError(
          errors,
          `${relPath}: duplicate slug "${story.slug}" in same file.`,
        );
        continue;
      }
      localSlugSet.add(story.slug);
      stories.push(story);

      if (globalSlugOwner.has(story.slug)) {
        addError(
          errors,
          `${relPath}: slug "${story.slug}" already exists in ${globalSlugOwner.get(story.slug)} (cross-domain duplicate).`,
        );
      } else {
        globalSlugOwner.set(story.slug, relPath);
      }

      const seenEvidenceIds = new Set();
      for (const evidenceId of story.evidenceLinks) {
        if (!hasNonEmptyString(evidenceId)) {
          addError(
            errors,
            `${relPath}: story "${story.slug}" has empty evidence link.`,
          );
          continue;
        }
        if (seenEvidenceIds.has(evidenceId)) {
          addError(
            errors,
            `${relPath}: story "${story.slug}" has duplicate evidence link "${evidenceId}".`,
          );
          continue;
        }
        seenEvidenceIds.add(evidenceId);
        if (!evidenceById.has(evidenceId)) {
          addError(
            errors,
            `${relPath}: story "${story.slug}" references unknown evidence id "${evidenceId}".`,
          );
        }
      }
    }
  }

  let knownCoverageGaps = [];
  if (doc.knownCoverageGaps !== undefined) {
    if (!Array.isArray(doc.knownCoverageGaps)) {
      addError(
        errors,
        `${relPath}: "knownCoverageGaps" must be an array when provided.`,
      );
    } else {
      knownCoverageGaps = doc.knownCoverageGaps;
    }
  }
  const knownGapReasonsByStory = new Map();
  for (const [index, gap] of knownCoverageGaps.entries()) {
    if (!gap || typeof gap !== "object") {
      addError(
        errors,
        `${relPath}: knownCoverageGaps[${index}] must be an object.`,
      );
      continue;
    }
    if (!hasNonEmptyString(gap.description)) {
      addError(
        errors,
        `${relPath}: knownCoverageGaps[${index}] missing non-empty "description".`,
      );
    }
    if (!Array.isArray(gap.references) || gap.references.length === 0) {
      addError(
        errors,
        `${relPath}: knownCoverageGaps[${index}] must include non-empty "references" array.`,
      );
    } else {
      for (const reference of gap.references) {
        if (!hasNonEmptyString(reference)) {
          addError(
            errors,
            `${relPath}: knownCoverageGaps[${index}] contains empty reference.`,
          );
        }
      }
    }
    if (gap.storySlugs !== undefined) {
      if (!Array.isArray(gap.storySlugs) || gap.storySlugs.length === 0) {
        addError(
          errors,
          `${relPath}: knownCoverageGaps[${index}] "storySlugs" must be a non-empty array when provided.`,
        );
      } else {
        for (const slug of gap.storySlugs) {
          if (!hasNonEmptyString(slug)) {
            addError(
              errors,
              `${relPath}: knownCoverageGaps[${index}] contains empty story slug.`,
            );
            continue;
          }
          if (!localSlugSet.has(slug)) {
            addError(
              errors,
              `${relPath}: knownCoverageGaps[${index}] references unknown story slug "${slug}".`,
            );
            continue;
          }
          if (hasNonEmptyString(gap.description)) {
            const existing = knownGapReasonsByStory.get(slug) || [];
            existing.push(gap.description);
            knownGapReasonsByStory.set(slug, existing);
          }
        }
      }
    }
  }

  for (const story of stories) {
    const status = computeStoryStatus(
      story,
      evidenceById,
      knownGapReasonsByStory,
    );
    if (status === "missing") {
      if (!hasNonEmptyString(story.gapReason)) {
        addError(
          errors,
          `${relPath}: missing story "${story.slug}" must include non-empty gapReason.`,
        );
      }
      continue;
    }
    if (status === "partial") {
      if (story.evidenceLinks.length === 0) {
        addError(
          errors,
          `${relPath}: partial story "${story.slug}" must include evidenceLinks.`,
        );
      }
      const hasKnownCoverageGapReason = knownGapReasonsByStory.has(story.slug);
      if (!hasNonEmptyString(story.gapReason) && !hasKnownCoverageGapReason) {
        addError(
          errors,
          `${relPath}: partial story "${story.slug}" must include non-empty gapReason or a knownCoverageGaps entry with storySlugs.`,
        );
      }
      continue;
    }
    if (story.evidenceLinks.length === 0) {
      addError(
        errors,
        `${relPath}: story "${story.slug}" has no evidence links but is not marked missing.`,
      );
    }

    if (status !== "missing") {
      validateStoryTrace({
        relPath,
        story,
        evidenceById,
        errors,
        fileContentCache,
      });
    }
  }

  return {
    domain: doc.domain,
    file: relPath,
    stories,
    evidenceById,
    knownCoverageGaps,
    knownGapReasonsByStory,
  };
}

function main() {
  const rawArgs = process.argv.slice(2).filter((arg) => arg !== "--");
  const showGaps = rawArgs.includes("--gaps");
  const showTrace = rawArgs.includes("--trace");
  const showTraceJson = rawArgs.includes("--trace-json");
  const args = rawArgs.filter(
    (arg) => arg !== "--gaps" && arg !== "--trace" && arg !== "--trace-json",
  );
  const errors = [];
  const storyFiles = collectStoryFiles(args, errors);
  const domains = new Map();
  const slugOwner = new Map();
  const fileContentCache = new Map();

  if (errors.length > 0) {
    console.error("Evidence validation failed:\n");
    for (const message of errors) {
      console.error(`- ${message}`);
    }
    process.exit(1);
  }

  for (const filePath of storyFiles) {
    const relPath = path.relative(ROOT, filePath);
    let doc;
    try {
      doc = readJson(filePath);
    } catch (error) {
      addError(errors, `Invalid JSON in ${relPath}: ${error.message}`);
      continue;
    }

    const result = validateDocument(
      doc,
      relPath,
      errors,
      slugOwner,
      fileContentCache,
    );
    if (!result) {
      continue;
    }

    if (domains.has(result.domain)) {
      addError(
        errors,
        `${relPath}: duplicate domain "${result.domain}" already declared in ${domains.get(result.domain).file}.`,
      );
      continue;
    }
    domains.set(result.domain, result);
  }

  if (errors.length > 0) {
    console.error("Evidence validation failed:\n");
    for (const message of errors) {
      console.error(`- ${message}`);
    }
    process.exit(1);
  }

  console.log("Evidence validation passed.\n");
  if (args.length > 0) {
    console.log(
      `Scoped run: validated ${storyFiles.length} requested file(s).\n`,
    );
  }

  const domainNames = Array.from(domains.keys()).sort();
  const traceReport = [];
  for (const domain of domainNames) {
    const domainData = domains.get(domain);
    const counts = {
      implemented_tested: 0,
      implemented_untested: 0,
      partial: 0,
      missing: 0,
    };

    for (const story of domainData.stories) {
      const status = computeStoryStatus(
        story,
        domainData.evidenceById,
        domainData.knownGapReasonsByStory,
      );
      counts[status] += 1;
    }

    const parts = STATUS_ORDER.filter((status) => counts[status] > 0)
      .map((status) => `${status}=${counts[status]}`)
      .join(", ");

    console.log(`- ${domain}: ${domainData.stories.length} stories (${parts})`);
    const proofCounts = domainData.stories.reduce(
      (acc, story) => {
        const level = story.trace?.proofLevel;
        if (TRACE_PROOF_LEVELS.has(level)) {
          acc[level] += 1;
        }
        return acc;
      },
      { unit: 0, runtime: 0, e2e: 0 },
    );
    traceReport.push({ domain, stories: domainData.stories.length, proofCounts });
    if (showTrace || showTraceJson) {
      console.log(
        `  trace: unit=${proofCounts.unit}, runtime=${proofCounts.runtime}, e2e=${proofCounts.e2e}`,
      );
    }
    if (!showGaps) {
      continue;
    }

    const statusGaps = domainData.stories
      .map((story) => ({
        story,
        status: computeStoryStatus(
          story,
          domainData.evidenceById,
          domainData.knownGapReasonsByStory,
        ),
      }))
      .filter(({ status }) => status === "partial" || status === "missing");

    if (statusGaps.length === 0 && domainData.knownCoverageGaps.length === 0) {
      console.log("  gap-audit: no gaps recorded");
      continue;
    }

    if (statusGaps.length > 0) {
      console.log("  Story status gaps:");
      for (const { story, status } of statusGaps) {
        const knownReasons =
          domainData.knownGapReasonsByStory.get(story.slug) || [];
        const reason = hasNonEmptyString(story.gapReason)
          ? story.gapReason
          : knownReasons.length > 0
            ? knownReasons.join("; ")
            : "no gapReason provided";
        console.log(`  - ${status}: ${story.slug} (${reason})`);
      }
    }

    if (domainData.knownCoverageGaps.length > 0) {
      console.log("  Known coverage gaps:");
      for (const gap of domainData.knownCoverageGaps) {
        const storyPart =
          Array.isArray(gap.storySlugs) && gap.storySlugs.length > 0
            ? ` [stories: ${gap.storySlugs.join(", ")}]`
            : "";
        console.log(`  - ${gap.description}${storyPart}`);
      }
    }
  }

  if (showTraceJson) {
    console.log("");
    console.log(
      JSON.stringify(
        {
          traceReport,
        },
        null,
        2,
      ),
    );
  }
}

main();
