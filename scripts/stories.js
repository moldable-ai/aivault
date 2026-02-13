#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const STORIES_DIR = path.join(ROOT, "prds", "user-stories");
const EXCLUDED_FILES = new Set(["how-to.json"]);

function createFormatter(plain) {
  const colorsEnabled =
    !plain &&
    process.env.NO_COLOR === undefined &&
    (Boolean(process.stdout.isTTY) || hasString(process.env.FORCE_COLOR));

  function paint(text, ansiPrefix) {
    if (!colorsEnabled) {
      return text;
    }
    return `\x1b[${ansiPrefix}m${text}\x1b[0m`;
  }

  return {
    heading: (text) => paint(text, "1;36"),
    section: (text) => paint(text, "1"),
    dim: (text) => paint(text, "90"),
    code: (text) => paint(`\`${text}\``, "1"),
    status(status) {
      const token = `[${status}]`;
      if (status === "covered") {
        return paint(token, "1;32");
      }
      if (status === "partial") {
        return paint(token, "1;33");
      }
      return paint(token, "1;31");
    },
    gap: (text) => paint(text, "33"),
    error: (text) => paint(text, "31"),
  };
}

function readJson(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

function listStoryFiles() {
  return fs
    .readdirSync(STORIES_DIR)
    .filter((name) => name.endsWith(".json"))
    .filter((name) => !EXCLUDED_FILES.has(name))
    .map((name) => path.join(STORIES_DIR, name))
    .sort();
}

function resolveTarget(target) {
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

function collectFiles(targets) {
  if (targets.length === 0) {
    return listStoryFiles();
  }

  const resolved = new Set();
  const errors = [];

  for (const target of targets) {
    const filePath = resolveTarget(target);
    if (!filePath) {
      errors.push(
        `Target "${target}" not found. Pass a domain (e.g. "approvals") or path to a stories JSON file.`,
      );
      continue;
    }

    const normalized = path.resolve(filePath);
    if (!normalized.startsWith(STORIES_DIR + path.sep)) {
      errors.push(`Target "${target}" must be under prds/user-stories/.`);
      continue;
    }

    if (!normalized.endsWith(".json")) {
      errors.push(`Target "${target}" must be a .json file or a domain name.`);
      continue;
    }

    if (EXCLUDED_FILES.has(path.basename(normalized))) {
      errors.push(`Target "${target}" is not a domain stories file.`);
      continue;
    }

    resolved.add(normalized);
  }

  if (errors.length > 0) {
    throw new Error(errors.map((message) => `- ${message}`).join("\n"));
  }

  return Array.from(resolved).sort();
}

function hasString(value) {
  return typeof value === "string" && value.length > 0;
}

function computeStatus(story) {
  if (!Array.isArray(story.evidenceLinks) || story.evidenceLinks.length === 0) {
    return "missing";
  }
  if (story.partial === true) {
    return "partial";
  }
  return "covered";
}

function summarizeCounts(stories) {
  const counts = {
    covered: 0,
    partial: 0,
    missing: 0,
  };
  for (const story of stories) {
    counts[computeStatus(story)] += 1;
  }
  return counts;
}

function flattenStories(sections) {
  const stories = [];
  for (const section of sections) {
    if (!section || typeof section !== "object") {
      continue;
    }
    if (!Array.isArray(section.stories)) {
      continue;
    }
    for (const story of section.stories) {
      stories.push(story);
    }
  }
  return stories;
}

function wrapText(text, maxWidth) {
  const normalized = String(text || "")
    .trim()
    .replace(/\s+/g, " ");
  if (normalized.length === 0) {
    return [""];
  }

  const words = normalized.split(" ");
  const lines = [];
  let current = "";
  for (const word of words) {
    if (current.length === 0) {
      current = word;
      continue;
    }
    if (`${current} ${word}`.length <= maxWidth) {
      current = `${current} ${word}`;
      continue;
    }
    lines.push(current);
    current = word;
  }
  if (current.length > 0) {
    lines.push(current);
  }
  return lines;
}

function parseArgs(rawArgs) {
  const args = rawArgs.filter((arg) => arg !== "--");
  const plain = args.includes("--plain");
  const help = args.includes("--help") || args.includes("-h");
  const targets = args.filter(
    (arg) => arg !== "--plain" && arg !== "--help" && arg !== "-h",
  );

  const unknownFlags = targets.filter((arg) => arg.startsWith("-"));
  if (unknownFlags.length > 0) {
    throw new Error(
      `Unknown option(s): ${unknownFlags.join(", ")}. Use --help to see supported flags.`,
    );
  }

  return { plain, help, targets };
}

function printHelp() {
  console.log("Usage:");
  console.log("  pnpm stories -- [--plain] [domain|path ...]");
  console.log("");
  console.log("Examples:");
  console.log("  pnpm stories");
  console.log("  pnpm stories -- approvals");
  console.log("  pnpm stories -- approvals groups");
  console.log("  pnpm stories -- prds/user-stories/approvals.json");
  console.log("  pnpm stories -- --plain approvals");
}

function renderDomain(doc, relPath, formatter) {
  if (!doc || typeof doc !== "object") {
    throw new Error(`${relPath}: expected JSON object root.`);
  }
  if (!hasString(doc.domain)) {
    throw new Error(`${relPath}: missing non-empty "domain" string.`);
  }
  if (!Array.isArray(doc.sections)) {
    throw new Error(`${relPath}: missing "sections" array.`);
  }

  const allStories = flattenStories(doc.sections);
  const counts = summarizeCounts(allStories);
  const wrapWidth = Math.max(40, Number(process.stdout.columns || 120) - 4);

  console.log(formatter.heading(`## ${doc.domain}`));
  console.log(
    formatter.dim(
      `${allStories.length} stories - ${counts.covered} covered, ${counts.partial} partial, ${counts.missing} missing`,
    ),
  );
  console.log("");

  for (const section of doc.sections) {
    if (!section || typeof section !== "object") {
      continue;
    }
    if (!hasString(section.title) || !Array.isArray(section.stories)) {
      continue;
    }
    console.log(formatter.section(`### ${section.title}`));
    console.log("");

    for (const story of section.stories) {
      if (!story || typeof story !== "object") {
        continue;
      }
      const slug = hasString(story.slug) ? story.slug : "unknown-slug";
      const text = hasString(story.story)
        ? story.story
        : "(missing story text)";
      const status = computeStatus(story);
      const traceLevel = hasString(story?.trace?.proofLevel)
        ? story.trace.proofLevel
        : "none";
      const assertionCount = Array.isArray(story?.trace?.assertions)
        ? story.trace.assertions.length
        : 0;
      console.log(
        `- ${formatter.status(status)} ${formatter.code(slug)} ${formatter.dim(`[trace:${traceLevel}; assertions:${assertionCount}]`)}`,
      );
      const storyLines = wrapText(text, wrapWidth);
      for (const line of storyLines) {
        console.log(`  ${formatter.dim(line)}`);
      }
      if (status !== "covered" && hasString(story.gapReason)) {
        const gapLines = wrapText(`gap: ${story.gapReason}`, wrapWidth);
        for (const line of gapLines) {
          console.log(`  ${formatter.gap(line)}`);
        }
      }
      console.log("");
    }
  }
}

function main() {
  let parsed;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (error) {
    const formatter = createFormatter(true);
    console.error(
      formatter.error(`Stories rendering failed:\n${error.message}`),
    );
    process.exit(1);
  }
  if (parsed.help) {
    printHelp();
    return;
  }

  const formatter = createFormatter(parsed.plain);
  let files;
  try {
    files = collectFiles(parsed.targets);
  } catch (error) {
    console.error(
      formatter.error(`Stories rendering failed:\n${error.message}`),
    );
    process.exit(1);
  }

  console.log(formatter.heading("# User Stories"));
  console.log("");

  for (const filePath of files) {
    const relPath = path.relative(ROOT, filePath);
    let doc;
    try {
      doc = readJson(filePath);
    } catch (error) {
      console.error(
        formatter.error(
          `Stories rendering failed:\n- Invalid JSON in ${relPath}: ${error.message}`,
        ),
      );
      process.exit(1);
    }

    try {
      renderDomain(doc, relPath, formatter);
    } catch (error) {
      console.error(
        formatter.error(`Stories rendering failed:\n- ${error.message}`),
      );
      process.exit(1);
    }
  }
}

main();
