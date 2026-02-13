#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const CARGO_TOML = path.join(ROOT, "Cargo.toml");

function run(cmd, opts = {}) {
  return execSync(cmd, { stdio: "inherit", ...opts });
}

function read(cmd, opts = {}) {
  return execSync(cmd, { encoding: "utf8", ...opts }).trim();
}

function readCargoVersion() {
  const raw = fs.readFileSync(CARGO_TOML, "utf8");
  const match = raw.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error("Could not find version in Cargo.toml");
  return match[1];
}

function bumpVersion(current, kind) {
  const match = current.match(/^(\d+)\.(\d+)\.(\d+)(.*)?$/);
  if (!match) throw new Error(`Unsupported version format: ${current}`);
  let major = Number(match[1]);
  let minor = Number(match[2]);
  let patch = Number(match[3]);
  const suffix = match[4] || "";

  if (kind === "major") {
    major += 1;
    minor = 0;
    patch = 0;
  } else if (kind === "minor") {
    minor += 1;
    patch = 0;
  } else if (kind === "patch") {
    patch += 1;
  }

  return `${major}.${minor}.${patch}${suffix}`;
}

function parseStableVersion(version) {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compareStableVersions(a, b) {
  for (let idx = 0; idx < 3; idx += 1) {
    if (a[idx] !== b[idx]) return a[idx] - b[idx];
  }
  return 0;
}

function stableVersionFromTag(tag) {
  const match = tag.match(/^(?:cli-v|v)(\d+\.\d+\.\d+)$/);
  return match ? match[1] : null;
}

function latestStableGitVersion() {
  const out = read("git tag --list 'v*' 'cli-v*'");
  const tags = out
    .split(/\r?\n/)
    .map((tag) => tag.trim())
    .filter(Boolean);

  let best = null;
  let bestParsed = null;
  for (const tag of tags) {
    const version = stableVersionFromTag(tag);
    if (!version) continue;
    const parsed = parseStableVersion(version);
    if (!parsed) continue;
    if (!bestParsed || compareStableVersions(parsed, bestParsed) > 0) {
      best = version;
      bestParsed = parsed;
    }
  }
  return best;
}

function updateCargoVersion(next) {
  const raw = fs.readFileSync(CARGO_TOML, "utf8");
  const updated = raw.replace(/^version\s*=\s*"([^"]+)"/m, `version = "${next}"`);
  fs.writeFileSync(CARGO_TOML, updated);
}

function tagExists(tag) {
  try {
    execSync(`git rev-parse -q --verify refs/tags/${tag}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function usage() {
  console.log("\nUsage:");
  console.log(
    "  pnpm release:cli <version|patch|minor|major> [--dry-run] [--no-push] [--allow-dirty]"
  );
  console.log("  (creates git tag: cli-vX.Y.Z)\n");
}

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const noPush = args.includes("--no-push");
const allowDirty = args.includes("--allow-dirty");
const filtered = args.filter((arg) => !arg.startsWith("--"));
const input = filtered[0];

if (!input) {
  usage();
  process.exit(1);
}

const current = readCargoVersion();
const next =
  ["patch", "minor", "major"].includes(input)
    ? bumpVersion(latestStableGitVersion() || current, input)
    : input.replace(/^cli-v/, "").replace(/^v/, "");

if (!allowDirty) {
  const status = execSync("git status --porcelain", { encoding: "utf8" }).trim();
  if (status.length > 0) {
    console.error(
      "\nWorking tree is dirty. Commit or stash changes, or pass --allow-dirty.\n"
    );
    process.exit(1);
  }
}

const tag = `cli-v${next}`;
if (tagExists(tag)) {
  console.error(`\nTag already exists locally: ${tag}\n`);
  process.exit(1);
}

console.log(`\nReleasing CLI ${current} -> ${next} (${tag})`);

if (dryRun) {
  console.log("\nDry run: no files changed.");
  process.exit(0);
}

updateCargoVersion(next);

run("cargo generate-lockfile --manifest-path Cargo.toml");

run("git add Cargo.toml Cargo.lock");
run(`git commit -m "release: cli v${next}"`);
run(`git tag ${tag}`);

if (!noPush) {
  run("git push origin HEAD");
  run(`git push origin ${tag}`);
}

console.log(`\nDone. Tagged ${tag}.\n`);

