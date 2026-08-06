#!/usr/bin/env node
"use strict";

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CARGO_TOML = path.join(ROOT, "Cargo.toml");

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: ROOT,
    stdio: "inherit",
    ...options,
  });
}

function read(command, args) {
  return execFileSync(command, args, {
    cwd: ROOT,
    encoding: "utf8",
  }).trim();
}

function cargoVersion() {
  const contents = fs.readFileSync(CARGO_TOML, "utf8");
  const match = contents.match(/^version\s*=\s*"([^"]+)"/m);
  if (!match) throw new Error("Could not resolve the aivault Cargo version.");
  return match[1];
}

function repository() {
  const remote = read("git", ["remote", "get-url", "origin"]);
  const match = remote.match(/github\.com[:/]([^/]+\/[^/.]+)(?:\.git)?$/);
  if (!match) throw new Error(`Origin is not a GitHub repository: ${remote}`);
  return match[1];
}

function crateIsPublished(version) {
  try {
    const response = read("curl", [
      "-fsS",
      `https://crates.io/api/v1/crates/aivault/${version}`,
    ]);
    return JSON.parse(response).version?.num === version;
  } catch {
    return false;
  }
}

function usage() {
  console.log("Usage: pnpm release [--dry-run]");
  console.log(
    "Publishes the Cargo version already tagged at HEAD, then creates its GitHub release.",
  );
}

const args = new Set(process.argv.slice(2));
if (args.has("--help") || args.has("-h")) {
  usage();
  process.exit(0);
}
if ([...args].some((arg) => arg !== "--dry-run")) {
  usage();
  process.exit(1);
}

const version = cargoVersion();
const tag = `cli-v${version}`;
if (read("git", ["status", "--porcelain"])) {
  throw new Error("Working tree is dirty. Commit changes before publishing a release.");
}
run("git", ["rev-parse", "--verify", `${tag}^{commit}`], { stdio: "ignore" });
if (!read("git", ["ls-remote", "--tags", "origin", tag])) {
  throw new Error(`${tag} has not been pushed to origin.`);
}

console.log(`Publishing aivault ${version} from ${tag}.`);
if (args.has("--dry-run")) process.exit(0);

if (crateIsPublished(version)) {
  console.log(`aivault ${version} is already published on crates.io.`);
} else {
  run("cargo", ["publish", "--locked"]);
}

const repo = repository();
try {
  run("gh", ["release", "view", tag, "--repo", repo]);
  console.log(`GitHub release ${tag} already exists.`);
} catch {
  run("gh", [
    "release",
    "create",
    tag,
    "--repo",
    repo,
    "--title",
    `aivault v${version}`,
    "--generate-notes",
  ]);
}
