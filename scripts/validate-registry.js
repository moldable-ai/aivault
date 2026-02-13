#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
const registryDir = path.join(repoRoot, "registry");
const schemaPath = path.join(registryDir, "schemas", "registry-provider.schema.json");
const expectedSchemaRef = "./schemas/registry-provider.schema.json";

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function push(errors, file, message) {
  errors.push(`${file}: ${message}`);
}

function validateAuth(auth, file, errors) {
  if (auth === "basic" || auth === "mtls") {
    return;
  }
  if (!auth || typeof auth !== "object" || Array.isArray(auth)) {
    push(errors, file, "auth must be an object (or string variant basic/mtls)");
    return;
  }
  const keys = Object.keys(auth);
  if (keys.length !== 1) {
    push(errors, file, "auth object must define exactly one strategy");
    return;
  }
  const key = keys[0];
  const value = auth[key];

  const requireFields = (obj, fields) => {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      push(errors, file, `auth.${key} must be an object`);
      return false;
    }
    let ok = true;
    for (const field of fields) {
      if (!isNonEmptyString(obj[field])) {
        push(errors, file, `auth.${key}.${field} must be a non-empty string`);
        ok = false;
      }
    }
    return ok;
  };

  if (key === "header") {
    requireFields(value, ["header_name", "value_template"]);
    return;
  }
  if (key === "path") {
    requireFields(value, ["prefix_template"]);
    return;
  }
  if (key === "query") {
    requireFields(value, ["param_name"]);
    return;
  }
  if (key === "multi_header") {
    if (!Array.isArray(value) || value.length === 0) {
      push(errors, file, "auth.multi_header must be a non-empty array");
      return;
    }
    for (const item of value) {
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        push(errors, file, "auth.multi_header[] entries must be objects");
        continue;
      }
      if (!isNonEmptyString(item.header_name)) {
        push(errors, file, "auth.multi_header[].header_name must be a non-empty string");
      }
      if (!isNonEmptyString(item.value_template)) {
        push(errors, file, "auth.multi_header[].value_template must be a non-empty string");
      }
    }
    return;
  }
  if (key === "o_auth2") {
    if (requireFields(value, ["grant_type", "token_endpoint"])) {
      if (value.scopes !== undefined) {
        if (!Array.isArray(value.scopes) || value.scopes.some((s) => !isNonEmptyString(s))) {
          push(errors, file, "auth.o_auth2.scopes must be an array of non-empty strings");
        }
      }
    }
    return;
  }
  if (key === "aws_sig_v4") {
    requireFields(value, ["service", "region"]);
    return;
  }
  if (key === "hmac") {
    requireFields(value, ["algorithm", "header_name", "value_template"]);
    return;
  }
  push(errors, file, `unsupported auth variant '${key}'`);
}

function sortedUnique(arr) {
  const uniq = Array.from(new Set(arr));
  const sorted = [...uniq].sort();
  return arr.length === sorted.length && arr.every((v, i) => v === sorted[i]);
}

function validateStringArray(arr, file, field, errors) {
  if (!Array.isArray(arr) || arr.length === 0) {
    push(errors, file, `${field} must be a non-empty array`);
    return false;
  }
  if (arr.some((item) => !isNonEmptyString(item))) {
    push(errors, file, `${field} must contain only non-empty strings`);
    return false;
  }
  if (!sortedUnique(arr)) {
    push(errors, file, `${field} must be sorted ascending with no duplicates`);
  }
  return true;
}

function validateCapability(capability, provider, file, errors, seenCapabilityIds) {
  if (!capability || typeof capability !== "object" || Array.isArray(capability)) {
    push(errors, file, "capabilities[] entries must be objects");
    return;
  }
  if (!isNonEmptyString(capability.id)) {
    push(errors, file, "capabilities[].id must be a non-empty string");
  }
  if (!isNonEmptyString(capability.provider)) {
    push(errors, file, "capabilities[].provider must be a non-empty string");
  } else if (capability.provider !== provider) {
    push(
      errors,
      file,
      `capabilities[].provider '${capability.provider}' must match provider '${provider}'`
    );
  }
  if (isNonEmptyString(capability.id)) {
    if (seenCapabilityIds.has(capability.id)) {
      push(errors, file, `duplicate capability id across registry files: '${capability.id}'`);
    } else {
      seenCapabilityIds.add(capability.id);
    }
  }

  const allow = capability.allow;
  if (!allow || typeof allow !== "object" || Array.isArray(allow)) {
    push(errors, file, "capabilities[].allow must be an object");
    return;
  }
  validateStringArray(allow.hosts, file, "capabilities[].allow.hosts", errors);
  validateStringArray(allow.methods, file, "capabilities[].allow.methods", errors);
  validateStringArray(allow.pathPrefixes, file, "capabilities[].allow.pathPrefixes", errors);
}

function main() {
  const errors = [];

  if (!fs.existsSync(schemaPath)) {
    console.error(`Missing registry schema: ${path.relative(repoRoot, schemaPath)}`);
    process.exit(1);
  }
  JSON.parse(fs.readFileSync(schemaPath, "utf8"));

  const entries = fs.readdirSync(registryDir, { withFileTypes: true });
  const jsonFiles = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
    .map((entry) => entry.name)
    .sort();

  if (jsonFiles.length === 0) {
    console.error("No registry provider files found in registry/");
    process.exit(1);
  }

  const seenProviders = new Set();
  const seenCapabilityIds = new Set();
  let capabilitiesTotal = 0;

  for (const fileName of jsonFiles) {
    const fullPath = path.join(registryDir, fileName);
    const fileLabel = path.join("registry", fileName);
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(fullPath, "utf8"));
    } catch (err) {
      push(errors, fileLabel, `invalid JSON: ${err.message}`);
      continue;
    }

    if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
      push(errors, fileLabel, "root must be an object");
      continue;
    }

    if (doc.$schema !== expectedSchemaRef) {
      push(
        errors,
        fileLabel,
        `$schema must equal '${expectedSchemaRef}' (got '${doc.$schema || ""}')`
      );
    }

    if (!isNonEmptyString(doc.provider)) {
      push(errors, fileLabel, "provider must be a non-empty string");
      continue;
    }
    const expectedFile = `${doc.provider}.json`;
    if (fileName !== expectedFile) {
      push(errors, fileLabel, `filename should be '${expectedFile}'`);
    }
    if (seenProviders.has(doc.provider)) {
      push(errors, fileLabel, `duplicate provider '${doc.provider}'`);
    } else {
      seenProviders.add(doc.provider);
    }

    validateAuth(doc.auth, fileLabel, errors);
    validateStringArray(doc.hosts, fileLabel, "hosts", errors);

    if (!Array.isArray(doc.capabilities) || doc.capabilities.length === 0) {
      push(errors, fileLabel, "capabilities must be a non-empty array");
      continue;
    }

    const capabilityIds = [];
    for (const capability of doc.capabilities) {
      if (capability && typeof capability === "object" && isNonEmptyString(capability.id)) {
        capabilityIds.push(capability.id);
      }
      validateCapability(capability, doc.provider, fileLabel, errors, seenCapabilityIds);
      capabilitiesTotal += 1;
    }
    if (!sortedUnique(capabilityIds)) {
      push(errors, fileLabel, "capabilities must be sorted by id with no duplicates");
    }
  }

  if (errors.length > 0) {
    console.error("Registry validation failed:");
    for (const err of errors) {
      console.error(`- ${err}`);
    }
    process.exit(1);
  }

  console.log(
    `Registry validation passed (${seenProviders.size} providers, ${capabilitiesTotal} capabilities).`
  );
}

main();
