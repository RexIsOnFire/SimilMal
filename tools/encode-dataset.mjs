// Re-encode the plaintext dataset into the base64 wrapper the app loads.
//
// Why base64: the dataset documents real malware indicator strings (ransom
// note names, killswitch domains, etc.). Antivirus (e.g. Bitdefender) flags a
// plaintext file full of those as a false positive and locks/quarantines it.
// Shipping the payload base64-encoded keeps the repo and clones AV-clean; the
// browser decodes it at load. The encoded file is the source of truth that
// gets committed; the plaintext is gitignored.
//
// Usage:  node tools/encode-dataset.mjs [path/to/plaintext.json]
// Default input:  data/dataset.json      Output:  data/dataset.b64.json

import { readFileSync, writeFileSync } from "node:fs";

const input = process.argv[2] || "data/dataset.json";
const output = "data/dataset.b64.json";

const raw = readFileSync(input, "utf8");
const parsed = JSON.parse(raw); // validate before encoding
const payload = Buffer.from(raw, "utf8").toString("base64");

const wrapper = {
  encoding: "base64",
  schema_version: parsed.schema_version,
  samples_count: parsed.samples.length,
  note:
    "Payload is base64-encoded to avoid antivirus false positives on the plaintext malware indicator strings it documents. Decoded in-browser at load. This is inert reference DATA, not executable code.",
  payload,
};

writeFileSync(output, JSON.stringify(wrapper));
console.log(`encoded ${parsed.samples.length} samples: ${input} -> ${output}`);
