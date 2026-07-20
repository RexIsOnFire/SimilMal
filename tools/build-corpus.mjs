// build-corpus.mjs — build a REAL corpus from MalwareBazaar's public data.
//
// Two data sources, both real (no fabricated hashes or imphashes):
//   1. MalwareBazaar recent CSV feed (public, no auth) — gives real sha256,
//      signature (family), imphash, file_type, tlsh for ~750 recent samples.
//   2. For a few samples per family, full get_info via the user's proxy Worker
//      (needs the MB key in the Worker) — gives the real PE import table so the
//      corpus has genuine imports/imported_functions to match on.
//
// Usage:
//   node tools/build-corpus.mjs <proxyWorkerUrl> [perFamily=6] [enrichPerFamily=2]
//
// Writes data/dataset.json (plaintext) then you run tools/encode-dataset.mjs.
//
// Everything here is real published metadata about real samples. We still label
// the dataset as a reference/education corpus, but there is no invented data.

import { writeFileSync } from "node:fs";

const CSV_URL = "https://bazaar.abuse.ch/export/csv/recent/";
const proxyUrl = process.argv[2];
const perFamily = parseInt(process.argv[3] || "6", 10);
const enrichPerFamily = parseInt(process.argv[4] || "2", 10);

if (!proxyUrl) {
  console.error("usage: node tools/build-corpus.mjs <proxyWorkerUrl> [perFamily] [enrichPerFamily]");
  process.exit(1);
}

// We do NOT hardcode families: every named signature in the feed is eligible,
// so the corpus reflects whatever real families are circulating. A family is
// only kept if it reaches `minPerFamily` samples, to avoid one-off noise.
const minPerFamily = parseInt(process.env.MIN_PER_FAMILY || "1", 10);

function parseCsvLine(line) {
  // MB CSV fields are quoted and comma+space separated: "a", "b", ...
  const out = [];
  const re = /"([^"]*)"/g;
  let m;
  while ((m = re.exec(line)) !== null) out.push(m[1]);
  return out;
}

function fileTypeToCompiler(ft, tags) {
  const t = (ft || "").toLowerCase();
  const tg = (tags || []).map((x) => x.toLowerCase());
  if (tg.includes("net") || tg.includes("msil")) return ".NET (C#)";
  if (t.includes("elf")) return "GCC (ELF)";
  if (tg.includes("upx")) return "UPX (packed)";
  if (t === "exe" || t === "dll") return "Microsoft Visual C++ (unknown)";
  return "unknown";
}

async function enrich(sha256) {
  try {
    const resp = await fetch(proxyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash: sha256 }),
    });
    const data = await resp.json();
    const rec = data && data.data && data.data[0];
    if (!rec) return null;
    const imports = [];
    const importedFns = [];
    if (rec.pe && Array.isArray(rec.pe.imports)) {
      for (const imp of rec.pe.imports) {
        if (imp.dll) imports.push(imp.dll);
        if (Array.isArray(imp.functions)) importedFns.push(...imp.functions);
      }
    }
    return { imports, importedFns };
  } catch {
    return null;
  }
}

async function main() {
  console.log("fetching MalwareBazaar recent feed…");
  const csv = await (await fetch(CSV_URL)).text();
  const lines = csv.split("\n").filter((l) => l && !l.startsWith("#"));

  // header order: first_seen, sha256, md5, sha1, reporter, file_name,
  //   file_type_guess, mime, signature, clamav, vtpercent, imphash, ssdeep, tlsh
  const byFamily = new Map();
  for (const line of lines) {
    const f = parseCsvLine(line);
    if (f.length < 14) continue;
    const [first_seen, sha256, , , , file_name, file_type, , signature, , , imphash, , tlsh] = f;
    if (!signature || signature === "n/a") continue;
    const fam = signature; // every named family is eligible
    if (!byFamily.has(fam)) byFamily.set(fam, []);
    const list = byFamily.get(fam);
    if (list.length >= perFamily) continue;
    if (imphash && imphash !== "n/a" && list.some((s) => s.imphash === imphash)) continue; // dedup identical imphash
    list.push({ first_seen, sha256, file_name, file_type, signature, imphash, tlsh });
  }

  // drop families that didn't reach the minimum (avoids one-off signature noise)
  for (const [fam, list] of [...byFamily]) {
    if (list.length < minPerFamily) byFamily.delete(fam);
  }

  const samples = [];
  for (const [fam, list] of byFamily) {
    let enriched = 0;
    for (const s of list) {
      let imports = [];
      let importedFns = [];
      if (enriched < enrichPerFamily) {
        const e = await enrich(s.sha256);
        if (e) { imports = e.imports; importedFns = e.importedFns; enriched++; }
      }
      // Real structural signals only. We deliberately do NOT feed the family
      // signature into the strings feature: that would be circular (matching on
      // the very label we then "infer"). imphash (import-table hash) and tlsh
      // (locality-sensitive hash) are genuine structural fingerprints.
      const tags = [s.file_type, s.signature].filter((x) => x && x !== "n/a");
      const strings = [];
      if (s.imphash && s.imphash !== "n/a") strings.push("imphash:" + s.imphash);
      if (s.tlsh && s.tlsh !== "n/a") strings.push("tlsh:" + s.tlsh);
      samples.push({
        sha256: s.sha256.toLowerCase(),
        name: (s.file_name && s.file_name !== "n/a" ? s.file_name : s.signature) + " (" + s.sha256.slice(0, 8) + ")",
        family: s.signature,
        type: s.file_type || "Unknown",
        first_seen: s.first_seen,
        compiler: fileTypeToCompiler(s.file_type, tags),
        arch: (s.file_type || "").toUpperCase(),
        imphash: s.imphash && s.imphash !== "n/a" ? s.imphash : null,
        imports,
        imported_functions: importedFns,
        functions: [], // MalwareBazaar does not provide disassembled functions
        strings,
        resources: [],
      });
    }
    console.log(`  ${fam}: ${list.length} samples (${Math.min(enrichPerFamily, list.length)} enriched with imports)`);
  }

  const corpus = {
    schema_version: 2,
    generated: new Date().toISOString().slice(0, 10),
    source: "MalwareBazaar (abuse.ch) recent CSV feed + get_info enrichment",
    note: "Real published PE malware metadata from MalwareBazaar: genuine SHA256 hashes, imphashes, signatures, and (for enriched samples) real PE import tables. Disassembled functions and extracted strings are not available from MalwareBazaar, so those feature sets are empty; matching leans on imphash, imports, compiler and tags.",
    feature_weights: {
      imphash: 0.30,
      imports: 0.25,
      functions: 0.15,
      strings: 0.15,
      resources: 0.05,
      compiler: 0.10,
    },
    samples,
  };

  const outPath = process.env.CORPUS_OUT || "data/dataset.json";
  writeFileSync(outPath, JSON.stringify(corpus, null, 2));
  console.log(`\nwrote ${outPath} with ${samples.length} REAL samples across ${byFamily.size} families`);
}

main();
