// similarity.js — multi-feature weighted similarity engine.
//
// Each sample is described by several feature SETS (functions, imports,
// strings, resources) plus a scalar compiler string. We score each feature
// independently, then combine them with the weights declared in the corpus.
//
// Set similarity uses Jaccard by default. Jaccard punishes samples of very
// different sizes even when the smaller is fully contained in the larger, so
// we blend in the containment coefficient (overlap / size-of-smaller-set):
//
//     blended = 0.6 * jaccard + 0.4 * containment
//
// This keeps a small loader that shares all of its imports with a big sample
// from being scored near-zero purely because the big sample has many more.

export function normalizeToken(s) {
  return String(s == null ? "" : s).trim().toLowerCase();
}

export function toSet(list) {
  const set = new Set();
  for (const item of list || []) {
    const t = normalizeToken(item);
    if (t) set.add(t);
  }
  return set;
}

export function intersect(aSet, bSet) {
  const [small, large] = aSet.size <= bSet.size ? [aSet, bSet] : [bSet, aSet];
  const shared = [];
  for (const v of small) if (large.has(v)) shared.push(v);
  return shared;
}

export function jaccard(aSet, bSet) {
  // NOTE: "both empty" is deliberately NOT treated as identical here. Absence of
  // a feature on both sides is absence of evidence, not evidence of similarity.
  // compareSamples() excludes a feature that is empty on both sides from the
  // weighted average entirely (see `present` in setScore), so this function is
  // only ever called with at least one non-empty side in scoring.
  if (aSet.size === 0 || bSet.size === 0) return 0;
  const shared = intersect(aSet, bSet).length;
  const union = aSet.size + bSet.size - shared;
  return union === 0 ? 0 : shared / union;
}

export function containment(aSet, bSet) {
  const minSize = Math.min(aSet.size, bSet.size);
  if (minSize === 0) return 0;
  return intersect(aSet, bSet).length / minSize;
}

export function setScore(aList, bList) {
  const a = toSet(aList);
  const b = toSet(bList);
  // `present` = this feature carries evidence to compare. If BOTH sides are
  // empty the feature is unknown for this pair and must be excluded from the
  // weighted average (not scored 1.0 — that bug made every metadata-only live
  // sample match whichever corpus entry shared the same empty feature).
  const present = a.size > 0 && b.size > 0;
  const j = jaccard(a, b);
  const c = containment(a, b);
  const score = 0.6 * j + 0.4 * c;
  return {
    score,
    present,
    jaccard: j,
    containment: c,
    shared: intersect(a, b),
    aSize: a.size,
    bSize: b.size,
  };
}

// Compiler is a scalar, not a set. Compare on a coarse "toolchain family" so
// "Microsoft Visual C++ 2015" and "...2017" are near, not identical, and a
// .NET vs native mismatch scores ~0.
function compilerFamily(s) {
  const t = normalizeToken(s);
  if (!t) return { family: "unknown", version: null };
  if (t.includes(".net") || t.includes("c#")) return { family: "dotnet", version: null };
  if (t.includes("visual c++") || t.includes("msvc")) {
    const m = t.match(/(\d{4}|6\.0)/);
    return { family: "msvc", version: m ? m[1] : null };
  }
  if (t.includes("gcc") || t.includes("clang") || t.includes("musl") || t.includes("uclibc"))
    return { family: "gcc", version: null };
  if (t.includes("upx") || t.includes("packed")) return { family: "packed", version: null };
  if (t.includes("delphi") || t.includes("borland")) return { family: "delphi", version: null };
  if (t.includes("go ") || t.startsWith("go") || t.includes("golang")) return { family: "go", version: null };
  if (t.includes("rust")) return { family: "rust", version: null };
  if (t.includes("nsis") || t.includes("inno")) return { family: "installer", version: null };
  return { family: t, version: null };
}

export function compilerScore(aComp, bComp) {
  const a = compilerFamily(aComp);
  const b = compilerFamily(bComp);
  // Unknown on either side = no evidence: mark not-present so it is excluded
  // from the weighted average rather than contributing a misleading 0.5.
  if (a.family === "unknown" || b.family === "unknown")
    return { score: 0, present: false, note: "toolchain unknown on one side" };
  if (a.family !== b.family) return { score: 0, present: true, note: "different toolchain family" };
  if (a.version && b.version) {
    return a.version === b.version
      ? { score: 1, present: true, note: "same toolchain + version" }
      : { score: 0.6, present: true, note: "same toolchain, different version" };
  }
  // Same BROAD family with no version detail (e.g. both "MSVC (unknown)") is
  // weak evidence — most Windows malware is MSVC, so sharing it says little.
  // Score it low so it can't, on its own, push unrelated samples to a high match.
  return { score: 0.25, present: true, note: "same broad toolchain (weak signal)" };
}

// TLSH (Trend Micro Locality Sensitive Hash) is a fuzzy hash: unlike imphash
// (exact), the DISTANCE between two TLSH digests measures how structurally
// similar two files are, even when not identical. This is what lets a sample
// with a unique imphash still score meaningful similarity to near-neighbors.
//
// The distance is Trend Micro's reference TLSH diff (tlsh_impl.cpp, diff_total
// with length), for the standard digest: "T1" + 70 hex = checksum byte, L byte,
// Q byte (two 4-bit ratios), then 32 body bytes = 128 two-bit buckets.
//   checksum differs        +1
//   L (log file length)      circular diff d: 0, 1, or d*12
//   Q1, Q2 ratios            circular diff d: d if d<=1, else (d-1)*12
//   each body bucket         |a-b|, except 3 costs 6
// In the hex digest the header bytes are nibble-swapped. Verified against
// py-tlsh's tlsh.diff on 300 real pairs from this corpus (exact match).
// Distance 0 = identical; related files are typically < 100, unrelated ones
// several hundred. We map distance to a 0..1 similarity with a soft curve.
const TLSH_HEX_LEN = 70;

function hexBytes(hex) {
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2) return null;
  const out = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

function modDiff(x, y, range) {
  const d = Math.abs(x - y);
  return Math.min(d, range - d);
}

const swapNibbles = (b) => ((b & 0x0f) << 4) | (b >> 4);

function bucketDistance(a, b) {
  let dist = 0;
  for (let shift = 0; shift < 8; shift += 2) {
    const d = Math.abs(((a >> shift) & 3) - ((b >> shift) & 3));
    dist += d === 3 ? 6 : d;
  }
  return dist;
}

export function tlshDistance(aHash, bHash) {
  const a = hexBytes(normalizeToken(aHash).replace(/^t1/, ""));
  const b = hexBytes(normalizeToken(bHash).replace(/^t1/, ""));
  if (!a || !b || a.length * 2 !== TLSH_HEX_LEN || b.length * 2 !== TLSH_HEX_LEN) return null;
  let dist = a[0] === b[0] ? 0 : 1;
  const ldiff = modDiff(swapNibbles(a[1]), swapNibbles(b[1]), 256);
  dist += ldiff <= 1 ? ldiff : ldiff * 12;
  for (const shift of [0, 4]) {
    const qdiff = modDiff((a[2] >> shift) & 0x0f, (b[2] >> shift) & 0x0f, 16);
    dist += qdiff <= 1 ? qdiff : (qdiff - 1) * 12;
  }
  for (let i = 3; i < a.length; i++) dist += bucketDistance(a[i], b[i]);
  return dist;
}

export function tlshScore(aHash, bHash) {
  const d = tlshDistance(aHash, bHash);
  if (d === null) return { score: 0, present: false, note: "TLSH missing/incompatible" };
  // Map distance -> similarity. d=0 identical (1.0); d>=300 ~ unrelated (~0).
  // Soft curve so near-neighbors (d<100) still read as clearly similar.
  const score = Math.max(0, 1 - d / 300);
  const note =
    d === 0 ? "identical TLSH" :
    d < 60 ? `very close (TLSH dist ${d})` :
    d < 120 ? `related (TLSH dist ${d})` :
    d < 200 ? `distant (TLSH dist ${d})` :
    `unrelated (TLSH dist ${d})`;
  return { score, present: true, distance: d, note };
}

// imphash is a hash of a PE's import table: two files with the SAME imphash have
// an identical set/order of imported functions — a very strong same-toolkit /
// same-family signal that real malware clustering relies on. It is an exact
// scalar match: equal = 1.0, different = 0, missing on either side = no evidence
// (present=false, excluded from the average).
export function imphashScore(aImp, bImp) {
  const a = normalizeToken(aImp);
  const b = normalizeToken(bImp);
  if (!a || !b || a === "n/a" || b === "n/a")
    return { score: 0, present: false, shared: [], note: "imphash missing on one side" };
  if (a === b) return { score: 1, present: true, shared: [a], note: "identical imphash (same import table)" };
  return { score: 0, present: true, shared: [], note: "different imphash" };
}

// Compare two samples, returning the overall percentage plus the per-feature
// breakdown the UI renders.
export function compareSamples(query, candidate, weights) {
  const w = weights || {
    imphash: 0.28, tlsh: 0.27, imports: 0.15, functions: 0.1, strings: 0.1, resources: 0.03, compiler: 0.07,
  };

  const imphash = imphashScore(query.imphash, candidate.imphash);
  const tlsh = tlshScore(query.tlsh || firstTlsh(query.strings), candidate.tlsh || firstTlsh(candidate.strings));
  const functions = setScore(query.functions, candidate.functions);
  const imports = setScore(mergeImports(query), mergeImports(candidate));
  const strings = setScore(query.strings, candidate.strings);
  const resources = setScore(query.resources, candidate.resources);
  const compiler = compilerScore(query.compiler, candidate.compiler);

  const parts = { imphash, tlsh, functions, imports, strings, resources, compiler };

  // Only features present (carrying evidence) on BOTH sides count toward the
  // score, and the weights are renormalized over just those. This means a
  // metadata-only live sample (no functions/strings/resources) is judged on
  // the features it actually has — not penalized or falsely boosted by the
  // features it lacks.
  let total = 0;
  let weightSum = 0;
  for (const key of Object.keys(w)) {
    const part = parts[key];
    if (!part || !part.present) continue;
    total += w[key] * part.score;
    weightSum += w[key];
  }
  const overall = weightSum > 0 ? total / weightSum : 0;

  // How much of the model's total weight actually had evidence — lets the UI
  // say "scored on 40% of features" and the family inference stay cautious
  // when comparisons rest on thin data.
  const totalWeight = Object.values(w).reduce((s, x) => s + x, 0) || 1;
  const coverage = weightSum / totalWeight;

  return {
    overall,
    overallPct: Math.round(overall * 1000) / 10, // one decimal
    coverage,
    parts,
  };
}

// Corpus samples carry their TLSH as a "tlsh:<hex>" token in strings; pull it
// out so tlshScore can use it even when there's no top-level tlsh field.
export function firstTlsh(strings) {
  for (const s of strings || []) {
    const t = String(s);
    if (t.toLowerCase().startsWith("tlsh:")) return t.slice(5);
  }
  return null;
}

// Treat DLL names and imported function names as one "imports" feature so the
// score reflects the whole import surface, not just DLL count.
export function mergeImports(sample) {
  const dlls = (sample.imports || []).map((d) => "dll:" + normalizeToken(d));
  const fns = (sample.imported_functions || []).map((f) => "fn:" + normalizeToken(f));
  return [...dlls, ...fns];
}

// Rank an entire corpus against a query sample. Returns candidates sorted by
// overall similarity descending, each carrying its full breakdown.
export function rankCorpus(query, corpus, opts) {
  const options = opts || {};
  const excludeExact = options.excludeSelf !== false;
  const weights = corpus.feature_weights;
  const results = [];

  for (const candidate of corpus.samples) {
    if (excludeExact && candidate.sha256 === query.sha256) continue;
    const cmp = compareSamples(query, candidate, weights);
    results.push({ candidate, ...cmp });
  }
  results.sort((a, b) => b.overall - a.overall);
  return results;
}

// Best-guess family: weighted vote over the top-K matches, weighted by their
// similarity. Only asserts a family when the leading vote is both dominant and
// backed by a reasonably strong top match.
export function inferFamily(ranked, opts) {
  const k = (opts && opts.topK) || 5;
  const top = ranked.slice(0, k).filter((r) => r.overall > 0.15);
  if (top.length === 0) return { family: "Unknown", confidence: 0, votes: [] };

  const tally = new Map();
  for (const r of top) {
    const fam = r.candidate.family || "Unknown";
    tally.set(fam, (tally.get(fam) || 0) + r.overall);
  }
  const votes = [...tally.entries()]
    .map(([family, weight]) => ({ family, weight }))
    .sort((a, b) => b.weight - a.weight);

  const totalWeight = votes.reduce((s, v) => s + v.weight, 0) || 1;
  const leader = votes[0];
  const share = leader.weight / totalWeight;
  const topMatch = ranked[0] ? ranked[0].overall : 0;

  // confidence blends how dominant the leading family is with how strong the
  // single best match is.
  const confidence = Math.round(Math.min(1, share * 0.6 + topMatch * 0.4) * 100);
  const family = topMatch >= 0.35 ? leader.family : "Unknown / low confidence";

  return { family, confidence, share: Math.round(share * 100), votes };
}
