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
      : { score: 0.75, present: true, note: "same toolchain, different version" };
  }
  return { score: 0.9, present: true, note: "same toolchain family" };
}

// Compare two samples, returning the overall percentage plus the per-feature
// breakdown the UI renders.
export function compareSamples(query, candidate, weights) {
  const w = weights || {
    functions: 0.3, imports: 0.25, strings: 0.25, resources: 0.1, compiler: 0.1,
  };

  const functions = setScore(query.functions, candidate.functions);
  const imports = setScore(mergeImports(query), mergeImports(candidate));
  const strings = setScore(query.strings, candidate.strings);
  const resources = setScore(query.resources, candidate.resources);
  const compiler = compilerScore(query.compiler, candidate.compiler);

  const parts = { functions, imports, strings, resources, compiler };

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
