// datasource.js — resolve a SHA256 into a feature profile.
//
// Order of resolution:
//   1. Bundled corpus (instant, offline, full features).
//   2. Live MalwareBazaar lookup IF the user has saved their own Auth-Key.
//
// MalwareBazaar (abuse.ch) requires an Auth-Key header. A public static page
// must NOT ship a secret key, so the key is entered by the user and kept only
// in this browser's localStorage. Even then, browser access depends on the
// endpoint sending permissive CORS headers; when it doesn't, the fetch fails
// and we fall back to the corpus. That limitation is surfaced in the UI, not
// hidden.
//
// MalwareBazaar's get_info returns metadata (imports, file_type, signatures,
// tags) but NOT disassembled functions or extracted strings, so a live sample
// is scored on the features it actually has (imports/compiler/tags-as-strings)
// with the missing sets left empty.

const MB_ENDPOINT = "https://mb-api.abuse.ch/api/v1/";
const KEY_STORAGE = "similmal.mb_authkey";

export function getSavedApiKey() {
  try {
    return localStorage.getItem(KEY_STORAGE) || "";
  } catch {
    return "";
  }
}

export function saveApiKey(key) {
  try {
    if (key) localStorage.setItem(KEY_STORAGE, key);
    else localStorage.removeItem(KEY_STORAGE);
    return true;
  } catch {
    return false;
  }
}

export function findInCorpus(sha256, corpus) {
  const target = String(sha256 || "").trim().toLowerCase();
  return corpus.samples.find((s) => s.sha256.toLowerCase() === target) || null;
}

// Map a MalwareBazaar get_info record into our feature-profile shape.
function mbRecordToProfile(rec) {
  const family =
    rec.signature ||
    (Array.isArray(rec.tags) ? rec.tags.find((t) => /trojan|ransom|stealer|bot|loader|rat|worm|miner/i.test(t)) : null) ||
    "Unknown";

  // MalwareBazaar exposes imported DLLs via the "pe_imphash" world only
  // indirectly; the richest import data is in the "code_sign" / "dhash_icon"
  // fields plus tags. We use what's present and label the rest as unavailable.
  const imports = [];
  const importedFns = [];

  // Some records carry a "pe" section with imports when available.
  if (rec.pe && Array.isArray(rec.pe.imports)) {
    for (const imp of rec.pe.imports) {
      if (imp.dll) imports.push(imp.dll);
      if (Array.isArray(imp.functions)) importedFns.push(...imp.functions);
    }
  }

  const strings = Array.isArray(rec.tags) ? rec.tags.slice() : [];
  if (rec.file_name) strings.push(rec.file_name);
  if (rec.imphash) strings.push("imphash:" + rec.imphash);

  return {
    sha256: (rec.sha256_hash || "").toLowerCase(),
    name: rec.file_name || rec.sha256_hash,
    family,
    type: (rec.tags && rec.tags[0]) || rec.file_type || "Unknown",
    first_seen: rec.first_seen || null,
    compiler: guessCompilerFromMb(rec),
    arch: rec.architecture || (rec.file_type || "").toUpperCase(),
    imports,
    imported_functions: importedFns,
    functions: [], // not provided by MalwareBazaar metadata
    strings,
    resources: [],
    _source: "malwarebazaar",
    _partial: importedFns.length === 0 && imports.length === 0,
  };
}

function guessCompilerFromMb(rec) {
  const ft = String(rec.file_type || "").toLowerCase();
  const tags = (rec.tags || []).map((t) => t.toLowerCase());
  if (tags.includes("net") || ft.includes("net") || tags.includes("msil")) return ".NET (C#)";
  if (ft.includes("elf")) return "GCC (ELF)";
  if (tags.includes("upx")) return "UPX (packed)";
  if (ft.includes("dll") || ft.includes("exe")) return "Microsoft Visual C++ (unknown)";
  return "unknown";
}

// Query MalwareBazaar for a hash. Resolves to a profile, or throws with a
// human-readable reason the caller shows before falling back to the corpus.
export async function queryMalwareBazaar(sha256, apiKey) {
  if (!apiKey) throw new Error("no-key");

  const body = new URLSearchParams();
  body.set("query", "get_info");
  body.set("hash", String(sha256).trim());

  let resp;
  try {
    resp = await fetch(MB_ENDPOINT, {
      method: "POST",
      headers: { "Auth-Key": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
  } catch (e) {
    // Almost always a CORS or network failure from the browser.
    const err = new Error("network-or-cors");
    err.detail = String(e && e.message ? e.message : e);
    throw err;
  }

  if (!resp.ok) {
    const err = new Error("http-" + resp.status);
    throw err;
  }

  const data = await resp.json();
  if (data.query_status !== "ok" || !Array.isArray(data.data) || data.data.length === 0) {
    const err = new Error("not-found");
    err.status = data.query_status;
    throw err;
  }

  return mbRecordToProfile(data.data[0]);
}

// High-level resolver used by the app. Returns { profile, source, warning }.
export async function resolveSample(sha256, corpus, { preferLive } = {}) {
  const inCorpus = findInCorpus(sha256, corpus);
  const apiKey = getSavedApiKey();

  // If a key is set and the user asked to prefer live, try MalwareBazaar first.
  if (preferLive && apiKey) {
    try {
      const profile = await queryMalwareBazaar(sha256, apiKey);
      const warning = profile._partial
        ? "MalwareBazaar returned metadata only (no disassembled functions or extracted strings). Similarity is computed on imports, compiler and tags — treat scores as coarse."
        : null;
      return { profile, source: "malwarebazaar", warning };
    } catch (e) {
      const reason = liveErrorMessage(e);
      if (inCorpus) {
        return { profile: inCorpus, source: "corpus", warning: "Live lookup failed (" + reason + "). Showing bundled corpus profile instead." };
      }
      return { profile: null, source: null, warning: "Live lookup failed (" + reason + ") and the hash is not in the bundled corpus." };
    }
  }

  if (inCorpus) {
    return { profile: inCorpus, source: "corpus", warning: null };
  }

  // Not in corpus and no live path attempted.
  if (apiKey) {
    // Have a key but preferLive was off; try live as a fallback.
    try {
      const profile = await queryMalwareBazaar(sha256, corpus && apiKey);
      return { profile, source: "malwarebazaar", warning: profile._partial ? "Metadata-only live result; scores are coarse." : null };
    } catch (e) {
      return { profile: null, source: null, warning: "Hash not in corpus; live lookup failed (" + liveErrorMessage(e) + ")." };
    }
  }

  return {
    profile: null,
    source: null,
    warning: "This SHA256 is not in the bundled corpus. Add your MalwareBazaar Auth-Key in Settings to attempt a live lookup.",
  };
}

function liveErrorMessage(e) {
  switch (e && e.message) {
    case "no-key": return "no API key saved";
    case "network-or-cors": return "network/CORS blocked in browser";
    case "not-found": return "hash unknown to MalwareBazaar";
    default:
      if (e && e.message && e.message.startsWith("http-")) return "API returned " + e.message.slice(5);
      return e && e.message ? e.message : "unknown error";
  }
}
