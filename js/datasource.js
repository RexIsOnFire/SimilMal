// datasource.js — resolve a SHA256 into a feature profile.
//
// Order of resolution:
//   1. Bundled corpus (instant, offline, full features).
//   2. Live MalwareBazaar lookup via the user's proxy Worker (optional).
//
// Why a proxy Worker instead of calling MalwareBazaar directly:
//   MalwareBazaar (mb-api.abuse.ch) requires an Auth-Key on every request AND
//   sends no CORS headers, so a static browser page can never call it directly.
//   The user deploys the tiny Cloudflare Worker in worker/malwarebazaar-proxy.js
//   (which holds their key server-side and adds CORS) and pastes its URL here.
//   The browser calls the Worker; the Worker calls MalwareBazaar. No secret ever
//   lives in this page or the visitor's browser.
//
// MalwareBazaar's get_info returns metadata (imports/imphash, file_type,
// signature, tags) but NOT disassembled functions or extracted strings, so a
// live sample is scored on the features it actually has, with the missing sets
// left empty and flagged as coarse in the UI.

const PROXY_STORAGE = "similmal.proxy_url";

export function getProxyUrl() {
  try {
    return (localStorage.getItem(PROXY_STORAGE) || "").trim();
  } catch {
    return "";
  }
}

export function saveProxyUrl(url) {
  try {
    const clean = (url || "").trim();
    if (clean) localStorage.setItem(PROXY_STORAGE, clean);
    else localStorage.removeItem(PROXY_STORAGE);
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
  const tags = Array.isArray(rec.tags) ? rec.tags : [];
  const family =
    rec.signature ||
    tags.find((t) => /trojan|ransom|stealer|bot|loader|rat|worm|miner|wiper|backdoor/i.test(t)) ||
    "Unknown";

  const imports = [];
  const importedFns = [];
  if (rec.pe && Array.isArray(rec.pe.imports)) {
    for (const imp of rec.pe.imports) {
      if (imp.dll) imports.push(imp.dll);
      if (Array.isArray(imp.functions)) importedFns.push(...imp.functions);
    }
  }

  // Use the imphash as a strong "import fingerprint" string when the full import
  // table isn't provided, plus tags and filenames as available string features.
  const strings = tags.slice();
  if (rec.imphash) strings.push("imphash:" + rec.imphash);
  if (rec.tlsh) strings.push("tlsh:" + rec.tlsh);
  if (rec.file_name) strings.push(rec.file_name);

  return {
    sha256: (rec.sha256_hash || "").toLowerCase(),
    name: rec.file_name || rec.sha256_hash,
    family,
    type: tags[0] || rec.file_type || "Unknown",
    first_seen: rec.first_seen || null,
    compiler: guessCompilerFromMb(rec),
    arch: rec.file_arch || String(rec.file_type || "").toUpperCase(),
    imphash: rec.imphash && rec.imphash !== "n/a" ? rec.imphash : null,
    imports,
    imported_functions: importedFns,
    functions: [], // not provided by MalwareBazaar metadata
    strings,
    resources: [],
    _source: "malwarebazaar",
    // "partial" = no strong structural feature to match on. With a real imphash
    // we DO have a strong signal, so only flag partial when even that is absent.
    _partial: !rec.imphash || rec.imphash === "n/a",
  };
}

function guessCompilerFromMb(rec) {
  const ft = String(rec.file_type || "").toLowerCase();
  const tags = (rec.tags || []).map((t) => t.toLowerCase());
  if (tags.includes("net") || tags.includes("msil") || ft.includes("net")) return ".NET (C#)";
  if (ft.includes("elf")) return "GCC (ELF)";
  if (tags.includes("upx")) return "UPX (packed)";
  if (ft.includes("dll") || ft.includes("exe")) return "Microsoft Visual C++ (unknown)";
  return "unknown";
}

// Query MalwareBazaar through the user's proxy Worker. Resolves to a profile or
// throws with a machine-readable message the caller turns into UI text.
export async function queryViaProxy(sha256, proxyUrl) {
  if (!proxyUrl) throw new Error("no-proxy");

  let resp;
  try {
    resp = await fetch(proxyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash: String(sha256).trim() }),
    });
  } catch (e) {
    const err = new Error("proxy-unreachable");
    err.detail = String(e && e.message ? e.message : e);
    throw err;
  }

  let data;
  try {
    data = await resp.json();
  } catch {
    throw new Error("proxy-bad-response");
  }

  if (!resp.ok) {
    // Worker/upstream errors carry a structured { error } we can surface.
    const err = new Error("proxy-error-" + resp.status);
    err.detail = data && data.error ? data.error : "";
    throw err;
  }
  if (data.query_status && data.query_status !== "ok") {
    throw new Error(data.query_status === "hash_not_found" ? "not-found" : "mb-" + data.query_status);
  }
  if (!Array.isArray(data.data) || data.data.length === 0) {
    throw new Error("not-found");
  }

  return mbRecordToProfile(data.data[0]);
}

// High-level resolver used by the app. Returns { profile, source, warning }.
//
// preferLive === true: try the proxy FIRST (for a hash that may also be in the
// corpus, e.g. to compare live metadata), then fall back to the corpus.
// preferLive falsey: corpus first; only try the proxy if the hash is unknown
// AND a proxy is configured. An unchecked box with no proxy never calls out.
export async function resolveSample(sha256, corpus, { preferLive } = {}) {
  const inCorpus = findInCorpus(sha256, corpus);
  const proxyUrl = getProxyUrl();

  if (preferLive && proxyUrl) {
    try {
      const profile = await queryViaProxy(sha256, proxyUrl);
      return { profile, source: "malwarebazaar", warning: partialWarning(profile) };
    } catch (e) {
      const reason = liveErrorMessage(e);
      if (inCorpus) {
        return { profile: inCorpus, source: "corpus", warning: "Live lookup failed (" + reason + "). Showing bundled corpus profile instead." };
      }
      return { profile: null, source: null, warning: "Live lookup failed (" + reason + "), and this hash is not in the bundled corpus." };
    }
  }

  if (inCorpus) {
    return { profile: inCorpus, source: "corpus", warning: null };
  }

  // Not in corpus. Only reach out if the user actually configured a proxy.
  if (proxyUrl) {
    try {
      const profile = await queryViaProxy(sha256, proxyUrl);
      return { profile, source: "malwarebazaar", warning: partialWarning(profile) };
    } catch (e) {
      return { profile: null, source: null, warning: "This hash is not in the bundled corpus, and the live lookup failed (" + liveErrorMessage(e) + ")." };
    }
  }

  return {
    profile: null,
    source: null,
    warning: "This SHA256 is not in the bundled corpus. To look up arbitrary hashes live, deploy the MalwareBazaar proxy Worker and paste its URL in Settings.",
  };
}

function partialWarning(profile) {
  return profile._partial
    ? "MalwareBazaar returned metadata only (no disassembled functions or extracted strings). Similarity is computed on imports, compiler and tags — treat scores as coarse."
    : null;
}

function liveErrorMessage(e) {
  const m = e && e.message;
  switch (m) {
    case "no-proxy": return "no proxy URL configured";
    case "proxy-unreachable": return "proxy unreachable (check the Worker URL)";
    case "proxy-bad-response": return "proxy returned a non-JSON response";
    case "not-found": return "hash unknown to MalwareBazaar";
    default:
      if (m && m.startsWith("proxy-error-")) {
        const detail = e.detail ? " – " + e.detail : "";
        return "proxy/upstream returned " + m.slice(12) + detail;
      }
      if (m && m.startsWith("mb-")) return "MalwareBazaar: " + m.slice(3);
      return m || "unknown error";
  }
}
