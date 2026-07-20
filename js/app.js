// app.js — controller: wire the UI to the datasource + similarity engine.
import { rankCorpus, inferFamily } from "./similarity.js";
import { resolveSample, getProxyUrl, saveProxyUrl } from "./datasource.js";

const SHA256_RE = /^[a-fA-F0-9]{64}$/;

const el = (id) => document.getElementById(id);
const state = { corpus: null };

async function loadCorpus() {
  // The dataset ships base64-encoded (data/dataset.b64.json) so its plaintext
  // malware indicator strings don't trip antivirus false positives in the repo
  // or on clone. It is inert reference DATA; we decode it here at load.
  const resp = await fetch("./data/dataset.b64.json", { cache: "no-cache" });
  if (!resp.ok) throw new Error("Failed to load dataset.b64.json (" + resp.status + ")");
  const wrapper = await resp.json();
  if (!wrapper || wrapper.encoding !== "base64" || !wrapper.payload) {
    throw new Error("dataset.b64.json is malformed (expected base64 wrapper).");
  }
  const json = decodeBase64Utf8(wrapper.payload);
  return JSON.parse(json);
}

function decodeBase64Utf8(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder("utf-8").decode(bytes);
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function pct(x) {
  return (Math.round(x * 1000) / 10).toFixed(1) + "%";
}

function scoreClass(p) {
  if (p >= 0.75) return "score-high";
  if (p >= 0.45) return "score-mid";
  return "score-low";
}

// ---- rendering ----------------------------------------------------------

function renderExamples() {
  const wrap = el("examples");
  wrap.innerHTML = "";
  for (const s of state.corpus.samples.slice(0, 8)) {
    const b = document.createElement("button");
    b.className = "chip";
    b.textContent = s.family + " — " + s.sha256.slice(0, 10) + "…";
    b.title = s.name + "\n" + s.sha256;
    b.addEventListener("click", () => {
      el("hash-input").value = s.sha256;
      runAnalysis();
    });
    wrap.appendChild(b);
  }
}

function featureRow(label, part, kind) {
  const shared = part.shared || [];
  const pctScore = part.score;
  const noteKind = kind === "compiler" || kind === "imphash";
  const chips = shared
    .slice(0, 40)
    .map((s) => `<span class="tag">${esc(s)}</span>`)
    .join("");
  const more = shared.length > 40 ? `<span class="tag muted">+${shared.length - 40} more</span>` : "";
  const meta = !part.present
    ? `<span class="feat-note">not compared — no data on one side</span>`
    : noteKind
      ? `<span class="feat-note">${esc(part.note || "")}</span>`
      : `<span class="feat-note">${shared.length} shared · Jaccard ${pct(part.jaccard)} · containment ${pct(part.containment)}</span>`;

  return `
    <div class="feature">
      <div class="feature-head">
        <span class="feature-name">${esc(label)}</span>
        <span class="feature-score ${scoreClass(pctScore)}">${pct(pctScore)}</span>
      </div>
      <div class="feature-bar"><div class="feature-fill ${scoreClass(pctScore)}" style="width:${(pctScore * 100).toFixed(1)}%"></div></div>
      ${meta}
      ${shared.length || kind === "compiler" ? `<div class="tags">${chips}${more}</div>` : `<div class="tags muted">no shared items</div>`}
    </div>`;
}

function renderTopMatch(query, result, familyGuess, sourceInfo) {
  const c = result.candidate;
  const p = result.parts;
  const overall = result.overallPct;

  el("result").classList.remove("hidden");
  el("empty").classList.add("hidden");

  const sourceBadge =
    sourceInfo.source === "malwarebazaar"
      ? `<span class="src-badge live">live: MalwareBazaar</span>`
      : `<span class="src-badge corpus">bundled corpus</span>`;

  el("result").innerHTML = `
    <div class="verdict">
      <div class="verdict-score ${scoreClass(overall / 100)}">
        <div class="big-pct">${overall.toFixed(1)}%</div>
        <div class="big-label">similar</div>
      </div>
      <div class="verdict-body">
        <div class="verdict-line">
          <span class="k">Closest match</span>
          <span class="v">${esc(c.name)} <span class="mono">(${esc(c.sha256.slice(0, 16))}…)</span></span>
        </div>
        <div class="verdict-line">
          <span class="k">Likely family</span>
          <span class="v family">${esc(familyGuess.family)} <span class="conf">${familyGuess.confidence}% · ${esc(familyGuess.source || "similarity inference")}</span></span>
        </div>
        <div class="verdict-line">
          <span class="k">Type</span><span class="v">${esc(c.type || "—")}</span>
        </div>
        <div class="verdict-line">
          <span class="k">Compiler</span><span class="v">${esc(query.compiler || "unknown")} <span class="muted">vs</span> ${esc(c.compiler || "unknown")}</span>
        </div>
        <div class="verdict-line">
          <span class="k">Source</span><span class="v">${sourceBadge}</span>
        </div>
      </div>
    </div>

    <h3 class="section-h">Feature breakdown</h3>
    <div class="features">
      ${featureRow("Imphash (import table)", p.imphash, "imphash")}
      ${featureRow("Imports", p.imports, "imports")}
      ${featureRow("Shared functions", p.functions, "functions")}
      ${featureRow("Shared strings", p.strings, "strings")}
      ${featureRow("Shared resources", p.resources, "resources")}
      ${featureRow("Compiler", p.compiler, "compiler")}
    </div>
  `;
}

function renderSimilarList(ranked) {
  const list = el("similar-list");
  const top = ranked.slice(0, 8).filter((r) => r.overall > 0.05);
  if (top.length === 0) {
    list.innerHTML = `<p class="muted">No other samples cross the similarity floor.</p>`;
    return;
  }
  list.innerHTML = top
    .map((r) => {
      const c = r.candidate;
      return `
      <button class="sim-row" data-sha="${esc(c.sha256)}">
        <span class="sim-pct ${scoreClass(r.overall)}">${r.overallPct.toFixed(1)}%</span>
        <span class="sim-main">
          <span class="sim-name">${esc(c.name)}</span>
          <span class="sim-sub">${esc(c.family)} · ${esc(c.type || "")}</span>
        </span>
        <span class="sim-hash mono">${esc(c.sha256.slice(0, 12))}…</span>
      </button>`;
    })
    .join("");

  list.querySelectorAll(".sim-row").forEach((row) => {
    row.addEventListener("click", () => {
      el("hash-input").value = row.getAttribute("data-sha");
      runAnalysis();
    });
  });
}

function showMessage(msg, kind) {
  const box = el("message");
  if (!msg) {
    box.classList.add("hidden");
    box.textContent = "";
    return;
  }
  box.className = "message " + (kind || "info");
  box.textContent = msg;
  box.classList.remove("hidden");
}

// ---- main flow ----------------------------------------------------------

async function runAnalysis() {
  const raw = el("hash-input").value.trim();
  showMessage("");
  if (!SHA256_RE.test(raw)) {
    showMessage("Enter a valid SHA256 (64 hex characters).", "error");
    return;
  }

  el("analyze-btn").disabled = true;
  el("analyze-btn").textContent = "Analyzing…";

  try {
    const preferLive = el("prefer-live") && el("prefer-live").checked;
    const { profile, source, warning } = await resolveSample(raw, state.corpus, { preferLive });

    if (!profile) {
      el("result").classList.add("hidden");
      el("similar-wrap").classList.add("hidden");
      el("empty").classList.remove("hidden");
      showMessage(warning || "No profile found for that hash.", "error");
      return;
    }

    if (warning) showMessage(warning, "warn");

    const ranked = rankCorpus(profile, state.corpus, { excludeSelf: true });

    if (ranked.length === 0) {
      el("result").classList.add("hidden");
      showMessage("Loaded the sample, but the corpus has nothing to compare against.", "warn");
      return;
    }

    // Family: if the source already KNOWS the family (MalwareBazaar's signature,
    // or a labeled corpus hit), that is authoritative — report it directly and
    // don't overwrite it with a similarity guess. Only infer from the corpus
    // when the sample itself carries no family label.
    const knownFamily = profile.family && !/^unknown/i.test(profile.family) ? profile.family : null;
    let familyGuess;
    if (knownFamily) {
      familyGuess = {
        family: knownFamily,
        confidence: source === "malwarebazaar" ? 100 : 95,
        source: source === "malwarebazaar" ? "MalwareBazaar signature" : "corpus label",
      };
    } else {
      familyGuess = inferFamily(ranked, { topK: 5 });
      familyGuess.source = "similarity inference";
    }

    renderTopMatch(profile, ranked[0], familyGuess, { source });
    el("similar-wrap").classList.remove("hidden");
    renderSimilarList(ranked);
  } catch (e) {
    showMessage("Analysis error: " + (e && e.message ? e.message : e), "error");
  } finally {
    el("analyze-btn").disabled = false;
    el("analyze-btn").textContent = "Analyze";
  }
}

// ---- settings (proxy URL) -----------------------------------------------

function initSettings() {
  const dlg = el("settings");
  const proxyField = el("proxy-url");
  proxyField.value = getProxyUrl();

  el("settings-btn").addEventListener("click", () => dlg.showModal());
  el("settings-close").addEventListener("click", () => dlg.close());
  el("save-proxy").addEventListener("click", () => {
    const val = proxyField.value.trim();
    saveProxyUrl(val);
    showMessage(val ? "Proxy URL saved. Live lookup is now enabled." : "Proxy URL cleared. Live lookup disabled.", "info");
    dlg.close();
  });
}

// ---- boot ---------------------------------------------------------------

async function boot() {
  try {
    state.corpus = await loadCorpus();
  } catch (e) {
    showMessage(e.message, "error");
    return;
  }
  el("corpus-count").textContent = state.corpus.samples.length;
  const famCount = new Set(state.corpus.samples.map((s) => s.family)).size;
  const famEl = el("family-count");
  if (famEl) famEl.textContent = famCount;
  renderExamples();
  initSettings();

  el("analyze-btn").addEventListener("click", runAnalysis);
  el("hash-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") runAnalysis();
  });
}

boot();
