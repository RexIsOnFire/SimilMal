# SimilMal — Malware Similarity Engine

Like GitHub's "similar repositories," but for malware. Enter a SHA256 and SimilMal returns the
closest known sample, a likely family, and a per-feature breakdown of what they share.

Everything runs **in the browser**. There is no backend, no upload, and no build step, so it deploys
to GitHub Pages as-is.

## What it shows

For a given SHA256:

- **Overall similarity** (e.g. `93.0% similar`) to the closest known sample
- **Likely family** with a confidence score, inferred by a weighted vote over the top matches
- **Shared functions** — overlapping analyst-labeled behaviors
- **Shared strings** — overlapping notable strings
- **Shared resources** — overlapping embedded resources
- **Compiler / toolchain** comparison
- **Imports** — shared DLLs and imported functions
- A ranked **similar samples** list you can click to pivot

## How similarity is computed

Each sample is a set of feature groups. SimilMal scores each group independently, then combines them
with the weights declared in the dataset (`feature_weights`):

| Feature   | Weight | Method                          |
|-----------|--------|---------------------------------|
| Functions | 0.30   | blended Jaccard + containment   |
| Imports   | 0.25   | blended Jaccard + containment   |
| Strings   | 0.25   | blended Jaccard + containment   |
| Resources | 0.10   | blended Jaccard + containment   |
| Compiler  | 0.10   | toolchain-family match          |

Set similarity blends **Jaccard** (`|A∩B| / |A∪B|`) with the **containment coefficient**
(`|A∩B| / min(|A|,|B|)`) as `0.6·jaccard + 0.4·containment`. Containment stops a small sample that is
fully contained in a much larger one from scoring near-zero just because of size. The math lives in
[`js/similarity.js`](js/similarity.js) and is fully transparent and explainable.

## Where the data comes from

**Bundled corpus (default).** `data/dataset.b64.json` ships a curated set of well-known malware family
profiles (WannaCry, NotPetya, Emotet, TrickBot, Cobalt Strike, AgentTesla, Mirai, Ryuk, Conti, Zeus,
and more). Published SHA256 hashes are used where available; the feature vectors are analyst-curated
approximations compiled from public reporting — this is a teaching/demonstration corpus, not a live
sandbox dump.

**Live lookup (optional).** For a hash not in the corpus, SimilMal can query
**MalwareBazaar (abuse.ch)** live from your browser. This requires **your own** Auth-Key, entered in
Settings and stored only in this browser's `localStorage` — no secret is ever committed to the repo.

> Important browser limitation: a purely static page cannot safely embed a shared API key, and live
> calls only work if MalwareBazaar returns permissive CORS headers to the browser. When the live call
> is blocked (CORS/network) or the hash is unknown, SimilMal falls back to the bundled corpus and says
> so in the UI. MalwareBazaar metadata also lacks disassembled functions and extracted strings, so a
> live result is scored on the features it does provide (imports, compiler, tags) and flagged as
> coarse.

## Run locally

The app uses native ES modules, which browsers only load over HTTP (not `file://`). Serve the folder:

```bash
cd SimilMal
python3 -m http.server 8080
# then open http://localhost:8080
```

Any static server works (`npx serve`, `php -S`, etc.).

## Deploy to GitHub Pages

1. Push this repository to GitHub.
2. In **Settings → Pages**, set the source to **GitHub Actions**.
3. The included workflow ([`.github/workflows/deploy.yml`](.github/workflows/deploy.yml)) validates the
   corpus and publishes the site on every push to `main`.

The `.nojekyll` file ensures GitHub serves the `js/`, `css/`, and `data/` folders untouched.

## Why the dataset is base64-encoded

The corpus documents real malware indicator strings — ransom-note filenames, killswitch domains,
command lines. A plaintext file full of those is a **false-positive magnet** for antivirus: during
development Bitdefender flagged the plaintext `corpus.json` as `Generic.RYUK.*` and quarantined it.

To keep the repository and every clone AV-clean, the app loads `data/dataset.b64.json`, whose
`payload` is the base64 of the plaintext dataset. The browser decodes it at load
([`js/app.js`](js/app.js) → `loadCorpus`). This is inert reference **data**, not code — encoding just
stops the string-signature match. The plaintext files (`data/dataset.json`, `data/corpus.json`) are
`.gitignore`d and never committed.

## Extending the corpus

Edit the plaintext dataset (`data/dataset.json`), then re-encode it:

```bash
node tools/encode-dataset.mjs        # data/dataset.json -> data/dataset.b64.json
```

Commit the regenerated `data/dataset.b64.json`. Each sample in the `samples` array:

```json
{
  "sha256": "…64 hex…",
  "name": "Human-readable name",
  "family": "Family",
  "type": "Ransomware | Loader | Infostealer | …",
  "compiler": "Microsoft Visual C++ 2015 | .NET (C#) | GCC (ELF) | UPX (packed) | …",
  "arch": "x86 | x64 | ARM/ELF",
  "imports": ["KERNEL32.dll", "…"],
  "imported_functions": ["CreateFileW", "…"],
  "functions": ["fn_labeled_behavior", "…"],
  "strings": ["notable string", "…"],
  "resources": ["embedded resource description", "…"]
}
```

The engine normalizes tokens (trim + lowercase), so casing and surrounding whitespace don't matter.

## Project layout

```
index.html               UI shell
css/styles.css           Styles
js/app.js                Controller: input -> resolve -> rank -> render (+ base64 decode)
js/similarity.js         Weighted multi-feature similarity engine
js/datasource.js         Corpus lookup + MalwareBazaar live adapter
data/dataset.b64.json    Curated corpus, base64-encoded (loaded by the app)
tools/encode-dataset.mjs Re-encode plaintext dataset -> base64 wrapper
.github/workflows/       GitHub Pages deploy workflow
```

## Scope and honesty

SimilMal is an educational, static demonstration of *similarity fingerprinting*. It is not a sandbox,
not an antivirus, and not a substitute for professional malware analysis. Similarity to a family is a
hypothesis to investigate, not a verdict.
