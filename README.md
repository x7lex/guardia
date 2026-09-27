# Guardia web app and static PE scanner

Guardia runs in a browser with a Next.js frontend and Python/FastAPI scanner.
Choose files or folders (including subfolders), then click **Scan All**. The app
uploads selected files one at a time, displays real analysis reports, and saves
scan history in browser storage. It no longer requires Electron or local folder
paths. Rescanning after a page reload requires selecting the original files again.

## Run the web app

Prerequisites: Python 3.11+, Node.js 22.18+ (or a newer supported LTS), and npm.
The commands below use macOS/Linux shell syntax. Start by cloning the repository:

```sh
git clone https://github.com/x7lex/hackthehill3.git
cd hackthehill3
```

Install the dependencies and start both services from the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
npm ci --prefix hackthehill3-website-final/website/scanly
.venv/bin/python scripts/dev.py
```

Open [http://localhost:3000](http://localhost:3000). Ctrl-C stops both services.
If a virtual environment and node_modules are already installed, only the last
command is needed. The frontend runs on port 3000 and the Python API on port 8000.
Select files or a folder, then click **Scan All** to create reports.
No API token is required for scanning.

For optional Gemini reviews, copy `.env.example` to `.env` (if you do not already
have one), set `API_TOKEN` or `GEMINI_API_KEY`, and restart the launcher. The same
file can set `BACKEND_PORT`; the launcher forwards that port to the frontend.
Keep `.env` local—Git ignores it.

To run separately, start `.venv/bin/python src/main.py --serve` at the root,
then `npm run dev` from `hackthehill3-website-final/website/scanly`.

## Production

Run the Python API as a long-lived service with `.venv/bin/python src/main.py --serve`.
In `hackthehill3-website-final/website/scanly`, run `npm run build`, then `npm start`.
This is a Node server deployment; static export hosting cannot proxy scans.

The browser posts to `/api/scan` on the website's own origin. Next.js streams the
request to the Python API at `http://127.0.0.1:8000` by default. For a separate
backend host, set `BACKEND_URL` in the website's `.env.local` or service environment
(see its `.env.example`). Python loads the root `.env` automatically; existing process environment variables
take priority, including `BACKEND_HOST` and `BACKEND_PORT`.
Keep the Python API private behind the website. Deploy with HTTPS and configure
any hosting proxy to allow the desired upload size and scan duration.

Uploads are limited to 512 MiB per file. Unsupported files are explicitly skipped.
The API uses temporary files, deletes originals after each analysis, and returns
reports without persisting them on the server. Reports stay in this browser's
local storage; the CLI below still writes JSON reports to disk. The scanner
serializes requests to bound parser memory. Cancel stops the browser's queue;
an analysis already running may finish on the server before its temporary file
is removed.

## Gemini review

After each API/CLI scan or CLI rescore, Gemini independently evaluates the complete
raw `analysis` evidence and separate `reputation` evidence. The backend excludes the
deterministic score, local verdict, weighted reasons and previous AI opinions from
its request, including legacy weights inside recovered script findings, so Gemini
can disagree without being anchored to the score.

Its plain-text response starts with exactly one of `THIS IS PERFECTLY FINE`,
`I CANNOT CONFIDENTLY SAY THAT`, or `USE AT YOUR OWN RISK`, followed by evidence-based
reasoning. A positive opinion is not a safety guarantee. Responses that violate the
verdict contract are rejected rather than assigned an invented verdict. Common
Markdown presentation syntax is removed before display. The result is saved in
`gemini_review`; neither engine score is overwritten. Old cached score-aware
reviews are identified as legacy.

Missing credentials, oversized evidence or provider failures preserve the report
with an explicit review-unavailable reason. Temporary provider 500/502/503/504
responses get at most three attempts with exponential backoff and jitter within
one 90-second deadline. Persistent overload returns 503; credential, billing and
quota errors are not automatically retried. The UI supports retry.

Set `API_TOKEN` (or `GEMINI_API_KEY`) in the root `.env`. The default model is
`gemini-3.8-flash`; override with `GEMINI_MODEL`. Restart Python after changing these
settings. Credentials never enter the browser bundle. Reviews are limited to 4 MiB
of JSON and are not silently truncated. Provider quota/access errors appear in the
panel. The integration uses Google's [generateContent API](https://ai.google.dev/api/generate-content).

## Verification

Browser tests start isolated production servers on ports 3100 and 8100 with live
Gemini calls disabled. Provider interactions are mocked in tests; fixture comparison
uses the configured live reviewer. Avoid running a production build concurrently
with a development server using the same Next.js output directory.

```sh
.venv/bin/python -m unittest discover -s tests -v
cd hackthehill3-website-final/website/scanly
npm run lint
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

Browser tests launch the production frontend and Python API, upload a synthetic
PE through the real parser, and check nested folders, report details, persistence,
unsupported files, and connection errors. No test executes uploaded binaries.

## Command-line scanner

Run from the project directory:

```sh
.venv/bin/python src/main.py /path/to/file-or-directory
```

Rescore an existing report without reopening its binary:

```sh
.venv/bin/python src/main.py --rescore-report /path/to/report.json
```

Analysis is static only. Reports are written to `src/reports`.
Model 5 separates hash reputation, deterministic local scoring and independent
Gemini assessment. Unsigned files start at 4.0 and suspicious combinations amplify
more strongly than in signed software. Common imports/instructions remain weak;
packing and concealed scripts now contribute. Valid recognized issuers receive
bounded discounts and are explicitly distinct from verified OS certificate chains.
Every local contribution is explained; the local score is retained even when an
exact known-malicious hash overrides the final engine classification to 10.0.
There is no confidence index or visibility floor.

The UI shows local heuristic score, final engine score, hash reputation and Gemini
independently. Scores below 3 use the happy face, 3–4.9 neutral, and 5+ frowny.

Optional hash-only reputation configuration in `.env`:

```sh
REPUTATION_PROVIDER=malwarebazaar
MALWAREBAZAAR_API_KEY=your-key
```

Alternatively use `REPUTATION_PROVIDER=virustotal` and `VIRUSTOTAL_API_KEY`.
Default is `disabled`; there is no upload/download implementation. Unknown hashes,
outages and rate limits do not stop static scans and do not imply safety. The
[scoring policy](docs/risk-architecture.md) documents the exact consensus and
positive-reputation thresholds. Obtain provider credentials from
[MalwareBazaar](https://bazaar.abuse.ch/api/) or [VirusTotal](https://docs.virustotal.com/reference/overview).

Optional local YARA scanning:

```sh
# yara-python is already included in requirements.txt.
# In .env, point to reviewed local rules:
YARA_RULES_PATH=/absolute/path/to/rules.yar
```

Strong YARA weight requires rule metadata `malware = true` and
`confidence = "high"`; generic matches are weak. Rules are not downloaded.

See [architecture, weights and calibration results](docs/risk-architecture.md), and
[full model 5 diagnostic reports](docs/diagnostics/model5). Reproduce the comparison:

```sh
.venv/bin/python scripts/compare_reports.py --output docs/diagnostics/model5
# Add --samples-dir /path/to/original/PEs for fresh static scans as well.
```

Appended ZIP containers are inspected in memory with entry, byte, depth and
decompression limits. Python source inspection uses AST syntax and bounded literal
transformations, including encoded names; it never imports or runs the bundled
application. Native archive members, bytecode, UPX code, unsupported 7z resources
and unresolved script layers remain explicit coverage limitations. No new
third-party dependency was added for the risk redesign.

Recovered Python also receives a bounded AST deobfuscation report with decoded
strings, symbolic imports and attributes, behavior hints, transformation examples
and resolution coverage. These facts enrich the existing source-local behavior
rules; model 5 gives observed concealment and correlated behaviors explicit risk contributions. See [Python deobfuscation](docs/python-deobfuscation.md)
for supported patterns, safety limits and a synthetic demo.
