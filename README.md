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

After each API or CLI scan (and CLI rescore), the backend sends the
complete report JSON (including extracted strings and analysis evidence) to Google
Gemini through the Python backend. It does not upload the original binary to Gemini.
The response explains the evidence, uncertainty, and suggested next steps while
preserving the original scanner score. The plain-text second opinion is saved as `gemini_review` and displayed in the
report panel. It assesses score reasonableness and likely false positives/negatives.
The prompt prohibits Markdown conventions, and the backend removes common Markdown
presentation syntax before saving or displaying reviews.
Missing credentials, oversized reports, or provider failures leave the deterministic
report intact with an explicit review-unavailable reason. The panel supports retry.
Configured reviews can add up to 90 seconds to each scan. Temporary provider
500/502/503/504 errors receive up to three attempts with exponential backoff and
jitter within that total deadline. Persistent Gemini overload returns HTTP 503
with a clear provider-unavailable message; key, billing and quota errors are not
automatically retried.

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
Model 4 uses a signature baseline plus capability combinations and a bounded CPU
contribution. Unsigned files start at 4.0, invalid signatures at 5.0, unknown
verification at 3.0, valid unrecognized signatures at 0.5, and valid recognized
signatures at 0.0. Trusted signing discounts weak findings by 90%; strong chains
retain their full weight. Multiple behavioral families amplify one another.
Every term and multiplier is explained in JSON; the final sum is capped at 10.0.
There is no confidence score or visibility floor. Extraction limitations remain
in the raw evidence, and low risk does not establish safety.

See [the scoring policy and verification results](docs/risk-architecture.md).
Fresh scans, saved-report rescoring, and live plain-text Gemini reviews are in
[model 4 diagnostics](docs/diagnostics/model4).

Reproduce the comparison (optionally add `--samples-dir /path/to/fixtures` for
fresh static scans):

```sh
.venv/bin/python scripts/compare_reports.py --output docs/diagnostics/model4
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
rules without assigning risk points. See [Python deobfuscation](docs/python-deobfuscation.md)
for supported patterns, safety limits and a synthetic demo.
