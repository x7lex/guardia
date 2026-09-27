# Automatic Gemini findings

The scanner and HTTP proxy flow were adapted from `origin/main` at `ce3a84d`.
The Python Gemini integration is unchanged. Every successful file scan now sends
its complete report, including behavior evidence, to the existing `/review`
endpoint automatically. Reviews run sequentially without blocking scanning.
The default model is `gemini-2.5-flash`. Temporary Google server errors get one
retry followed by `gemini-2.5-flash-lite`; all attempts share a 90-second deadline.
Override the fallback with `GEMINI_FALLBACK_MODEL` (an empty value disables it).
Billing, quota, and authentication errors are returned without retries.

Findings appear in the top-center panel below the banner. Select a file to see its
review, collapse the panel for more space, or retry a failed review. Completed
reviews are saved with scan history and reused when those scans are reopened.
Older saved scans without reviews are reviewed when opened. Gemini failure does
not discard the underlying scan results.

## Run locally on Windows

1. In the repository root, copy `.env.example` to `.env` and set `API_TOKEN` or
   `GEMINI_API_KEY`. Keep credentials in this server-only file. `GEMINI_MODEL`
   controls the model; its default is inherited from main.
2. Install backend dependencies in a virtual environment:
   `py -m venv .venv`, then `.venv\Scripts\python -m pip install -r requirements.txt`.
3. In `website/scanly`, run `npm run dev` (browser) or `npm run desktop:dev`.
   Both commands start the Python scanner automatically and wait for its health
   check before opening the website. `npm start` does the same for production.
   They reuse an existing healthy scanner and only stop processes they started.
   If Python uses a different address, set `BACKEND_URL` in this folder's
   `.env.local`, following `.env.example`. Root `.env` `BACKEND_HOST` and
   `BACKEND_PORT` are also respected. Set `PYTHON_PATH` to use a different Python
   installation; otherwise the launcher prefers the root `.venv`.
4. For a separately managed scanner, run
   `.venv\Scripts\python src\main.py --serve` from the repository root.

The latest backend uses uploaded files rather than the old `/path` WebSocket.
Browse or drop files/folders, then select Scan All. Desktop drops still report
the absolute path through `onDrop`; the actual scan uses the selected file bytes.
The API key stays on the Python backend; the frontend proxies reports to it.

Production uses `npm run build` and `npm start`. Desktop builds now include a
local Next server for the scan/review proxies instead of a static export. The
Python scanner must still be running separately for an installed desktop build;
the development and web launch commands manage it automatically.

## Verification

- Frontend: `node --experimental-strip-types --test tests/*.test.mjs`
- Type checking: `npx tsc --noEmit`
- Production build: `npm run build`
- Backend from repository root: `.venv\Scripts\python -m unittest discover -s tests`

Backend Gemini tests mock Google responses; they do not consume API quota.
