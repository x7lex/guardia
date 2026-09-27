# Guardia browser app

This Next.js app connects to the Python static PE scanner in the repository root.
See the [root setup guide](../../../README.md) for installation, the combined
launcher, production setup, and end-to-end tests.

From the repository root, run `.venv/bin/python scripts/dev.py` and open
[http://localhost:3000](http://localhost:3000).

To run only this frontend:

```sh
npm install
npm run dev
```

The Python API must also be running (`.venv/bin/python src/main.py --serve` from
the root). Optionally copy `.env.example` to `.env.local` and set `BACKEND_URL`
when Python runs somewhere other than `http://127.0.0.1:8000`.

Select a folder or files using the browser picker. Scans upload files individually
and retain subfolder names. Results, skipped-file explanations, filters, report
windows, transcript downloads, and browser-local history are available. Reloading
the page keeps reports; rescan requires reselecting the files.

Production: `npm run build && npm start`. Electron and static export are no longer
used. The `/api/scan` route streams uploads to Python and relays its reports and
errors over the same origin, so remote browsers do not connect to their own localhost.
