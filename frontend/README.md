# Smart Network Anomaly Analyzer — Dashboard

A React + TypeScript single-page app for the `sn-analyzer` FastAPI backend:
live pipeline status, capture start/stop, and an alert history browser with
evidence download.

## Prerequisites

- Node.js 18+ and npm (Node was not installed as part of this backend
  project, so install it from https://nodejs.org if you don't already have
  it — the LTS version is fine).
- The backend API running and reachable, since this dashboard has no data of
  its own — it only displays what `/status`, `/alerts`, etc. return.

## Running it

From this `frontend/` folder:

```
npm install
npm run dev
```

This starts the Vite dev server on **http://localhost:5173**. Open that in a
browser.

In a separate terminal, start the backend the same way you already have
been:

```
sn-analyzer-api --config configs/default.yaml
```

The dev server proxies every request under `/api/*` straight to
`http://127.0.0.1:8000` (see `vite.config.ts`), so the two talk to each other
without any CORS configuration to worry about. If you run the API on a
different host or port, update the `target` in `vite.config.ts`.

## What's here

- `src/api/types.ts` — TypeScript types mirroring the Pydantic schemas in
  `sn_analyzer/api/schemas.py`. If you change a field on the backend, update
  this file to match — nothing enforces they stay in sync automatically.
- `src/api/client.ts` — a small typed `fetch` wrapper, one function per
  endpoint.
- `src/pages/Dashboard.tsx` — pipeline status (polls `/status` every 2s),
  a form to start/stop capture (live interface or PCAP replay), and a
  severity breakdown of stored alerts.
- `src/pages/Alerts.tsx` — a paginated, filterable (severity, IP) table of
  alert history.
- `src/pages/AlertDetail.tsx` — one alert's full detail: scores, contributing
  features, the raw feature vector, and an evidence PCAP download link when
  one was retained.

## Building for production

```
npm run build
```

Produces static files in `dist/`. This dashboard was set up to run against a
separate dev server rather than be served by FastAPI itself, so serving
`dist/` (e.g. via any static file host, or wiring it into `api/app.py` later
with FastAPI's `StaticFiles`) is a separate step, not done here.
