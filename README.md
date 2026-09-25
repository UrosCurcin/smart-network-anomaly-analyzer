# Smart Network Anomaly Analyzer

A network anomaly detection pipeline: it captures packets (live or from a
`.pcap` file), groups them into per-flow time windows, extracts 14 numeric
features per window, and scores each window with an unsupervised
**Isolation Forest** model. Windows that score high enough raise an alert,
with a small evidence `.pcap` of the exact packets involved. A FastAPI
backend exposes this as a REST API, and a React/TypeScript dashboard
(`frontend/`) drives it and browses alert history.

See `Smart network anomaly analyzer documentation.pdf` (or the shared
walkthrough doc) for a full plain-language explanation of how every piece
works -- this README only covers getting it running.

## Prerequisites

- Python 3.10+
- Node.js 18+ and npm (for the dashboard)
- On Windows, packet capture needs [Npcap](https://npcap.com/) installed
  (WinPcap-compatible mode). On Linux/macOS, live capture needs elevated
  privileges (`sudo`) or the appropriate capabilities on the Python
  interpreter; PCAP replay needs neither.

## Backend setup

From the project root:

```powershell
python -m venv .venv
.venv\Scripts\activate          # or: source .venv/bin/activate on Linux/macOS
pip install -e .[dev,api]
```

This installs the package in **editable** mode, so edits under `src/`
take effect immediately without reinstalling.

## Running it

Replay a PCAP file straight from the CLI (trains a fresh baseline, then
scores and alerts on the rest of the file):

```powershell
sn-analyzer --config configs/default.yaml --pcap logs\mixed_traffic_test.pcap
```

Or run the full API + dashboard together, in two terminals:

```powershell
# Terminal 1 -- backend API (http://127.0.0.1:8000, docs at /docs)
sn-analyzer-api --config configs\default.yaml

# Terminal 2 -- dashboard (http://localhost:5173)
cd frontend
npm install
npm run dev
```

Open the dashboard, pick a PCAP file or a live interface, choose whether to
train a new baseline or load a previously saved model, and hit **Start
capture**. Alerts appear on the **Alerts** page as the model flags them.

## Running the tests

```powershell
pytest
```

`pytest.ini` points `pythonpath` at `src` and `testpaths` at `tests`, so this
works from the project root with no extra flags. The suite covers feature
extraction, stream demultiplexing, the Isolation Forest model (including
save/load round-trips), the alert manager and repository (including the
mark-observed / delete / clear-all alert history endpoints), the config
loader, and the FastAPI app's endpoints.

## Configuration

`configs/default.yaml` documents every setting inline. The short version of
what's worth tuning:

| Setting | Default | What it controls |
|---|---|---|
| `analysis.threshold` | 0.80 | Anomaly score (0-1) at/above which an alert fires |
| `analysis.window_packets` / `window_seconds` | 50 / 30.0 | A flow window closes on whichever limit hits first |
| `analysis.bootstrap_windows` | 100 | How many early windows train the baseline before scoring starts |
| `analysis.alert_cooldown_seconds` | 300.0 | Suppresses repeat alerts from the same flow within this window |
| `storage.database_path` | `data/alerts.db` | Where alert history is persisted |
| `storage.evidence_dir` | `artifacts/evidence` | Where per-alert evidence `.pcap` files are written |

Settings layer as: built-in defaults -> `configs/default.yaml` -> environment
variables (`SN_<SECTION>__<FIELD>`, e.g. `SN_ANALYSIS__THRESHOLD=0.9`) ->
explicit CLI flags/API request fields. Run `sn-analyzer --help` for the full
flag list.

## Project layout

```
src/sn_analyzer/
  ingestion/      live capture + PCAP replay, stream demultiplexing
  features/       per-window feature extraction (14-value vectors)
  models/         the Isolation Forest model (fit/score/save/load)
  inference/      ensemble scoring + decision threshold
  alerting/       alert creation, severity, cooldown, evidence export, sinks
  storage/        SQLite alert repository
  api/            FastAPI app, routers, request/response schemas
  cli.py          the AnalyzerService pipeline + `sn-analyzer` entry point
frontend/         React + TypeScript dashboard (see frontend/README.md)
tests/            pytest suite mirroring the src/ layout
configs/          YAML configuration
```

## Known limitations / not yet built

Worth knowing (and saying out loud, rather than discovering the hard way):

- **No authentication on the API.** Anyone who can reach the backend can
  start/stop capture and read/delete alert history.
- **The model trains once per session and doesn't adapt afterward.** If
  normal traffic patterns genuinely shift over time, accuracy will drift;
  there's no periodic/continuous retraining.
- **Only one model is registered** (Isolation Forest), even though the
  inference engine is built to support a weighted ensemble of several.
- **No packaging/deployment story** (no Dockerfile, no process manager
  config) -- it's run directly with `sn-analyzer-api` today.
- **The baseline/bootstrap phase must see representative "normal" traffic.**
  If it's dominated by one flow type, the model won't recognize other
  ordinary traffic as normal either (see the config table above --
  `bootstrap_windows` and how it's filled matters a lot).
