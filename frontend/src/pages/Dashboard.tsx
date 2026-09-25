import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api/client";
import type {
  InterfaceOut,
  ModelFileOut,
  PcapFileOut,
  SeverityCounts,
  StatusResponse,
} from "../api/types";
import { CaptureStateBadge } from "../components/StatusBadge";
import SeverityChart from "../components/SeverityChart";

const POLL_MS = 2000;

export default function Dashboard() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [counts, setCounts] = useState<SeverityCounts | null>(null);
  const [interfaces, setInterfaces] = useState<InterfaceOut[]>([]);
  const [interfacesError, setInterfacesError] = useState<string | null>(null);
  const [pcapFiles, setPcapFiles] = useState<PcapFileOut[]>([]);
  const [modelFiles, setModelFiles] = useState<ModelFileOut[]>([]);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Form state for starting a session.
  const [mode, setMode] = useState<"interface" | "pcap">("interface");
  const [interfaceName, setInterfaceName] = useState("");
  const [pcapPath, setPcapPath] = useState("");
  const [bpf, setBpf] = useState("");
  const [promiscuous, setPromiscuous] = useState(false);

  // Which model to use: load a previously saved one (skips training), or
  // train a fresh baseline this session and optionally save the result.
  const [modelMode, setModelMode] = useState<"train" | "load">("train");
  const [modelToLoad, setModelToLoad] = useState("");
  const [modelSaveName, setModelSaveName] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [nextStatus, nextCounts] = await Promise.all([api.getStatus(), api.alertStats()]);
      setStatus(nextStatus);
      setCounts(nextCounts);
    } catch (err) {
      // A transient failure here shouldn't blank the page; keep the last
      // good snapshot and let the next poll try again.
      console.error("Failed to refresh status", err);
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  useEffect(() => {
    api
      .listInterfaces()
      .then((list) => {
        setInterfaces(list);
        if (list.length > 0) setInterfaceName((current) => current || list[0].name);
      })
      .catch((err) => {
        // Common on a machine without capture privileges/Npcap; not fatal,
        // since PCAP replay still works without any interfaces listed.
        setInterfacesError(err instanceof ApiError ? err.message : String(err));
      });
  }, []);

  useEffect(() => {
    api
      .listPcaps()
      .then(setPcapFiles)
      .catch((err) => {
        // Not fatal either: the field still accepts a typed filename or full
        // path even if the server's pcap_dir can't be listed for some reason.
        console.error("Failed to list available PCAP files", err);
      });
  }, []);

  const refreshModels = useCallback(() => {
    api
      .listModels()
      .then((list) => {
        setModelFiles(list);
        if (list.length > 0) setModelToLoad((current) => current || list[0].name);
      })
      .catch((err) => {
        console.error("Failed to list saved models", err);
      });
  }, []);

  useEffect(() => {
    refreshModels();
  }, [refreshModels]);

  async function handleStart() {
    setActionError(null);
    setBusy(true);
    try {
      const next = await api.startCapture({
        interface: mode === "interface" ? interfaceName || null : null,
        pcap: mode === "pcap" ? pcapPath || null : null,
        bpf: bpf || null,
        promiscuous,
        model_path: modelMode === "load" ? modelToLoad || null : null,
        model_save_path: modelMode === "train" ? modelSaveName || null : null,
      });
      setStatus(next);
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleStop() {
    setActionError(null);
    setBusy(true);
    try {
      const next = await api.stopCapture();
      setStatus(next);
      // A model saved during this session now shows up in the load list.
      refreshModels();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const isRunning = status?.state === "running" || status?.state === "stopping";

  return (
    <div className="page">
      <h1>Dashboard</h1>

      <section className="card">
        <h2>Pipeline status</h2>
        {status ? (
          <div className="status-grid">
            <div>
              <span className="field-label">State</span>
              <CaptureStateBadge state={status.state} />
            </div>
            <div>
              <span className="field-label">Source</span>
              <span>{status.source ?? "—"}</span>
            </div>
            <div>
              <span className="field-label">Baseline ready</span>
              <span>{status.is_ready ? "Yes" : "Learning…"}</span>
            </div>
            <div>
              <span className="field-label">Active flows</span>
              <span>{status.active_flow_count}</span>
            </div>
            <div>
              <span className="field-label">Evicted flows</span>
              <span>{status.evicted_flow_count}</span>
            </div>
            <div>
              <span className="field-label">Alert threshold</span>
              <span>{status.threshold.toFixed(3)}</span>
            </div>
            {status.started_at && (
              <div>
                <span className="field-label">Started</span>
                <span>{new Date(status.started_at).toLocaleString()}</span>
              </div>
            )}
            {status.model_save_path && (
              <div className="full-width">
                <span className="field-label">Model save path</span>
                <span className="mono">{status.model_save_path}</span>
              </div>
            )}
            {status.error && (
              <div className="full-width error-text">
                <span className="field-label">Error</span>
                <span>{status.error}</span>
              </div>
            )}
          </div>
        ) : (
          <p>Loading…</p>
        )}
      </section>

      <section className="card">
        <h2>Capture control</h2>
        {interfacesError && (
          <p className="hint">
            Couldn't list capture interfaces ({interfacesError}). You can still replay a PCAP file
            below.
          </p>
        )}
        <div className="mode-toggle">
          <label>
            <input
              type="radio"
              checked={mode === "interface"}
              onChange={() => setMode("interface")}
              disabled={isRunning}
            />
            Live interface
          </label>
          <label>
            <input
              type="radio"
              checked={mode === "pcap"}
              onChange={() => setMode("pcap")}
              disabled={isRunning}
            />
            PCAP file
          </label>
        </div>

        {mode === "interface" ? (
          <label className="field">
            Interface
            <select
              value={interfaceName}
              onChange={(e) => setInterfaceName(e.target.value)}
              disabled={isRunning || interfaces.length === 0}
            >
              {interfaces.length === 0 && <option value="">No interfaces found</option>}
              {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.name}
                  {iface.ip_address ? ` (${iface.ip_address})` : ""} — {iface.description}
                </option>
              ))}
            </select>
          </label>
        ) : (
          <label className="field">
            PCAP file
            <input
              type="text"
              list="pcap-file-options"
              value={pcapPath}
              onChange={(e) => setPcapPath(e.target.value)}
              placeholder="traffic.pcap"
              disabled={isRunning}
            />
            <datalist id="pcap-file-options">
              {pcapFiles.map((file) => (
                <option key={file.name} value={file.name} />
              ))}
            </datalist>
            <span className="hint">
              {pcapFiles.length > 0
                ? "Pick a file from the server's configured PCAP folder, or type a full path for one kept elsewhere."
                : "Just the filename — it's looked up in the server's configured PCAP folder. A full path also works for a file kept elsewhere."}
            </span>
          </label>
        )}

        <label className="field">
          BPF filter (optional)
          <input
            type="text"
            value={bpf}
            onChange={(e) => setBpf(e.target.value)}
            placeholder="tcp or udp"
            disabled={isRunning}
          />
        </label>

        <label className="checkbox-field">
          <input
            type="checkbox"
            checked={promiscuous}
            onChange={(e) => setPromiscuous(e.target.checked)}
            disabled={isRunning}
          />
          Promiscuous mode
        </label>

        <div className="mode-toggle">
          <label>
            <input
              type="radio"
              checked={modelMode === "train"}
              onChange={() => setModelMode("train")}
              disabled={isRunning}
            />
            Train a new baseline
          </label>
          <label>
            <input
              type="radio"
              checked={modelMode === "load"}
              onChange={() => setModelMode("load")}
              disabled={isRunning || modelFiles.length === 0}
            />
            Load a saved model
          </label>
        </div>

        {modelMode === "train" ? (
          <label className="field">
            Save the trained model as (optional)
            <input
              type="text"
              value={modelSaveName}
              onChange={(e) => setModelSaveName(e.target.value)}
              placeholder="trained.joblib"
              disabled={isRunning}
            />
            <span className="hint">
              Leave blank to train from scratch every time, same as before. Set this once and
              you can load it back with "Load a saved model" on the next run instead of
              retraining.
            </span>
          </label>
        ) : (
          <label className="field">
            Model to load
            <select
              value={modelToLoad}
              onChange={(e) => setModelToLoad(e.target.value)}
              disabled={isRunning || modelFiles.length === 0}
            >
              {modelFiles.length === 0 && <option value="">No saved models found</option>}
              {modelFiles.map((file) => (
                <option key={file.name} value={file.name}>
                  {file.name}
                </option>
              ))}
            </select>
            <span className="hint">
              Skips baseline training entirely — the pipeline starts scoring traffic against
              this model right away.
            </span>
          </label>
        )}

        {actionError && <p className="error-text">{actionError}</p>}

        <div className="button-row">
          <button
            onClick={handleStart}
            disabled={
              busy ||
              isRunning ||
              (mode === "interface" && !interfaceName) ||
              (modelMode === "load" && !modelToLoad)
            }
          >
            Start capture
          </button>
          <button onClick={handleStop} disabled={busy || !isRunning} className="secondary">
            Stop capture
          </button>
        </div>
      </section>

      <section className="card">
        <h2>Alerts by severity</h2>
        {counts ? <SeverityChart counts={counts} /> : <p>Loading…</p>}
      </section>
    </div>
  );
}
