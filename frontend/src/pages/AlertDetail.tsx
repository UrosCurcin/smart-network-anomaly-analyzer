import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError } from "../api/client";
import type { AlertOut } from "../api/types";
import { SeverityBadge } from "../components/StatusBadge";

export default function AlertDetail() {
  const { alertId } = useParams<{ alertId: string }>();
  const navigate = useNavigate();
  const [alert, setAlert] = useState<AlertOut | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!alertId) return;
    setAlert(null);
    setError(null);
    api
      .getAlert(alertId)
      .then(setAlert)
      .catch((err) => setError(err instanceof ApiError ? err.message : String(err)));
  }, [alertId]);

  async function toggleAcknowledged() {
    if (!alert) return;
    setActionError(null);
    setBusy(true);
    try {
      setAlert(await api.acknowledgeAlert(alert.alert_id, !alert.acknowledged));
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function deleteThisAlert() {
    if (!alert) return;
    if (!window.confirm("Delete this alert and its evidence PCAP? This cannot be undone.")) {
      return;
    }
    setActionError(null);
    setBusy(true);
    try {
      await api.deleteAlert(alert.alert_id);
      navigate("/alerts");
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
      setBusy(false);
    }
  }

  if (error) {
    return (
      <div className="page">
        <p className="error-text">{error}</p>
        <Link to="/alerts">Back to alerts</Link>
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="page">
        <p>Loading…</p>
      </div>
    );
  }

  return (
    <div className="page">
      <Link to="/alerts" className="back-link">
        &larr; Back to alerts
      </Link>
      <div className="page-header">
        <h1>
          Alert <span className="mono">{alert.alert_id}</span>
        </h1>
        <div className="button-row">
          <button className="secondary" disabled={busy} onClick={toggleAcknowledged}>
            {alert.acknowledged ? "Unmark observed" : "Mark observed"}
          </button>
          <button className="secondary danger" disabled={busy} onClick={deleteThisAlert}>
            Delete alert
          </button>
        </div>
      </div>
      {actionError && <p className="error-text">{actionError}</p>}

      <section className="card">
        <div className="status-grid">
          <div>
            <span className="field-label">Severity</span>
            <SeverityBadge severity={alert.severity} />
          </div>
          <div>
            <span className="field-label">Anomaly score</span>
            <span>{alert.anomaly_score.toFixed(4)}</span>
          </div>
          <div>
            <span className="field-label">Observed</span>
            <span>{alert.acknowledged ? "Yes" : "Not yet"}</span>
          </div>
          <div>
            <span className="field-label">Created</span>
            <span>{new Date(alert.created_at).toLocaleString()}</span>
          </div>
          <div>
            <span className="field-label">Window end</span>
            <span>{new Date(alert.window_end).toLocaleString()}</span>
          </div>
          <div>
            <span className="field-label">Protocol</span>
            <span>{alert.protocol}</span>
          </div>
          <div className="full-width">
            <span className="field-label">Flow</span>
            <span className="mono">
              {alert.endpoint_a.address}
              {alert.endpoint_a.port !== null ? `:${alert.endpoint_a.port}` : ""} &harr;{" "}
              {alert.endpoint_b.address}
              {alert.endpoint_b.port !== null ? `:${alert.endpoint_b.port}` : ""}
            </span>
          </div>
          <div className="full-width">
            <span className="field-label">Suspicious IPs</span>
            <span className="mono">{alert.suspicious_ips.join(", ") || "—"}</span>
          </div>
        </div>
      </section>

      <section className="card">
        <h2>Evidence</h2>
        {alert.evidence_available ? (
          <a href={api.evidenceUrl(alert.alert_id)} download>
            Download evidence PCAP
          </a>
        ) : (
          <p>No evidence was retained for this alert.</p>
        )}
      </section>

      <section className="card">
        <h2>Model scores</h2>
        <table className="kv-table">
          <tbody>
            {Object.entries(alert.model_scores).map(([model, score]) => (
              <tr key={model}>
                <td>{model}</td>
                <td>{score.toFixed(4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2>Contributing features</h2>
        {alert.contributing_features.length > 0 ? (
          <ul>
            {alert.contributing_features.map((feature) => (
              <li key={feature}>{feature}</li>
            ))}
          </ul>
        ) : (
          <p>None recorded.</p>
        )}
      </section>

      <section className="card">
        <h2>Feature vector</h2>
        <table className="kv-table">
          <tbody>
            {alert.feature_names.map((name, i) => (
              <tr key={name}>
                <td>{name}</td>
                <td>{alert.feature_values[i]?.toFixed(4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
