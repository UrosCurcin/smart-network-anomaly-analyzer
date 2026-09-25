import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../api/client";
import type { AlertOut, Severity } from "../api/types";
import { SeverityBadge } from "../components/StatusBadge";

const PAGE_SIZE = 25;
type ObservedFilter = "" | "unobserved" | "observed";

export default function Alerts() {
  const [items, setItems] = useState<AlertOut[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [severity, setSeverity] = useState<Severity | "">("");
  const [ip, setIp] = useState("");
  const [observed, setObserved] = useState<ObservedFilter>("");
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [clearing, setClearing] = useState(false);

  const acknowledged = observed === "" ? undefined : observed === "observed";

  const refresh = useCallback(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .listAlerts({
        limit: PAGE_SIZE,
        offset,
        severity: severity || undefined,
        ip: ip || undefined,
        acknowledged,
      })
      .then((response) => {
        if (cancelled) return;
        setItems(response.items);
        setTotal(response.total);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [offset, severity, ip, acknowledged]);

  useEffect(() => refresh(), [refresh]);

  function updateFilter<T>(setter: (value: T) => void) {
    return (value: T) => {
      setOffset(0);
      setter(value);
    };
  }

  async function toggleAcknowledged(alert: AlertOut) {
    setActionError(null);
    setBusyId(alert.alert_id);
    try {
      await api.acknowledgeAlert(alert.alert_id, !alert.acknowledged);
      refresh();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusyId(null);
    }
  }

  async function deleteOne(alert: AlertOut) {
    if (!window.confirm("Delete this alert and its evidence PCAP? This cannot be undone.")) {
      return;
    }
    setActionError(null);
    setBusyId(alert.alert_id);
    try {
      await api.deleteAlert(alert.alert_id);
      refresh();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusyId(null);
    }
  }

  async function emptyAllAlerts() {
    if (
      !window.confirm(
        `Delete all ${total} alert(s) and every evidence PCAP on disk? This cannot be undone.`
      )
    ) {
      return;
    }
    setActionError(null);
    setClearing(true);
    try {
      await api.clearAlerts();
      setOffset(0);
      refresh();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setClearing(false);
    }
  }

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="page">
      <div className="page-header">
        <h1>Alerts</h1>
        <button
          className="secondary danger"
          onClick={emptyAllAlerts}
          disabled={clearing || total === 0}
        >
          {clearing ? "Emptying…" : "Empty all alerts"}
        </button>
      </div>

      <section className="card">
        <div className="filter-row">
          <label className="field">
            Severity
            <select
              value={severity}
              onChange={(e) => updateFilter(setSeverity)(e.target.value as Severity | "")}
            >
              <option value="">All</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
          <label className="field">
            IP address
            <input
              type="text"
              value={ip}
              onChange={(e) => updateFilter(setIp)(e.target.value)}
              placeholder="e.g. 10.0.0.5"
            />
          </label>
          <label className="field">
            Observed
            <select
              value={observed}
              onChange={(e) => updateFilter(setObserved)(e.target.value as ObservedFilter)}
            >
              <option value="">All</option>
              <option value="unobserved">Not yet observed</option>
              <option value="observed">Observed</option>
            </select>
          </label>
        </div>

        {error && <p className="error-text">{error}</p>}
        {actionError && <p className="error-text">{actionError}</p>}

        <table className="alert-table">
          <thead>
            <tr>
              <th>Created</th>
              <th>Severity</th>
              <th>Score</th>
              <th>Protocol</th>
              <th>Flow</th>
              <th>Evidence</th>
              <th>Observed</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((alert) => (
              <tr key={alert.alert_id} className={alert.acknowledged ? "row-observed" : ""}>
                <td>{new Date(alert.created_at).toLocaleString()}</td>
                <td>
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td>{alert.anomaly_score.toFixed(3)}</td>
                <td>{alert.protocol}</td>
                <td className="mono">
                  {alert.endpoint_a.address}
                  {alert.endpoint_a.port !== null ? `:${alert.endpoint_a.port}` : ""} &harr;{" "}
                  {alert.endpoint_b.address}
                  {alert.endpoint_b.port !== null ? `:${alert.endpoint_b.port}` : ""}
                </td>
                <td>{alert.evidence_available ? "Yes" : "—"}</td>
                <td>{alert.acknowledged ? "Yes" : "—"}</td>
                <td className="row-actions">
                  <Link to={`/alerts/${alert.alert_id}`}>Details</Link>
                  <button
                    className="secondary small"
                    disabled={busyId === alert.alert_id}
                    onClick={() => toggleAcknowledged(alert)}
                  >
                    {alert.acknowledged ? "Unmark" : "Mark observed"}
                  </button>
                  <button
                    className="secondary small danger"
                    disabled={busyId === alert.alert_id}
                    onClick={() => deleteOne(alert)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={8} className="empty-row">
                  No alerts match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>

        <div className="pagination">
          <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
            Previous
          </button>
          <span>
            Page {page} of {pageCount} ({total} total)
          </span>
          <button
            disabled={offset + PAGE_SIZE >= total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Next
          </button>
        </div>
      </section>
    </div>
  );
}
