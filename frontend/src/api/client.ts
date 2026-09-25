import type {
  AlertFilters,
  AlertListResponse,
  AlertOut,
  ClearAlertsResponse,
  InterfaceOut,
  ModelFileOut,
  PcapFileOut,
  SeverityCounts,
  StartCaptureRequest,
  StatusResponse,
} from "./types";

/** All requests go through the "/api" prefix, which Vite's dev server proxies
 * to the FastAPI backend (see vite.config.ts). In a production build served
 * by something other than Vite, point this at the real API origin instead. */
const BASE = "/api";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    // FastAPI's HTTPException bodies look like {"detail": "..."}.
    let detail = response.statusText;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      // Body wasn't JSON (or was empty); fall back to the status text.
    }
    throw new ApiError(response.status, detail);
  }
  // 204/empty responses never occur in this API today, but guard anyway.
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

function toQuery(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const query = search.toString();
  return query ? `?${query}` : "";
}

export const api = {
  health: () => request<{ status: string }>("/health"),

  getStatus: () => request<StatusResponse>("/status"),

  listInterfaces: () => request<InterfaceOut[]>("/capture/interfaces"),

  /** Files found in the server's configured `capture.pcap_dir`. Pass just the
   * `name` back in `startCapture({ pcap })` — no need to build a full path. */
  listPcaps: () => request<PcapFileOut[]>("/capture/pcaps"),

  /** Saved model artifacts (`*.joblib`) in the server's configured
   * `model.model_dir`. Pass a `name` back in `startCapture({ model_path })`
   * to load one instead of training a fresh baseline. */
  listModels: () => request<ModelFileOut[]>("/capture/models"),

  startCapture: (body: StartCaptureRequest) =>
    request<StatusResponse>("/capture/start", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  stopCapture: () => request<StatusResponse>("/capture/stop", { method: "POST" }),

  listAlerts: (filters: AlertFilters) =>
    request<AlertListResponse>(
      `/alerts${toQuery({
        limit: filters.limit,
        offset: filters.offset,
        severity: filters.severity,
        ip: filters.ip,
        since: filters.since,
        until: filters.until,
        acknowledged: filters.acknowledged,
      })}`
    ),

  alertStats: () => request<SeverityCounts>("/alerts/stats"),

  getAlert: (alertId: string) => request<AlertOut>(`/alerts/${encodeURIComponent(alertId)}`),

  /** Marks one alert observed (or, with `acknowledged: false`, clears that mark). */
  acknowledgeAlert: (alertId: string, acknowledged = true) =>
    request<AlertOut>(`/alerts/${encodeURIComponent(alertId)}/acknowledge`, {
      method: "POST",
      body: JSON.stringify({ acknowledged }),
    }),

  /** Deletes one alert and its evidence PCAP, if it has one. Cannot be undone. */
  deleteAlert: (alertId: string) =>
    request<void>(`/alerts/${encodeURIComponent(alertId)}`, { method: "DELETE" }),

  /** Empties the whole alert history and removes every evidence PCAP. Cannot be undone. */
  clearAlerts: () => request<ClearAlertsResponse>("/alerts", { method: "DELETE" }),

  /** Returns the evidence download URL directly; the browser handles the
   * actual file transfer (via an <a href> or window.open), so this isn't
   * routed through `request`, which assumes a JSON body. */
  evidenceUrl: (alertId: string) => `${BASE}/alerts/${encodeURIComponent(alertId)}/evidence`,
};
