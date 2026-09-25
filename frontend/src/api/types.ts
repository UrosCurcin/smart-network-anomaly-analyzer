// These mirror src/sn_analyzer/api/schemas.py field-for-field. If you add or
// rename a field on the backend, update the matching type here too — nothing
// enforces that the two stay in sync automatically.

export type Severity = "low" | "medium" | "high" | "critical";

export type CaptureState = "idle" | "running" | "stopping" | "failed";

export interface EndpointOut {
  address: string;
  port: number | null;
}

export interface AlertOut {
  alert_id: string;
  created_at: string; // ISO 8601
  severity: Severity;
  anomaly_score: number;
  window_end: string; // ISO 8601
  protocol: string;
  endpoint_a: EndpointOut;
  endpoint_b: EndpointOut;
  suspicious_ips: string[];
  evidence_available: boolean;
  acknowledged: boolean;
  model_scores: Record<string, number>;
  contributing_features: string[];
  feature_names: string[];
  feature_values: number[];
  packet_ids: number[];
}

export interface AlertListResponse {
  items: AlertOut[];
  total: number;
  limit: number;
  offset: number;
}

export interface SeverityCounts {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface InterfaceOut {
  name: string;
  description: string;
  ip_address: string | null;
}

export interface PcapFileOut {
  name: string;
}

export interface ModelFileOut {
  name: string;
}

export interface StatusResponse {
  state: CaptureState;
  source: string | null;
  started_at: string | null;
  error: string | null;
  is_ready: boolean;
  active_flow_count: number;
  evicted_flow_count: number;
  threshold: number;
  model_save_path: string | null;
}

export interface StartCaptureRequest {
  interface?: string | null;
  pcap?: string | null;
  bpf?: string | null;
  promiscuous?: boolean | null;
  model_path?: string | null;
  model_save_path?: string | null;
}

export interface AlertFilters {
  limit?: number;
  offset?: number;
  severity?: Severity | "";
  ip?: string;
  since?: string; // ISO 8601, timezone-aware
  until?: string; // ISO 8601, timezone-aware
  acknowledged?: boolean;
}

export interface ClearAlertsResponse {
  deleted: number;
}
