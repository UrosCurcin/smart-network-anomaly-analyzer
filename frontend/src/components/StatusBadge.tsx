import type { CaptureState, Severity } from "../api/types";

const STATE_LABEL: Record<CaptureState, string> = {
  idle: "Idle",
  running: "Running",
  stopping: "Stopping",
  failed: "Failed",
};

export function CaptureStateBadge({ state }: { state: CaptureState }) {
  return <span className={`badge state-${state}`}>{STATE_LABEL[state]}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge severity-${severity}`}>{severity}</span>;
}
