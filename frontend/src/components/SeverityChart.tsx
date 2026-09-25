import type { SeverityCounts } from "../api/types";

const ORDER: (keyof SeverityCounts)[] = ["low", "medium", "high", "critical"];

/** A small hand-rolled horizontal bar chart. Pulling in a charting library for
 * four bars isn't worth the dependency; this keeps the frontend's install
 * light and avoids pinning yet another package version. */
export default function SeverityChart({ counts }: { counts: SeverityCounts }) {
  const max = Math.max(1, ...ORDER.map((key) => counts[key]));

  return (
    <div className="severity-chart">
      {ORDER.map((key) => {
        const value = counts[key];
        const widthPct = (value / max) * 100;
        return (
          <div className="severity-row" key={key}>
            <span className={`severity-label severity-${key}`}>{key}</span>
            <div className="severity-track">
              <div className={`severity-fill severity-${key}`} style={{ width: `${widthPct}%` }} />
            </div>
            <span className="severity-count">{value}</span>
          </div>
        );
      })}
    </div>
  );
}
