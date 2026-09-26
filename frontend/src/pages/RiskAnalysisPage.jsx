import { useMemo, useState } from "react";
import { Hash } from "lucide-react";

import QuantumEraScenario from "../components/QuantumEraScenario";
import { CRITICALITY_ORDER, URGENCY_ORDER } from "../utils/moscaScenario";
import {
  EmptyAnalysisState,
  MetricGrid,
  PaginationBar,
} from "./analysisPageUtils";
import { PAGE_SIZE, useCurrentScan } from "./analysisData";
import { getArtifactHash, formatShortHashNumber } from "../utils/cryptoHash";

export default function RiskAnalysisPage() {
  const result = useCurrentScan();
  const [scenario, setScenario] = useState(null);
  const [filter, setFilter] = useState(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const evaluations = useMemo(() => scenario?.evaluations || [], [scenario]);
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return evaluations.filter((item) => {
      const matchesCell = !filter || (
        item.criticality === filter.criticality && item.urgency === filter.urgency
      );
      const haystack = [
        item.artifact.file,
        item.artifact.algorithm,
        item.artifact.category,
        item.baseRisk,
        item.scenarioRisk,
      ].filter(Boolean).join(" ").toLowerCase();
      return matchesCell && (!query || haystack.includes(query));
    });
  }, [evaluations, filter, search]);
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE) || 1;
  const currentPage = Math.min(page, totalPages);
  const rows = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
  const artifacts = result?.artifacts || [];

  return (
    <div className="risk-analysis-viewport">
      {!result ? <EmptyAnalysisState /> : (
        <>
          <section className={`risk-banner ${(scenario?.overallRisk || "LOW").toLowerCase()}`}>
            <span>Overall quantum risk</span>
            <strong>{scenario?.overallRisk || "LOW"}</strong>
            <p>
              {scenario?.evaluations?.filter((item) => ["CRITICAL", "HIGH"].includes(item.scenarioRisk)).length || 0} components require attention based on the current scan and assumed quantum year {scenario?.assumedQuantumYear || "—"}.
            </p>
          </section>
          <MetricGrid cards={[
            ["Risk exposure", `${scenario?.riskPercentage ?? 0}%`],
            ["Quantum exposure", scenario?.quantumExposure ?? 0],
            ["Legacy weakness", scenario?.legacyWeakness ?? 0],
            ["Affected assets", artifacts.length],
          ]} />
          <QuantumEraScenario artifacts={artifacts} onScenarioChange={setScenario} />
          <section className="analysis-panel">
            <div className="analysis-panel-heading">
              <div>
                <h2>2D Mosca Risk Heatmap Matrix</h2>
                <p>Interactive 4×4 matrix plotting Mosca Urgency Tier vs Business Criticality. Click any cell to filter the priority list below.</p>
              </div>
              <button
                type="button"
                className={`btn-reset-matrix-filter ${filter ? "active" : ""}`}
                onClick={() => { setFilter(null); setPage(1); }}
                disabled={!filter}
              >
                Reset Matrix Filter
              </button>
            </div>
            <div className="mosca-heatmap" role="grid" aria-label="2D Mosca Risk Heatmap Matrix">
              <div className="mosca-heatmap-corner">
                <span>CRITICALITY ↓ \</span>
                <span>URGENCY →</span>
              </div>
              {URGENCY_ORDER.map((urgency) => (
                <div key={urgency} className={`mosca-heatmap-head head-${urgency.toLowerCase()}`}>
                  {urgency.charAt(0) + urgency.slice(1).toLowerCase()} Urgency
                </div>
              ))}
              {CRITICALITY_ORDER.map((criticality) => [
                <div key={`${criticality}-label`} className={`mosca-heatmap-row-label row-${criticality.toLowerCase()}`}>
                  {criticality.charAt(0) + criticality.slice(1).toLowerCase()} Criticality
                </div>,
                ...URGENCY_ORDER.map((urgency) => {
                  const count = scenario?.heatmap?.[criticality]?.[urgency] || 0;
                  const selected = filter?.criticality === criticality && filter?.urgency === urgency;
                  return (
                    <button
                      type="button"
                      key={`${criticality}-${urgency}`}
                      className={`mosca-cell cell-${criticality.toLowerCase()}-${urgency.toLowerCase()} ${selected ? "selected" : ""}`}
                      onClick={() => {
                        setFilter((prev) => (prev?.criticality === criticality && prev?.urgency === urgency ? null : { criticality, urgency }));
                        setPage(1);
                      }}
                      title={`${criticality} Criticality / ${urgency} Urgency: ${count} finding${count === 1 ? "" : "s"}${selected ? " (Click to clear filter)" : ""}`}
                    >
                      <strong>{count}</strong>
                      <span>{count === 1 ? "finding" : "findings"}</span>
                    </button>
                  );
                }),
              ])}
            </div>
          </section>
          <section className="analysis-panel">
            <div className="analysis-panel-heading">
              <div>
                <h2>Priority-ranked findings</h2>
                <p>X = data lifetime, Y = migration time, Z = years until the assumed quantum era. Unavailable fields use documented fallbacks.</p>
                {filter && (
                  <div className="active-matrix-filter-pill" style={{ marginTop: "6px" }}>
                    <span>Showing <strong>{filter.criticality} Criticality / {filter.urgency} Urgency</strong></span>
                    <button
                      type="button"
                      className="btn-clear-matrix-pill"
                      onClick={() => setFilter(null)}
                      title="Clear filter"
                      aria-label="Clear filter"
                    >
                      ×
                    </button>
                  </div>
                )}
              </div>
              <input
                className="analysis-search"
                value={search}
                onChange={(event) => { setSearch(event.target.value); setPage(1); }}
                placeholder="Search findings"
                aria-label="Search risk findings"
              />
            </div>
            <div className="analysis-table-wrap">
              <table className="analysis-table">
                <thead>
                  <tr>
                    <th>Finding / location</th>
                    <th>Base</th>
                    <th>Scenario</th>
                    <th>X</th>
                    <th>Y</th>
                    <th>Z</th>
                    <th>Margin</th>
                    <th>Urgency</th>
                    <th>Criticality</th>
                    <th>Score</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.length ? rows.map((item, index) => {
                    const artHash = getArtifactHash(item.artifact, index);
                    const shortHash = formatShortHashNumber(artHash, 8);

                    return (
                      <tr key={`${item.artifact.file}-${item.artifact.line}-${index}`}>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                            <strong>{item.artifact.algorithm || item.artifact.category || "Artifact"}</strong>
                            <span className="hash-tag-pill" title={`SHA-256: ${artHash}`}>
                              <Hash size={10} />
                              <span>{shortHash}</span>
                            </span>
                          </div>
                          <small>{item.artifact.file || "Unknown file"}{item.artifact.line ? `:${item.artifact.line}` : ""}</small>
                        </td>
                        <td>{item.baseRisk}</td>
                        <td>{item.scenarioRisk}</td>
                        <td>{item.xYears}y</td>
                        <td>{item.yYears}y</td>
                        <td>{item.zYears}y</td>
                        <td>{item.margin}y</td>
                        <td>{item.urgency}</td>
                        <td>{item.criticality}</td>
                        <td>{item.priorityScore}</td>
                      </tr>
                    );
                  }) : (
                    <tr><td colSpan={10}>No matching findings for the current filter.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
            <PaginationBar
              currentPage={currentPage}
              totalPages={totalPages}
              onPageChange={setPage}
              from={filtered.length ? (currentPage - 1) * PAGE_SIZE + 1 : 0}
              to={Math.min(currentPage * PAGE_SIZE, filtered.length)}
              total={filtered.length}
              noun="findings"
            />
          </section>
        </>
      )}
    </div>
  );
}
