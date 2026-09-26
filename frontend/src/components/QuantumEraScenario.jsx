import { useEffect, useMemo, useState } from "react";
import { calculateProjectScenarioRisk } from "../lib/scenarioRisk";

export default function QuantumEraScenario({ artifacts, onScenarioChange }) {
  const [assumedEra, setAssumedEra] = useState(2040);
  const scenario = useMemo(
    () => calculateProjectScenarioRisk(artifacts, assumedEra),
    [artifacts, assumedEra]
  );

  useEffect(() => {
    onScenarioChange?.({ ...scenario, assumedQuantumYear: assumedEra });
  }, [assumedEra, onScenarioChange, scenario]);

  return (
    <section className="quantum-era-scenario">
      <div className="quantum-era-header">
        <div className="quantum-era-heading-wrap">
          <h2>Quantum arrival estimate (Z)</h2>
          <p>Scenario risk uses the selected quantum-era year. Scanner base risk does not change.</p>
        </div>
        <label className="quantum-era-selector">
          <span>ASSUMED QUANTUM ERA</span>
          <div className="quantum-era-selector-controls">
            <span className="quantum-era-selected-year">{assumedEra}</span>
            <input
              aria-label="Assumed quantum era"
              type="range"
              min="2030"
              max="2050"
              step="1"
              value={assumedEra}
              onChange={(event) => setAssumedEra(Number(event.target.value))}
            />
            <div className="quantum-era-range-labels">
              <span>2030</span>
              <span>2050</span>
            </div>
          </div>
        </label>
      </div>
      <div className="quantum-era-risk-grid">
        <div className={`quantum-era-risk-card ${scenario.overallRisk.toLowerCase()}`}>
          <span>SCENARIO RISK</span>
          <strong>{scenario.overallRisk}</strong>
          <small>{scenario.evaluations.length} assets</small>
        </div>
        <div className="quantum-era-risk-card exposure">
          <span>RISK EXPOSURE</span>
          <strong>{scenario.riskPercentage}%</strong>
          <small>assets at risk</small>
        </div>
        <div className="quantum-era-risk-card quantum">
          <span>QUANTUM EXPOSURE</span>
          <strong>{scenario.quantumExposure}</strong>
          <small>vulnerable assets</small>
        </div>
        <div className="quantum-era-risk-card legacy">
          <span>LEGACY WEAKNESS</span>
          <strong>{scenario.legacyWeakness}</strong>
          <small>legacy / weak assets</small>
        </div>
      </div>
    </section>
  );
}
