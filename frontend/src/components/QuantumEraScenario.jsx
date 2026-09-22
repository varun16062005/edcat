import { useMemo, useState } from "react";

const ERA_OPTIONS = [2030, 2035, 2040, 2045, 2050];

const RISK_ORDER = [
  "CRITICAL",
  "HIGH",
  "ELEVATED",
  "LOW",
];

function baseRiskLabel(risk) {
  const value = String(risk || "").toUpperCase();
  if (value === "CRITICAL") return "CRITICAL";
  if (value === "HIGH") return "HIGH";
  if (value === "MEDIUM") return "ELEVATED";
  if (value === "ELEVATED") return "ELEVATED";
  return "LOW";
}

function quantumScenarioRisk(yearsToQuantum, assumedQuantumYear, currentYear) {
  if (assumedQuantumYear <= currentYear) return "CRITICAL";
  if (yearsToQuantum <= 5) return "CRITICAL";
  if (yearsToQuantum <= 10) return "HIGH";
  if (yearsToQuantum <= 15) return "ELEVATED";
  return "LOW";
}

function emptyCounts() {
  return {
    CRITICAL: 0,
    HIGH: 0,
    ELEVATED: 0,
    LOW: 0,
  };
}

export default function QuantumEraScenario({ artifacts }) {
  const currentYear = new Date().getFullYear();
  const [assumedEra, setAssumedEra] = useState("2040");
  const [customYear, setCustomYear] = useState(String(Math.min(2100, currentYear + 14)));

  const scenario = useMemo(() => {
    const selectedYear = assumedEra === "custom"
      ? Number(customYear)
      : Number(assumedEra);
    const assumedQuantumYear = Number.isFinite(selectedYear)
      ? Math.min(2100, selectedYear)
      : currentYear;
    const yearsToQuantum = assumedQuantumYear - currentYear;
    const counts = emptyCounts();

    artifacts.forEach((artifact) => {
      const isQuantumVulnerable = artifact.quantum_status === "VULNERABLE";
      const scenarioRisk = isQuantumVulnerable
        ? quantumScenarioRisk(yearsToQuantum, assumedQuantumYear, currentYear)
        : baseRiskLabel(artifact.risk);

      counts[scenarioRisk] += 1;
    });

    const overallRisk = RISK_ORDER.find((risk) => counts[risk] > 0) || "NORMAL";
    const totalArtifacts = artifacts.length;
    const quantumExposureCount = artifacts.filter(
      (artifact) => artifact.quantum_status === "VULNERABLE"
    ).length;
    const legacyWeaknessCount = artifacts.filter(
      (artifact) => artifact.quantum_status === "LEGACY_WEAK"
    ).length;
    const scenarioRiskAssets = counts.CRITICAL + counts.HIGH;

    return {
      overallRisk,
      overallCount: overallRisk === "NORMAL" ? 0 : counts[overallRisk],
      riskExposurePercentage: totalArtifacts > 0
        ? Math.round((scenarioRiskAssets / totalArtifacts) * 100)
        : 0,
      quantumExposureCount,
      legacyWeaknessCount,
    };
  }, [artifacts, assumedEra, customYear, currentYear]);

  return (
    <section className="quantum-era-scenario">
      <div className="quantum-era-header">
        <div className="quantum-era-heading-wrap">
          <h2>RISK ANALYSIS</h2>
          <p>Scenario risk based on the selected quantum-era assumption.</p>
        </div>

        <label className="quantum-era-selector">
          <span>ASSUMED QUANTUM ERA</span>
          <div className="quantum-era-selector-controls">
            <select
              aria-label="Assumed quantum era"
              value={assumedEra}
              onChange={(event) => setAssumedEra(event.target.value)}
            >
              {ERA_OPTIONS.map((year) => <option value={year} key={year}>{year}</option>)}
              <option value="custom">Custom</option>
            </select>

            {assumedEra === "custom" ? (
              <input
                aria-label="Custom quantum era year"
                type="number"
                min={currentYear}
                max="2100"
                value={customYear}
                onChange={(event) => setCustomYear(event.target.value)}
              />
            ) : null}
          </div>
        </label>
      </div>

      <div className="quantum-era-risk-grid">
        <div className={`quantum-era-risk-card ${scenario.overallRisk.toLowerCase()}`}>
          <span>CURRENT RISK</span>
          <strong>{scenario.overallRisk}</strong>
          <small>{scenario.overallCount} assets</small>
        </div>

        <div className="quantum-era-risk-card exposure">
          <span>RISK EXPOSURE</span>
          <strong>{scenario.riskExposurePercentage}%</strong>
          <small>assets at risk</small>
        </div>

        <div className="quantum-era-risk-card quantum">
          <span>QUANTUM EXPOSURE</span>
          <strong>{scenario.quantumExposureCount}</strong>
          <small>vulnerable assets</small>
        </div>

        <div className="quantum-era-risk-card legacy">
          <span>LEGACY WEAKNESS</span>
          <strong>{scenario.legacyWeaknessCount}</strong>
          <small>legacy / weak assets</small>
        </div>
      </div>
    </section>
  );
}
