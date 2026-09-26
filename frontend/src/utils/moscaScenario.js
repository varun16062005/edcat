const RISK_ORDER = ["CRITICAL", "HIGH", "ELEVATED", "LOW"];
const URGENCY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const CRITICALITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function baseRiskLabel(risk) {
  const value = String(risk || "").toUpperCase();
  if (value === "CRITICAL") return "CRITICAL";
  if (value === "HIGH") return "HIGH";
  if (value === "MEDIUM" || value === "ELEVATED") return "ELEVATED";
  if (value === "LOW" || value === "INFO") return "LOW";
  return "LOW";
}

function numericValue(artifact, keys) {
  for (const key of keys) {
    const value = Number(artifact?.[key]);
    if (Number.isFinite(value) && value >= 0) return value;
  }
  return null;
}

function fallbackLifetime(artifact) {
  const category = String(artifact?.category || "").toLowerCase();
  const usage = String(artifact?.usage || "").toLowerCase();
  if (category.includes("key") || usage.includes("private-key") || usage.includes("hardcoded")) return 2;
  if (category.includes("cloud") || usage.includes("kms") || usage.includes("vault")) return 20;
  if (String(artifact?.algorithm || "").toUpperCase().includes("RSA") ||
      String(artifact?.algorithm || "").toUpperCase().includes("ECDSA") ||
      String(artifact?.algorithm || "").toUpperCase().includes("ECDH")) {
    return 5;
  }
  return 5;
}

function fallbackMigrationYears(artifact) {
  const category = String(artifact?.category || "").toLowerCase();
  if (category.includes("certificate") || category.includes("tls")) return 0.5;
  if (category.includes("key")) return 1;
  return 1.5;
}

function fallbackCriticality(artifact) {
  const provided = String(
    artifact?.business_criticality || artifact?.businessCriticality || ""
  ).toUpperCase();
  if (CRITICALITY_ORDER.includes(provided)) return provided;
  const base = baseRiskLabel(artifact?.risk);
  if (base === "CRITICAL") return "CRITICAL";
  if (base === "HIGH") return "HIGH";
  if (base === "ELEVATED") return "MEDIUM";
  return "LOW";
}

function urgencyFromMargin(margin) {
  if (margin < 0) return "CRITICAL";
  if (margin < 3) return "HIGH";
  if (margin < 10) return "MEDIUM";
  return "LOW";
}

function moscaBucket(margin) {
  if (margin < 0) return "now";
  if (margin < 3) return "horizon";
  return "safe";
}

export function calculateArtifactScenarioRisk(artifact, assumedQuantumYear) {
  const currentYear = new Date().getFullYear();
  const baseRisk = baseRiskLabel(artifact?.risk);
  const quantumStatus = String(artifact?.quantum_status || "").toUpperCase();
  const lifetimeSource = numericValue(artifact, [
    "data_lifetime",
    "dataLifetime",
    "lifetime_years",
    "x_years",
  ]);
  const migrationSource = numericValue(artifact, [
    "migration_time",
    "migrationTime",
    "migration_years",
    "y_years",
  ]);
  const xYears = lifetimeSource ?? fallbackLifetime(artifact);
  const yYears = migrationSource ?? fallbackMigrationYears(artifact);
  const zYears = Math.max(1, Number(assumedQuantumYear) - currentYear);
  const margin = Number((zYears - (xYears + yYears)).toFixed(2));
  const criticality = fallbackCriticality(artifact);
  const urgency = urgencyFromMargin(margin);
  const quantumAtRisk = quantumStatus === "VULNERABLE";
  let scenarioRisk = baseRisk;

  if (quantumAtRisk && (margin < 0 || zYears <= 10)) scenarioRisk = "CRITICAL";
  else if (quantumAtRisk) scenarioRisk = "HIGH";
  else if (quantumStatus === "LEGACY_WEAK") scenarioRisk = "HIGH";
  if (criticality === "CRITICAL" && scenarioRisk === "HIGH") scenarioRisk = "CRITICAL";

  return {
    artifact,
    baseRisk,
    scenarioRisk,
    quantumAtRisk,
    xYears,
    yYears,
    zYears,
    margin,
    urgency,
    criticality,
    bucket: moscaBucket(margin),
    priorityScore: Number((
      (urgency === "CRITICAL" ? 16 : urgency === "HIGH" ? 11 : urgency === "MEDIUM" ? 6 : 2) +
      (criticality === "CRITICAL" ? 4.2 : criticality === "HIGH" ? 2.9 : criticality === "MEDIUM" ? 1.6 : 0.4)
    ).toFixed(2)),
    pqcTarget: recommendedPqc(artifact),
    factors: {
      dataLifetime: lifetimeSource ?? `Fallback ${xYears}y`,
      migrationTime: migrationSource ?? `Fallback ${yYears}y`,
      businessCriticality: artifact?.business_criticality || artifact?.businessCriticality || `Derived from ${baseRisk}`,
      yearsToQuantum: zYears,
      timingRisk: margin < 0,
      lifetimeFallback: lifetimeSource === null,
      migrationFallback: migrationSource === null,
    },
  };
}

export function recommendedPqc(artifact) {
  const usage = `${artifact?.usage || ""} ${artifact?.category || ""} ${artifact?.recommendation || ""}`.toLowerCase();
  const algorithm = String(artifact?.algorithm || "").toUpperCase();
  const targets = artifact?.migration_targets || artifact?.recommendation_detail?.migration_targets;
  if (Array.isArray(targets) && targets.length) return targets.join(" / ");
  if (targets && typeof targets === "object") {
    const values = Object.values(targets).filter(Boolean);
    if (values.length) return values.join(" / ");
  }
  const kem = usage.includes("key exchange") || usage.includes("key-establishment") ||
    usage.includes("kem") || algorithm.includes("ECDH") || algorithm.includes("DH");
  const signature = usage.includes("sign") || algorithm.includes("ECDSA") || algorithm.includes("DSA");
  if (algorithm.includes("RSA") && kem) return "ML-KEM";
  if (algorithm.includes("RSA") || signature) return "ML-DSA";
  if (algorithm.includes("ECDH") || kem) return "ML-KEM";
  if (algorithm.includes("ECDSA") || algorithm.includes("ED25519")) return "ML-DSA";
  if (algorithm.includes("AES") || algorithm.includes("3DES") || algorithm.includes("DES") || algorithm.includes("RC4")) {
    return "AES-256-GCM / ChaCha20-Poly1305";
  }
  return artifact?.recommendation || "Review against NIST PQC guidance";
}

export function calculateProjectScenarioRisk(artifacts = [], assumedQuantumYear = 2040) {
  const evaluations = artifacts.map((artifact) =>
    calculateArtifactScenarioRisk(artifact, assumedQuantumYear)
  );
  const counts = Object.fromEntries(RISK_ORDER.map((risk) => [risk, 0]));
  evaluations.forEach(({ scenarioRisk }) => {
    counts[scenarioRisk] += 1;
  });
  const overallRisk = RISK_ORDER.find((risk) => counts[risk] > 0) || "LOW";
  const highRiskCount = evaluations.filter(({ scenarioRisk }) =>
    ["CRITICAL", "HIGH"].includes(scenarioRisk)
  ).length;
  const buckets = {
    now: evaluations.filter((item) => item.bucket === "now").length,
    horizon: evaluations.filter((item) => item.bucket === "horizon").length,
    safe: evaluations.filter((item) => item.bucket === "safe").length,
  };
  const heatmap = {};
  CRITICALITY_ORDER.forEach((criticality) => {
    heatmap[criticality] = {};
    URGENCY_ORDER.forEach((urgency) => {
      heatmap[criticality][urgency] = evaluations.filter(
        (item) => item.criticality === criticality && item.urgency === urgency
      ).length;
    });
  });

  return {
    evaluations,
    overallRisk,
    riskPercentage: artifacts.length
      ? Math.round((highRiskCount / artifacts.length) * 100)
      : 0,
    quantumExposure: evaluations.filter(({ quantumAtRisk }) => quantumAtRisk).length,
    legacyWeakness: artifacts.filter(
      (artifact) => artifact.quantum_status === "LEGACY_WEAK"
    ).length,
    buckets,
    heatmap,
    assumedQuantumYear,
  };
}

export { RISK_ORDER, URGENCY_ORDER, CRITICALITY_ORDER };
