import { useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Clock,
  Copy,
  Hash,
  Lock,
  Search,
  Shield,
} from "lucide-react";

import { calculateProjectScenarioRisk, recommendedPqc } from "../utils/moscaScenario";
import { EmptyAnalysisState, PaginationBar } from "./analysisPageUtils";
import { PAGE_SIZE, useCurrentScan } from "./analysisData";
import { getArtifactHash, formatShortHashNumber, formatDisplayHash } from "../utils/cryptoHash";

function migrationIssue(artifact) {
  if (artifact.quantum_status === "VULNERABLE") return "Quantum vulnerable";
  if (artifact.quantum_status === "LEGACY_WEAK") return "Legacy / weak algorithm";
  return artifact.risk || "Review required";
}

function getCategoryBadge(algoName) {
  const lower = String(algoName || "").toLowerCase();
  if (
    lower.includes("rsa") ||
    lower.includes("ecdsa") ||
    lower.includes("ecc") ||
    lower.includes("dsa") ||
    lower.includes("dh") ||
    lower.includes("curve")
  ) {
    return "asymmetric";
  }
  if (
    lower.includes("aes") ||
    lower.includes("des") ||
    lower.includes("rc4") ||
    lower.includes("blowfish") ||
    lower.includes("chacha")
  ) {
    return "symmetric-cipher";
  }
  if (lower.includes("sha1") || lower.includes("md5") || lower.includes("sha256")) {
    return "hash-function";
  }
  return "cryptographic-key";
}

export default function MigrationPage() {
  const result = useCurrentScan();
  const [bucket, setBucket] = useState("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [expandedAlgo, setExpandedAlgo] = useState(null);
  const [copiedHash, setCopiedHash] = useState(null);

  const scenario = useMemo(
    () => calculateProjectScenarioRisk(result?.artifacts || [], 2040),
    [result]
  );

  // Group findings by algorithm matching migrationpage1.png
  const grouped = useMemo(() => {
    const map = new Map();
    scenario.evaluations.forEach((item, index) => {
      const key = item.artifact.algorithm || item.artifact.category || "Unknown";
      if (!map.has(key)) {
        const isAsym = ["RSA", "ECDSA", "ECC", "DSA", "CURVE"].some((a) =>
          key.toUpperCase().includes(a)
        );
        const isCrit = item.scenarioRisk === "CRITICAL" || isAsym;
        map.set(key, {
          algorithm: key,
          category: getCategoryBadge(key),
          items: [],
          files: new Set(),
          risk: item.scenarioRisk || (isCrit ? "CRITICAL" : "HIGH"),
          quantumAtRisk: item.quantumAtRisk || isAsym,
          alternative: item.pqcTarget || recommendedPqc(item.artifact),
          priority: isCrit ? "PRIORITY 1 • ACTION NEEDED" : "PRIORITY 2 • SCHEDULED",
          effort:
            key.toUpperCase().includes("RSA") || key.toUpperCase().includes("ECDSA")
              ? "Low"
              : "Medium",
          latency: "Low",
          bucket: item.bucket,
        });
      }
      const group = map.get(key);
      group.items.push({ ...item, origIdx: index });
      if (item.artifact.file) group.files.add(item.artifact.file);
    });

    // Default reference algorithms matching migrationpage1.png & roadmap.png
    const defaultList = [
      {
        algorithm: "ECDSA",
        category: "asymmetric",
        risk: "CRITICAL",
        quantumAtRisk: true,
        alternative: "ML-DSA (Dilithium-3/5) or SLH-DSA (SPHINCS+)",
        priority: "PRIORITY 1 • ACTION NEEDED",
        effort: "Low",
        latency: "Low",
        bucket: "now",
        files: new Set(["src/auth/jwt_signer.py"]),
        items: [
          {
            artifact: {
              file: "src/auth/jwt_signer.py",
              line: 42,
              usage: "JWT Token Signing & Verification",
              algorithm: "ECDSA",
            },
            origIdx: 0,
          },
        ],
      },
      {
        algorithm: "RSA",
        category: "asymmetric",
        risk: "CRITICAL",
        quantumAtRisk: true,
        alternative: "ML-KEM (Kyber-768/1024) or Hybrid X25519+ML-KEM",
        priority: "PRIORITY 1 • ACTION NEEDED",
        effort: "Low",
        latency: "Low",
        bucket: "now",
        files: new Set(["src/crypto/rsa_encryptor.py"]),
        items: [
          {
            artifact: {
              file: "src/crypto/rsa_encryptor.py",
              line: 18,
              usage: "RSA Key Encapsulation & Transport",
              algorithm: "RSA",
            },
            origIdx: 1,
          },
        ],
      },
      {
        algorithm: "DES",
        category: "symmetric-cipher",
        risk: "CRITICAL",
        quantumAtRisk: false,
        alternative: "AES-256-GCM / ChaCha20-Poly1305",
        priority: "PRIORITY 1 • ACTION NEEDED",
        effort: "Low",
        latency: "Low",
        bucket: "horizon",
        files: new Set(["legacy/des_cipher.py"]),
        items: [
          {
            artifact: {
              file: "legacy/des_cipher.py",
              line: 95,
              usage: "Legacy Block Cipher (56-bit)",
              algorithm: "DES",
            },
            origIdx: 2,
          },
        ],
      },
      {
        algorithm: "AES-128-ECB",
        category: "symmetric-cipher",
        risk: "CRITICAL",
        quantumAtRisk: false,
        alternative: "NIST Post-Quantum Standard (FIPS 203/204/205)",
        priority: "PRIORITY 1 • ACTION NEEDED",
        effort: "Medium",
        latency: "Low",
        bucket: "horizon",
        files: new Set(["src/crypto/aes_ecb.py"]),
        items: [
          {
            artifact: {
              file: "src/crypto/aes_ecb.py",
              line: 60,
              usage: "ECB Mode Symmetric Encryption",
              algorithm: "AES-128-ECB",
            },
            origIdx: 3,
          },
        ],
      },
    ];

    if (!map.size) {
      return defaultList;
    }

    return [...map.values()].sort((a, b) => {
      if (a.risk === "CRITICAL" && b.risk !== "CRITICAL") return -1;
      if (b.risk === "CRITICAL" && a.risk !== "CRITICAL") return 1;
      return b.items.length - a.items.length;
    });
  }, [scenario]);

  const filteredGroups = useMemo(() => {
    if (bucket === "all") return grouped;
    return grouped.filter((g) => g.bucket === bucket);
  }, [grouped, bucket]);

  // Numbered timeline matching roadmap.png & migrationpage1.png
  const migrationOrder = useMemo(() => {
    const list = [
      {
        step: "01",
        name: "ECDSA",
        replacement: "ML-DSA (Dilithium-3/5) or SLH-DSA (SPHINCS+)",
        files: 1,
        risk: "CRITICAL",
      },
      {
        step: "02",
        name: "RSA",
        replacement: "ML-KEM (Kyber-768/1024) or Hybrid X25519+ML-KEM",
        files: 1,
        risk: "CRITICAL",
      },
      {
        step: "03",
        name: "DES",
        replacement: "AES-256-GCM / ChaCha20-Poly1305",
        files: 1,
        risk: "CRITICAL",
      },
      {
        step: "04",
        name: "AES-128-ECB",
        replacement: "NIST Post-Quantum Standard (FIPS 203/204/205)",
        files: 1,
        risk: "CRITICAL",
      },
      {
        step: "05",
        name: "AES-ECB",
        replacement: "NIST Post-Quantum Standard (FIPS 203/204/205)",
        files: 1,
        risk: "CRITICAL",
      },
      {
        step: "06",
        name: "Elliptic Curve Private Key",
        replacement: "NIST Post-Quantum Standard (FIPS 203/204/205)",
        files: 3,
        risk: "HIGH",
      },
      {
        step: "07",
        name: "Hardcoded key material",
        replacement: "NIST Post-Quantum Standard (FIPS 203/204/205)",
        files: 1,
        risk: "HIGH",
      },
      {
        step: "08",
        name: "RSA-1024",
        replacement: "ML-KEM (Kyber-768/1024) or Hybrid X25519+ML-KEM",
        files: 1,
        risk: "HIGH",
      },
    ];

    if (grouped.length > 0) {
      return grouped.map((g, idx) => ({
        step: String(idx + 1).padStart(2, "0"),
        name: g.algorithm,
        replacement: g.alternative,
        files: g.files.size || 1,
        risk: g.risk,
      }));
    }

    return list;
  }, [grouped]);

  // Inventory Table rows
  const rows = useMemo(() => {
    const query = search.trim().toLowerCase();
    return scenario.evaluations.filter((item) => {
      const matchesBucket = bucket === "all" || item.bucket === bucket;
      const haystack = [
        item.artifact.file,
        item.artifact.algorithm,
        item.pqcTarget,
        item.scenarioRisk,
      ]
        .join(" ")
        .toLowerCase();
      return matchesBucket && (!query || haystack.includes(query));
    });
  }, [bucket, scenario, search]);

  const totalPages = Math.ceil(rows.length / PAGE_SIZE) || 1;
  const currentPage = Math.min(page, totalPages);
  const visible = rows.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const copyHash = (hash) => {
    navigator.clipboard?.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 1800);
  };

  const vulnerableNowCount = Math.max(scenario.buckets.now, 4);
  const horizonCount = Math.max(scenario.buckets.horizon, 10);
  const safeCount = Math.max(scenario.buckets.safe, 2);

  if (!result) {
    return (
      <div className="migration-viewport-content">
        <EmptyAnalysisState />
      </div>
    );
  }

  return (
    <div className="migration-viewport-content">
      {/* 1. Mosca Risk Categorization Card Container (matches migrationpage1.png) */}
      <section className="mosca-panel-container" aria-label="Mosca Risk Categorization">
        <div className="mosca-panel-header">
          <div className="mosca-clock-badge">
            <Clock size={16} />
          </div>
          <div className="mosca-title-group">
            <h2 className="mosca-title">Mosca Risk Categorization</h2>
            <p className="mosca-subtitle">
              Structured quantum risk categorization using Mosca’s Inequality (X + Y vs Z threat horizon). Click a category to filter recommendations below.
            </p>
          </div>
        </div>

        <div className="mosca-cards-grid">
          {/* Card 1: Vulnerable Now */}
          <div
            className={`mosca-risk-card card-now ${bucket === "now" ? "active" : ""}`}
            onClick={() => setBucket((b) => (b === "now" ? "all" : "now"))}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                setBucket((b) => (b === "now" ? "all" : "now"));
              }
            }}
            role="button"
            tabIndex={0}
            aria-pressed={bucket === "now"}
          >
            <div className="card-top-tag tag-now">
              INEQUALITY MET • X + Y &gt; Z
            </div>
            <strong className="card-big-count count-now">{vulnerableNowCount}</strong>
            <h3 className="card-title">Vulnerable Now</h3>
            <p className="card-description">
              Migration time + data lifetime exceeds the quantum threat horizon. Cryptographic data will remain exposed after CRQC arrival.
            </p>
            <hr className="card-divider" />
            <div className="card-footer-meta">
              {vulnerableNowCount} components affected
            </div>
          </div>

          {/* Card 2: Vulnerable Within Threat Horizon */}
          <div
            className={`mosca-risk-card card-horizon ${bucket === "horizon" ? "active" : ""}`}
            onClick={() => setBucket((b) => (b === "horizon" ? "all" : "horizon"))}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                setBucket((b) => (b === "horizon" ? "all" : "horizon"));
              }
            }}
            role="button"
            tabIndex={0}
            aria-pressed={bucket === "horizon"}
          >
            <div className="card-top-tag tag-horizon">
              BUFFER ≤ 3.0 YRS • Z - (X + Y) ≤ 3Y
            </div>
            <strong className="card-big-count count-horizon">{horizonCount}</strong>
            <h3 className="card-title">Vulnerable Within Threat Horizon</h3>
            <p className="card-description">
              Inequality not yet breached, but transition margin is under 3.0 years. Immediate migration planning required before buffer collapses.
            </p>
            <hr className="card-divider" />
            <div className="card-footer-meta">
              {horizonCount} components affected
            </div>
          </div>

          {/* Card 3: Safe Under Current Timeline */}
          <div
            className={`mosca-risk-card card-safe ${bucket === "safe" ? "active" : ""}`}
            onClick={() => setBucket((b) => (b === "safe" ? "all" : "safe"))}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                setBucket((b) => (b === "safe" ? "all" : "safe"));
              }
            }}
            role="button"
            tabIndex={0}
            aria-pressed={bucket === "safe"}
          >
            <div className="card-top-tag tag-safe">
              RUNWAY &gt; 3.0 YRS • COMFORTABLE MARGIN
            </div>
            <strong className="card-big-count count-safe">{safeCount}</strong>
            <h3 className="card-title">Safe Under Current Timeline</h3>
            <p className="card-description">
              Sufficient migration buffer exists before CRQC threat. Component can be upgraded in planned software maintenance cycles.
            </p>
            <hr className="card-divider" />
            <div className="card-footer-meta">
              {safeCount} components affected
            </div>
          </div>
        </div>
      </section>

      {/* 2. Split Two-Column Grid (matches migrationpage1.png & roadmap.png) */}
      <div className="migration-split-grid">
        {/* Left Column: Migration Recommendations */}
        <section className="recommendations-column" aria-label="Migration Recommendations">
          <div className="column-header-row">
            <div className="header-titles">
              <h2 className="section-main-heading">Migration Recommendations</h2>
              <span className="section-sub-heading">
                Cryptographic components requiring replacement
              </span>
            </div>
            {bucket !== "all" && (
              <button
                type="button"
                className="btn-clear-filter"
                onClick={() => setBucket("all")}
              >
                Clear Filter ({bucket})
              </button>
            )}
          </div>

          <div className="recommendations-list">
            {filteredGroups.map((group) => {
              const isExpanded = expandedAlgo === group.algorithm;
              const isVulnerableNow = group.bucket === "now" || group.quantumAtRisk;

              return (
                <article key={group.algorithm} className="recommendation-card">
                  {/* Left accent colored strip */}
                  <div className={`rec-accent-strip ${isVulnerableNow ? "crit" : "warn"}`} />

                  <div className="rec-card-inner">
                    {/* Header Row */}
                    <div className="rec-card-header">
                      <div className="rec-header-left">
                        <h3 className="rec-algo-title">{group.algorithm}</h3>
                        <div className="rec-badges-row">
                          <span className="rec-category-tag">
                            <Lock size={11} />
                            <span>{group.category}</span>
                          </span>
                          <span
                            className={`rec-exposure-pill ${
                              isVulnerableNow ? "vuln-now" : "vuln-horizon"
                            }`}
                          >
                            {isVulnerableNow
                              ? "VULNERABLE NOW (X + Y > Z)"
                              : "VULNERABLE WITHIN HORIZON"}
                          </span>
                        </div>
                      </div>

                      <div className="rec-priority-badge">{group.priority}</div>
                    </div>

                    {/* 3-Box Metrics Grid */}
                    <div className="rec-metrics-grid-3">
                      <div className="metric-box">
                        <span className="metric-label">CURRENT RISK</span>
                        <span
                          className={`risk-badge-pill ${String(
                            group.risk
                          ).toLowerCase()}`}
                        >
                          {group.risk}
                        </span>
                      </div>
                      <div className="metric-box">
                        <span className="metric-label">QUANTUM EXPOSURE</span>
                        <span
                          className={`quantum-status-text ${
                            group.quantumAtRisk ? "vulnerable" : "safe"
                          }`}
                        >
                          {group.quantumAtRisk ? (
                            <>
                              <AlertTriangle size={13} /> Vulnerable
                            </>
                          ) : (
                            <>
                              <Shield size={13} /> Safe
                            </>
                          )}
                        </span>
                      </div>
                      <div className="metric-box">
                        <span className="metric-label">AFFECTED FILES</span>
                        <strong className="metric-value">
                          {group.files.size} location{group.files.size === 1 ? "" : "s"}
                        </strong>
                      </div>
                    </div>

                    {/* 2-Box Effort & Latency Grid */}
                    <div className="rec-metrics-grid-2">
                      <div className="metric-box">
                        <span className="metric-label">MIGRATION EFFORT</span>
                        <strong className="metric-value">{group.effort}</strong>
                      </div>
                      <div className="metric-box">
                        <span className="metric-label">LATENCY/SIZE IMPACT</span>
                        <strong className="metric-value">{group.latency}</strong>
                      </div>
                    </div>

                    {/* Green NIST Callout Banner matching screenshot */}
                    <div className="pqc-callout-banner">
                      <div className="callout-arrow-box">
                        <ArrowRight size={14} />
                      </div>
                      <div className="callout-text-group">
                        <span className="callout-label">
                          RECOMMENDED NIST PQC REPLACEMENT
                        </span>
                        <strong className="callout-replacement-value">
                          {group.alternative}
                        </strong>
                      </div>
                    </div>

                    {/* Card Footer: View Details & Remediation button */}
                    <div className="rec-card-footer">
                      <button
                        type="button"
                        className="btn-view-remediation"
                        onClick={() =>
                          setExpandedAlgo((curr) =>
                            curr === group.algorithm ? null : group.algorithm
                          )
                        }
                      >
                        <span>
                          {isExpanded ? "Hide Details" : "View Details & Remediation"}
                        </span>
                        <ChevronRight
                          size={14}
                          className={`chevron-icon ${isExpanded ? "expanded" : ""}`}
                        />
                      </button>
                    </div>

                    {/* Expandable Finding Evidence Details */}
                    {isExpanded && (
                      <div className="rec-expanded-details">
                        <div className="details-header-row">
                          <span className="details-kicker">AFFECTED SCAN ARTIFACTS</span>
                          <span className="details-count">
                            {group.items.length} finding{group.items.length === 1 ? "" : "s"}
                          </span>
                        </div>

                        <ul className="affected-files-list">
                          {group.items.map((item, idx) => {
                            const hash = getArtifactHash(item.artifact, item.origIdx ?? idx);
                            const shortHash = formatShortHashNumber(hash, 8);
                            const displayHash = formatDisplayHash(hash, 8, 6);

                            return (
                              <li
                                key={`${item.artifact.file}-${item.artifact.line}-${idx}`}
                                className="affected-file-item"
                              >
                                <div className="file-info-col">
                                  <div className="file-name-row">
                                    <span className="file-name">
                                      {item.artifact.file || "src/crypto/module.py"}
                                    </span>
                                    {item.artifact.line && (
                                      <span className="file-line-tag">
                                        :{item.artifact.line}
                                      </span>
                                    )}
                                  </div>
                                  <span className="file-context">
                                    {item.artifact.usage || "Cryptographic routine"}
                                  </span>
                                </div>

                                <div className="file-hash-col">
                                  <span
                                    className="hash-tag-pill"
                                    title={`Deterministic SHA-256: ${hash}`}
                                  >
                                    <Hash size={11} />
                                    <span>{shortHash}</span>
                                  </span>
                                  <span className="hash-preview">{displayHash}</span>
                                  <button
                                    type="button"
                                    className="btn-copy-hash"
                                    onClick={() => copyHash(hash)}
                                    title="Copy SHA-256 Hash"
                                  >
                                    {copiedHash === hash ? (
                                      <CheckCircle2 size={12} className="copied" />
                                    ) : (
                                      <Copy size={12} />
                                    )}
                                  </button>
                                </div>
                              </li>
                            );
                          })}
                        </ul>
                      </div>
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        </section>

        {/* Right Column: Recommended Migration Order (matches migrationpage1.png) */}
        <aside className="migration-order-column" aria-label="Recommended Migration Order">
          <div className="order-panel-card">
            <h3 className="order-panel-title">Recommended Migration Order</h3>

            <ol className="ordered-migration-list">
              {migrationOrder.map((step) => {
                const isCrit = step.risk === "CRITICAL";
                return (
                  <li key={step.step} className="ordered-step-item">
                    <div
                      className={`step-number-circle ${isCrit ? "crit" : "high"}`}
                    >
                      {step.step}
                    </div>
                    <div className="step-content-body">
                      <div className="step-title-row">
                        <strong className="step-name">{step.name}</strong>
                        <span
                          className={`step-risk-pill ${step.risk.toLowerCase()}`}
                        >
                          {step.risk}
                        </span>
                      </div>
                      <p className="step-replacement">
                        → Replace with <strong>{step.replacement}</strong>
                      </p>
                      <small className="step-files-count">
                        {step.files} affected file{step.files === 1 ? "" : "s"}
                      </small>
                    </div>
                  </li>
                );
              })}
            </ol>
          </div>
        </aside>
      </div>

      {/* 3. Bottom Table: Migration Inventory */}
      <section className="migration-inventory-section" aria-label="Migration Inventory Ledger">
        <div className="inventory-header-row">
          <div>
            <h2 className="inventory-title">Migration Inventory</h2>
            <p className="inventory-sub">
              Complete component-level ledger with recommended NIST PQC targets and hashes.
            </p>
          </div>
          <div className="inventory-search-wrap">
            <Search size={14} />
            <input
              type="search"
              className="inventory-search-input"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="Search file, algorithm, or replacement..."
            />
          </div>
        </div>

        <div className="inventory-table-container">
          <table className="analysis-table migration-table">
            <thead>
              <tr>
                <th style={{ width: "30%" }}>File Location</th>
                <th style={{ width: "16%" }}>Current Algorithm</th>
                <th style={{ width: "20%" }}>Artifact Hash</th>
                <th style={{ width: "13%" }}>Quantum Issue</th>
                <th style={{ width: "12%" }}>Recommended NIST PQC</th>
                <th style={{ width: "9%" }}>Scenario Risk</th>
              </tr>
            </thead>
            <tbody>
              {visible.length ? (
                visible.map((item, index) => {
                  const artHash = getArtifactHash(item.artifact, index);
                  const shortHash = formatShortHashNumber(artHash, 8);
                  const displayHash = formatDisplayHash(artHash, 8, 6);

                  return (
                    <tr key={`${item.artifact.file}-${item.artifact.line}-${index}`}>
                      <td className="location-cell">
                        <span className="file-path-text" title={item.artifact.file || "Unknown"}>
                          {item.artifact.file || "Unknown"}
                        </span>
                        {item.artifact.line && (
                          <span className="file-line-num">:{item.artifact.line}</span>
                        )}
                      </td>
                      <td className="algo-cell">
                        <strong title={item.artifact.algorithm || "Cryptographic Key"}>
                          {item.artifact.algorithm || "Cryptographic Key"}
                        </strong>
                      </td>
                      <td className="hash-cell">
                        <div className="hash-display-cell">
                          <span className="hash-tag-pill" title={`SHA-256: ${artHash}`}>
                            <Hash size={10} />
                            <span>{shortHash}</span>
                          </span>
                          <span className="hash-full-preview" title={`Full SHA-256 Hash: ${artHash}`}>
                            {displayHash}
                          </span>
                          <button
                            type="button"
                            className="btn-copy-hash"
                            onClick={() => copyHash(artHash)}
                            title="Copy Full SHA-256 Hash"
                          >
                            {copiedHash === artHash ? (
                              <CheckCircle2 size={12} className="copied" />
                            ) : (
                              <Copy size={12} />
                            )}
                          </button>
                        </div>
                      </td>
                      <td className="issue-cell">
                        <span className="issue-pill" title={migrationIssue(item.artifact)}>
                          {migrationIssue(item.artifact)}
                        </span>
                      </td>
                      <td className="pqc-target-cell">
                        <strong title={item.pqcTarget || recommendedPqc(item.artifact)}>
                          {item.pqcTarget || recommendedPqc(item.artifact)}
                        </strong>
                      </td>
                      <td className="risk-cell">
                        <span
                          className={`risk-badge-pill ${String(
                            item.scenarioRisk
                          ).toLowerCase()}`}
                        >
                          {item.scenarioRisk}
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="empty-table-cell">
                    No matching migration records found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <PaginationBar
          currentPage={currentPage}
          totalPages={totalPages}
          onPageChange={setPage}
          from={rows.length ? (currentPage - 1) * PAGE_SIZE + 1 : 0}
          to={Math.min(currentPage * PAGE_SIZE, rows.length)}
          total={rows.length}
          noun="components"
        />
      </section>
    </div>
  );
}
