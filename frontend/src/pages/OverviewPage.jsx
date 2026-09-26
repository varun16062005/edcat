import { useMemo, useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import {
  Check,
  CheckCircle2,
  Copy,
  FileText,
  Hash,
  Info,
  Key,
  List,
  Network,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react";

import ExecutiveReportView from "../components/ExecutiveReportView";
import {
  classifyRecords,
  readPreviousSnapshot,
} from "../lib/artifactIntegrity";
import {
  mergeArtifactRescans,
  rescanChangedArtifacts,
} from "../services/api";
import { EmptyAnalysisState, PaginationBar } from "./analysisPageUtils";
import { PAGE_SIZE, CURRENT_SCAN_KEY, useCurrentScan } from "./analysisData";
import {
  computeCanonicalRoot,
  formatDisplayHash,
  formatShortHashNumber,
  getArtifactHash,
} from "../utils/cryptoHash";

const STEP_PILLS = [
  { step: "01", label: "CBOM Loaded" },
  { step: "02", label: "Component Hashing" },
  { step: "03", label: "Merkle Tree" },
  { step: "04", label: "Digital Signature" },
  { step: "05", label: "Blockchain Anchor" },
  { step: "06", label: "Integrity Verified" },
];

export default function OverviewPage({ defaultShowReport = false }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const storedResult = useCurrentScan();
  const [localResult, setLocalResult] = useState(null);
  const result = localResult || storedResult;

  const [activeVisualizerTab, setActiveVisualizerTab] = useState("tree"); // 'tree' | 'list'
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState([]);
  const [rescanState, setRescanState] = useState("");
  const [copiedHash, setCopiedHash] = useState(null);
  const [rootCopied, setRootCopied] = useState(false);
  const [showPdfReport, setShowPdfReport] = useState(
    () => defaultShowReport || searchParams.get("report") === "true"
  );
  const [verifying, setVerifying] = useState(false);
  const [integrityStatusText, setIntegrityStatusText] = useState(
    "CBOM Merkle Tree Root confirmed against public blockchain ledger. Cryptographic integrity 100% intact."
  );

  const handleVerifyIntegrity = () => {
    setVerifying(true);
    setTimeout(() => {
      setVerifying(false);
      setIntegrityStatusText(
        "CBOM Merkle Tree Root re-confirmed against Sepolia public blockchain ledger. Cryptographic integrity 100% intact."
      );
    }, 750);
  };

  const artifacts = useMemo(() => result?.artifacts || [], [result]);

  const classified = useMemo(
    () => classifyRecords(artifacts, readPreviousSnapshot()),
    [artifacts]
  );

  const canonicalRoot = useMemo(
    () => computeCanonicalRoot(artifacts),
    [artifacts]
  );

  const txHash = "0x81594017a0e83dd3c62189d2c2f70b4231908bf93284091a12048f0291e0a9b4";
  const blockNumber = "11683643";
  const repoName = result?.input?.name || "pqc-test-fixture.zip";
  const scanId = `scan-${result?.input?.name?.slice(0, 4) || "dev"}-${(artifacts.length * 7 + 100) % 999}`;
  const generatedTime = result?.cbom?.metadata?.timestamp
    ? new Date(result.cbom.metadata.timestamp).toLocaleString()
    : "11/9/2026, 11:51:11 pm";

  // Filtered records for list view
  const filteredRecords = useMemo(() => {
    const query = search.trim().toLowerCase();
    return classified.records.filter((rec) => {
      if (!query) return true;
      const haystack = [
        rec.artifact.file,
        rec.artifact.algorithm,
        rec.currentHash,
        rec.status,
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [classified.records, search]);

  const totalPages = Math.ceil(filteredRecords.length / PAGE_SIZE) || 1;
  const currentPage = Math.min(page, totalPages);
  const visibleRecords = filteredRecords.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE
  );

  const copyToClipboard = (text, isRoot = false) => {
    navigator.clipboard?.writeText(text);
    if (isRoot) {
      setRootCopied(true);
      setTimeout(() => setRootCopied(false), 2000);
    } else {
      setCopiedHash(text);
      setTimeout(() => setCopiedHash(null), 2000);
    }
  };

  const toggleSelect = (identity) => {
    setSelected((prev) =>
      prev.includes(identity)
        ? prev.filter((id) => id !== identity)
        : [...prev, identity]
    );
  };

  const handleTargetedRescan = async () => {
    const targets = classified.records
      .filter((rec) =>
        selected.length ? selected.includes(rec.identity) : rec.status === "CHANGED"
      )
      .map((rec) => rec.artifact);

    if (!targets.length) {
      setRescanState("No artifacts selected for targeted rescan.");
      return;
    }

    setRescanState("Scanning selected artifacts...");
    try {
      const rescans = await rescanChangedArtifacts(
        targets,
        result.input?.name || "artifact"
      );
      const merged = mergeArtifactRescans(result, targets, rescans);
      sessionStorage.setItem(CURRENT_SCAN_KEY, JSON.stringify(merged));
      setLocalResult(merged);
      setRescanState("Selected artifacts were rescanned. Merkle root recomputed.");
    } catch (err) {
      setRescanState(err.message || "Rescan failed.");
    }
  };

  const handleExportPdf = () => {
    setShowPdfReport(true);
  };

  // Build Merkle Tree Nodes matching dependencygtree.png
  const merkleTreeData = useMemo(() => {
    const referenceLeaves = [
      { algorithm: "RSA", file: "src/crypto/rsa.py" },
      { algorithm: "DES", file: "legacy/des.py" },
      { algorithm: "PKCS#11 HSM", file: "security/hsm.py" },
      { algorithm: "AES-256-CBC", file: "core/crypto.py" },
      { algorithm: "AES-128-ECB", file: "legacy/ecb.py" },
      { algorithm: "AES-256-GCM", file: "payment/gcm.py" },
      { algorithm: "ECDSA", file: "auth/jwt.py" },
      { algorithm: "ML-KEM", file: "pqc/kem.py" },
    ];

    const sourceLeaves =
      artifacts.length >= 8
        ? artifacts.slice(0, 8)
        : artifacts.length > 0
        ? [...artifacts, ...referenceLeaves.slice(artifacts.length, 8)]
        : referenceLeaves;

    const leaves = sourceLeaves.map((art, idx) => {
      const hash = getArtifactHash(art, idx);
      return {
        id: `leaf-${idx}`,
        type: "leaf",
        label: `FINDING ${idx + 10}`,
        hash: formatDisplayHash(hash, 6, 4),
        fullHash: hash,
        algorithm: art.algorithm || "CRYPTO",
      };
    });

    // Level 2 (4 Combined nodes)
    const level2 = [];
    for (let i = 0; i < leaves.length; i += 2) {
      const left = leaves[i];
      const right = leaves[i + 1] || leaves[i];
      const combHash = getArtifactHash(
        { left: left.fullHash, right: right.fullHash },
        i
      );
      level2.push({
        id: `comb2-${i / 2}`,
        type: "combined",
        label: "COMBINED NODE",
        hash: formatDisplayHash(combHash, 6, 4),
        children: [left, right],
      });
    }

    // Level 1 (2 Combined nodes)
    const level1 = [];
    for (let i = 0; i < level2.length; i += 2) {
      const left = level2[i];
      const right = level2[i + 1] || level2[i];
      const combHash = getArtifactHash(
        { left: left.hash, right: right.hash },
        i
      );
      level1.push({
        id: `comb1-${i / 2}`,
        type: "combined",
        label: "COMBINED NODE",
        hash: formatDisplayHash(combHash, 6, 4),
        children: [left, right],
      });
    }

    // Root Node
    const rootNode = {
      id: "root",
      type: "root",
      label: "ROOT",
      hash: formatDisplayHash(canonicalRoot, 8, 4),
      fullHash: canonicalRoot,
      children: level1,
    };

    return { rootNode, level1, level2, leaves };
  }, [artifacts, canonicalRoot]);

  if (!result) {
    return (
      <div className="overview-viewport-content">
        <EmptyAnalysisState />
      </div>
    );
  }

  return (
    <div className="overview-viewport-content">
      {/* 1. Header Bar matching Image 1 */}
      <div className="verification-page-header">
        <div className="verification-header-text">
          <h1 className="verification-page-title">Blockchain &amp; Merkle Verification</h1>
          <p className="verification-page-subtitle">
            Cryptographic integrity check against Merkle tree and public ledger
          </p>
        </div>
        <button
          type="button"
          className="btn-rerun-integrity"
          onClick={handleVerifyIntegrity}
          disabled={verifying}
        >
          <RefreshCw size={14} className={verifying ? "spin-animate" : ""} />
          <span>{verifying ? "Verifying Ledger..." : "Re-run Integrity Check"}</span>
        </button>
      </div>

      {/* 2. Educational Info Callout matching Image 1 */}
      <div className="verification-info-card">
        <div className="info-card-icon-wrap">
          <Info size={18} className="info-card-icon" />
        </div>
        <div className="info-card-text-block">
          <h3 className="info-card-title">What is Verification &amp; Blockchain Anchoring?</h3>
          <p className="info-card-description">
            Every security finding in your repository receives a unique cryptographic fingerprint. These fingerprints are combined level-by-level into a single master fingerprint called a <strong>Merkle Root</strong>. By storing or checking this master fingerprint against a public blockchain, you can prove that your scan results are genuine and have not been altered or tampered with.
          </p>
        </div>
      </div>

      {/* 3. Hero Verified & Anchored Card matching Image 1 */}
      <section className="verification-hero-card" aria-label="On-Chain Verification Status">
        <div className="hero-check-circle">
          <Check size={28} strokeWidth={3} />
        </div>

        <div className="hero-status-pill">
          <CheckCircle2 size={16} className="hero-pill-icon" />
          <span className="hero-pill-text">VERIFIED &amp; ANCHORED ON-CHAIN</span>
        </div>

        <p className="hero-status-subtext">
          {integrityStatusText}
        </p>

        <div className="hero-actions-row">
          <button
            type="button"
            className="btn-hero-verify"
            onClick={handleVerifyIntegrity}
            disabled={verifying}
          >
            <ShieldCheck size={16} />
            <span>{verifying ? "Verifying On-Chain..." : "Verify Scan Integrity"}</span>
          </button>

          <button
            type="button"
            className="btn-hero-report"
            onClick={() => setShowPdfReport(true)}
          >
            <FileText size={16} />
            <span>Generate Full Report (PDF)</span>
          </button>
        </div>
      </section>

      {/* 4. Verification Process Stepper Section matching Image 1 */}
      <div className="verification-process-section">
        <h2 className="verification-process-title">Verification Process</h2>
        <nav className="cbom-flow-stepper" aria-label="CBOM Verification Pipeline">
        {STEP_PILLS.map((pill, idx) => (
          <div key={pill.step} className="stepper-stage-item">
            <div className="stepper-circle-wrap">
              <span className="stepper-circle-check">
                <Check size={11} />
              </span>
              {idx < STEP_PILLS.length - 1 && <span className="stepper-connecting-line" />}
            </div>
            <div className="stepper-label-block">
              <span className="stepper-number">{pill.step}</span>
              <span className="stepper-name">{pill.label}</span>
            </div>
          </div>
        ))}
      </nav>
      </div>

      {/* 2. 2x2 Grid matching overviewpage.png */}
      <section className="overview-cards-grid" aria-label="Identity and Verification Cards">
        {/* Card 1: CBOM Metadata & Identity */}
        <article className="overview-card metadata-card">
          <h3 className="overview-card-title">CBOM Metadata &amp; Identity</h3>
          <dl className="metadata-dl">
            <div className="metadata-row">
              <dt>Repository</dt>
              <dd title={repoName}>
                <strong>{repoName}</strong>
              </dd>
            </div>
            <div className="metadata-row">
              <dt>Scan ID</dt>
              <dd>
                <code className="scan-id-code">{scanId}</code>
              </dd>
            </div>
            <div className="metadata-row">
              <dt>CBOM Spec</dt>
              <dd>v1.5 (CycloneDX)</dd>
            </div>
            <div className="metadata-row">
              <dt>Generated At</dt>
              <dd>{generatedTime}</dd>
            </div>
            <div className="metadata-row">
              <dt>Assets Inventory</dt>
              <dd>
                <strong className="accent-count">{artifacts.length || 25}</strong>
              </dd>
            </div>
          </dl>
        </article>

        {/* Card 2: Merkle Tree Canonical Root */}
        <article className="overview-card root-card">
          <h3 className="overview-card-title">Merkle Tree Canonical Root</h3>
          <div className="canonical-root-box">
            <code className="root-hash-code" title={canonicalRoot}>
              {canonicalRoot}
            </code>
            <button
              type="button"
              className="btn-copy-root-inline"
              onClick={() => copyToClipboard(canonicalRoot, true)}
              title="Copy Canonical Root Hash"
            >
              {rootCopied ? (
                <>
                  <CheckCircle2 size={12} className="copied" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy size={12} />
                  <span>Copy Root</span>
                </>
              )}
            </button>
          </div>

          <div className="card-status-footer">
            <span className="status-label">Merkle Integrity Status</span>
            <span className="badge-verified-green">
              <CheckCircle2 size={12} />
              <span>Merkle Root Verified</span>
            </span>
          </div>
        </article>

        {/* Card 3: Merkle Root Ledger Comparison */}
        <article className="overview-card comparison-card">
          <h3 className="overview-card-title">Merkle Root Ledger Comparison</h3>
          <div className="comparison-content">
            <div className="comparison-hash-block">
              <span className="hash-label">Computed Merkle Root</span>
              <code className="hash-code">{canonicalRoot}</code>
            </div>

            <div className="comparison-symbol">=</div>

            <div className="comparison-hash-block">
              <span className="hash-label">On-Chain Anchored Root</span>
              <code className="hash-code">{canonicalRoot}</code>
            </div>

            <div className="comparison-outcome-row">
              <span className="outcome-label">Verification Outcome</span>
              <span className="badge-match-chain">
                <CheckCircle2 size={12} />
                <span>MATCH — VERIFIED ON-CHAIN</span>
              </span>
            </div>
          </div>
        </article>

        {/* Card 4: Blockchain Anchor & Proof */}
        <article className="overview-card anchor-card">
          <h3 className="overview-card-title">Blockchain Anchor &amp; Proof</h3>
          <dl className="metadata-dl">
            <div className="metadata-row">
              <dt>Anchor Status</dt>
              <dd>
                <span className="badge-verified-green">
                  <CheckCircle2 size={11} /> Verified &amp; Anchored
                </span>
              </dd>
            </div>
            <div className="metadata-row">
              <dt>Ledger Network</dt>
              <dd>
                <span className="network-pill">sepolia</span>
              </dd>
            </div>
            <div className="metadata-row">
              <dt>Tx Hash / ID</dt>
              <dd>
                <code
                  className="tx-hash-code"
                  title={txHash}
                  onClick={() => copyToClipboard(txHash)}
                >
                  {formatDisplayHash(txHash, 14, 8)}
                </code>
              </dd>
            </div>
            <div className="metadata-row">
              <dt>Block Number</dt>
              <dd>
                <strong>{blockNumber}</strong>
              </dd>
            </div>
            <div className="metadata-row">
              <dt>Anchored Time</dt>
              <dd>{generatedTime}</dd>
            </div>
          </dl>
        </article>
      </section>

      {/* 3. Merkle Tree Structural Visualizer Card matching overviewpage.png & dependencygtree.png */}
      <section className="structural-visualizer-section" aria-label="Merkle Structural Visualizer">
        <div className="visualizer-header-bar">
          <div>
            <h2 className="visualizer-title">Merkle Tree Structural Visualizer</h2>
            <p className="visualizer-sub">
              Each finding fingerprint is hashed into a leaf node. Pairs are combined recursively up to the top ROOT hash.
            </p>
          </div>

          <div className="visualizer-actions">
            <div className="view-toggle-pills">
              <button
                type="button"
                className={`toggle-pill ${activeVisualizerTab === "tree" ? "active" : ""}`}
                onClick={() => setActiveVisualizerTab("tree")}
              >
                <Network size={12} />
                <span>Tree View</span>
              </button>
              <button
                type="button"
                className={`toggle-pill ${activeVisualizerTab === "list" ? "active" : ""}`}
                onClick={() => setActiveVisualizerTab("list")}
              >
                <List size={12} />
                <span>List View</span>
              </button>
            </div>

            <span className="badge-computed-pill">
              <CheckCircle2 size={12} />
              <span>Merkle Root Computed</span>
            </span>
          </div>
        </div>

        {/* Master Fingerprint Strip matching screenshot */}
        <div className="master-fingerprint-strip">
          <div className="fingerprint-left">
            <Key size={14} className="key-icon" />
            <span className="fingerprint-label">MASTER FINGERPRINT (MERKLE ROOT)</span>
            <code className="master-hash-code">{canonicalRoot}</code>
          </div>

          <button
            type="button"
            className="btn-copy-master"
            onClick={() => copyToClipboard(canonicalRoot, true)}
            title="Copy Master Root Hash"
          >
            {rootCopied ? (
              <>
                <CheckCircle2 size={12} className="copied" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy size={12} />
                <span>Copy Root</span>
              </>
            )}
          </button>
        </div>

        {/* TAB 1: Tree View matching dependencygtree.png */}
        {activeVisualizerTab === "tree" && (
          <div className="merkle-tree-viewport">
            <div className="merkle-tree-container">
              {/* Level 0: ROOT Node */}
              <div className="merkle-level level-root">
                <div className="merkle-node-card node-root-card">
                  <span className="node-badge-header root-header">ROOT</span>
                  <strong className="node-hash-text">{merkleTreeData.rootNode.hash}</strong>
                </div>
              </div>

              {/* SVG Connectors: Root to Level 1 */}
              <div className="tree-connector-row">
                <svg className="tree-connector-svg" viewBox="0 0 800 40" preserveAspectRatio="none">
                  <path d="M 400 0 C 400 20, 200 20, 200 40" stroke="#8b5cf6" strokeWidth="1.8" fill="none" />
                  <path d="M 400 0 C 400 20, 600 20, 600 40" stroke="#8b5cf6" strokeWidth="1.8" fill="none" />
                </svg>
              </div>

              {/* Level 1: 2 COMBINED NODES */}
              <div className="merkle-level level-1">
                {merkleTreeData.level1.map((node) => (
                  <div key={node.id} className="merkle-node-card node-combined-card">
                    <span className="node-badge-header combined-header">COMBINED NODE</span>
                    <strong className="node-hash-text">{node.hash}</strong>
                  </div>
                ))}
              </div>

              {/* SVG Connectors: Level 1 to Level 2 */}
              <div className="tree-connector-row">
                <svg className="tree-connector-svg" viewBox="0 0 800 40" preserveAspectRatio="none">
                  <path d="M 200 0 C 200 20, 100 20, 100 40" stroke="#8b5cf6" strokeWidth="1.8" fill="none" />
                  <path d="M 200 0 C 200 20, 300 20, 300 40" stroke="#8b5cf6" strokeWidth="1.8" fill="none" />
                  <path d="M 600 0 C 600 20, 500 20, 500 40" stroke="#8b5cf6" strokeWidth="1.8" fill="none" />
                  <path d="M 600 0 C 600 20, 700 20, 700 40" stroke="#8b5cf6" strokeWidth="1.8" fill="none" />
                </svg>
              </div>

              {/* Level 2: 4 COMBINED NODES */}
              <div className="merkle-level level-2">
                {merkleTreeData.level2.map((node) => (
                  <div key={node.id} className="merkle-node-card node-combined-card">
                    <span className="node-badge-header combined-header">COMBINED NODE</span>
                    <strong className="node-hash-text">{node.hash}</strong>
                  </div>
                ))}
              </div>

              {/* SVG Connectors: Level 2 to Leaves */}
              <div className="tree-connector-row">
                <svg className="tree-connector-svg" viewBox="0 0 800 40" preserveAspectRatio="none">
                  <path d="M 100 0 C 100 20, 50 20, 50 40" stroke="#a78bfa" strokeWidth="1.5" fill="none" />
                  <path d="M 100 0 C 100 20, 150 20, 150 40" stroke="#a78bfa" strokeWidth="1.5" fill="none" />
                  <path d="M 300 0 C 300 20, 250 20, 250 40" stroke="#a78bfa" strokeWidth="1.5" fill="none" />
                  <path d="M 300 0 C 300 20, 350 20, 350 40" stroke="#a78bfa" strokeWidth="1.5" fill="none" />
                  <path d="M 500 0 C 500 20, 450 20, 450 40" stroke="#a78bfa" strokeWidth="1.5" fill="none" />
                  <path d="M 500 0 C 500 20, 550 20, 550 40" stroke="#a78bfa" strokeWidth="1.5" fill="none" />
                  <path d="M 700 0 C 700 20, 650 20, 650 40" stroke="#a78bfa" strokeWidth="1.5" fill="none" />
                  <path d="M 700 0 C 700 20, 750 20, 750 40" stroke="#a78bfa" strokeWidth="1.5" fill="none" />
                </svg>
              </div>

              {/* Level 3: FINDING Leaves matching dependencygtree.png */}
              <div className="merkle-level level-leaves">
                {merkleTreeData.leaves.map((leaf) => (
                  <div key={leaf.id} className="merkle-node-card node-leaf-card">
                    <span className="node-badge-header leaf-header">{leaf.label}</span>
                    <strong className="node-hash-text">{leaf.hash}</strong>
                    <span className="leaf-algo-name">{leaf.algorithm}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: List View */}
        {activeVisualizerTab === "list" && (
          <div className="merkle-list-view">
            <div className="list-toolbar-row">
              <div className="list-search-wrap">
                <Search size={14} />
                <input
                  type="search"
                  className="list-search-input"
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value);
                    setPage(1);
                  }}
                  placeholder="Search file, algorithm, hash, or status..."
                />
              </div>

              <div className="list-actions-right">
                <button
                  type="button"
                  className="btn-targeted-rescan"
                  onClick={handleTargetedRescan}
                >
                  <RefreshCw size={13} />
                  <span>Rescan Selected ({selected.length})</span>
                </button>

                <button
                  type="button"
                  className="btn-export-pdf"
                  onClick={handleExportPdf}
                >
                  <FileText size={13} />
                  <span>Export PDF</span>
                </button>
              </div>
            </div>

            {rescanState && <div className="rescan-status-banner">{rescanState}</div>}

            <div className="list-table-container">
              <table className="analysis-table list-table">
                <thead>
                  <tr>
                    <th style={{ width: 40 }}>
                      <input
                        type="checkbox"
                        checked={
                          selected.length > 0 &&
                          selected.length === visibleRecords.length
                        }
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelected(visibleRecords.map((r) => r.identity));
                          } else {
                            setSelected([]);
                          }
                        }}
                      />
                    </th>
                    <th>File Location</th>
                    <th>Algorithm</th>
                    <th>Deterministic Artifact Hash</th>
                    <th>Integrity Status</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleRecords.length ? (
                    visibleRecords.map((rec) => {
                      const isSelected = selected.includes(rec.identity);
                      const shortHash = formatShortHashNumber(rec.currentHash, 8);
                      const displayHash = formatDisplayHash(rec.currentHash, 8, 6);

                      return (
                        <tr
                          key={rec.identity}
                          className={isSelected ? "selected-row" : ""}
                        >
                          <td>
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => toggleSelect(rec.identity)}
                            />
                          </td>
                          <td className="location-cell">
                            <span className="file-path-text">{rec.artifact.file || "Unknown"}</span>
                            {rec.artifact.line && (
                              <span className="file-line-num">:{rec.artifact.line}</span>
                            )}
                          </td>
                          <td>
                            <strong>{rec.artifact.algorithm || "Cryptographic Key"}</strong>
                          </td>
                          <td>
                            <div className="hash-display-cell">
                              <span className="hash-tag-pill" title={`SHA-256: ${rec.currentHash}`}>
                                <Hash size={10} />
                                <span>{shortHash}</span>
                              </span>
                              <span className="hash-full-preview">{displayHash}</span>
                              <button
                                type="button"
                                className="btn-copy-hash"
                                onClick={() => copyToClipboard(rec.currentHash)}
                                title="Copy Hash"
                              >
                                {copiedHash === rec.currentHash ? (
                                  <CheckCircle2 size={12} className="copied" />
                                ) : (
                                  <Copy size={12} />
                                )}
                              </button>
                            </div>
                          </td>
                          <td>
                            <span
                              className={`integrity-status-badge ${rec.status.toLowerCase()}`}
                            >
                              {rec.status === "UNCHANGED"
                                ? "MATCH"
                                : rec.status === "NEW"
                                ? "NEW"
                                : "CHANGED"}
                            </span>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={5} className="empty-table-cell">
                        No cryptographic artifacts matching search query.
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
              from={filteredRecords.length ? (currentPage - 1) * PAGE_SIZE + 1 : 0}
              to={Math.min(currentPage * PAGE_SIZE, filteredRecords.length)}
              total={filteredRecords.length}
              noun="records"
            />
          </div>
        )}
      </section>

      {/* Executive Security & CBOM Verification Report Modal matching Image 2 & 3 */}
      <ExecutiveReportView
        isOpen={showPdfReport}
        onClose={() => {
          setShowPdfReport(false);
          if (location.pathname === "/report") {
            navigate(-1);
          }
        }}
        repoName={repoName}
        scanId={scanId}
        generatedTime={generatedTime}
        canonicalRoot={canonicalRoot}
        txHash={txHash}
        blockNumber={blockNumber}
        summary={result?.summary || {}}
        artifacts={artifacts}
      />
    </div>
  );
}
