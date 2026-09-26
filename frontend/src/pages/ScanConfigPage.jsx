import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowRight,
  Check,
  Clock,
  FileArchive,
  FileCode2,
  FolderOpen,
  HardDrive,
  Loader2,
  ShieldAlert,
  Upload,
  X,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

import { scanFile } from "../services/api";
import { snapshotCurrentScan } from "../lib/artifactIntegrity";

const HISTORY_KEY = "ecdatScanHistory";
const CURRENT_SCAN_KEY = "ecdatScanResult";

const SCAN_STAGES = [
  {
    title: "Analyzing...",
    detail: "Parsing source architecture and extracting cryptographic primitives",
  },
  {
    title: "Looking for cryptographic files...",
    detail: "Scanning certificates, private keys, keystores, and configuration tokens",
  },
  {
    title: "Searching vulnerable files...",
    detail: "Matching legacy ciphers, weak hashing algorithms, and insecure key lengths",
  },
  {
    title: "Scanning statements...",
    detail: "Deep inspecting cryptographic API invocations and cipher suite declarations",
  },
  {
    title: "Synthesizing CBOM & Quantum Exposure...",
    detail: "Correlating findings, calculating Mosca urgency, and generating posture metrics",
  },
];

const SCAN_ACTIVITY_MESSAGES = [
  "Walking the selected project tree and cataloging source files...",
  "Looking for cryptographic files, PEM keys, and credentials...",
  "Searching vulnerable files and legacy cryptographic references...",
  "Scanning statements for deprecated ciphers and insecure APIs...",
  "Calculating Mosca migration urgency & Quantum Exposure Score...",
  "Building cryptographic inventory and artifact integrity hashes...",
  "Finalizing CBOM synthesis for security dashboard...",
];

const IGNORED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  ".venv",
  "venv",
  "__pycache__",
  ".next",
  "dist",
  "build",
]);

const SUPPORTED_EXTENSIONS = new Set([
  ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts",
  ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".php",
  ".rb", ".swift", ".m", ".mm", ".dart", ".scala", ".ex", ".exs",
  ".erl", ".fs", ".fsx", ".html", ".css", ".json", ".yaml",
  ".yml", ".xml", ".toml", ".ini", ".conf", ".cfg", ".properties",
  ".env", ".cnf", ".sh", ".bash", ".sql", ".md", ".pem", ".crt", ".cer",
  ".der", ".key", ".csr", ".p12", ".pfx", ".jks", ".p7b", ".p7c", ".zip", ".tar", ".gz", ".tgz",
]);

const MAX_TOTAL_UPLOAD_SIZE = 500 * 1024 * 1024;
const MAX_TEXT_FILE_SIZE = 10 * 1024 * 1024;
const ARCHIVE_EXTENSIONS = new Set([".zip", ".tar", ".gz", ".tgz", ".tar.gz"]);

function getExtension(path) {
  const normalized = String(path || "").toLowerCase();
  if (normalized.endsWith(".env")) return ".env";
  const dotIndex = normalized.lastIndexOf(".");
  return dotIndex >= 0 ? normalized.slice(dotIndex) : "";
}

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value === 0) return "0 B";
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 ** 3) return `${(value / (1024 ** 2)).toFixed(1)} MB`;
  return `${(value / (1024 ** 3)).toFixed(2)} GB`;
}

function isArchivePath(path) {
  const normalized = String(path || "").toLowerCase();
  return [...ARCHIVE_EXTENSIONS].some((ext) => normalized.endsWith(ext));
}

function safeRelativePath(path, fallback = "uploaded-file") {
  const normalized = String(path || fallback).replaceAll("\\", "/");
  const parts = normalized.split("/").filter((part) => part && part !== "." && part !== "..");
  return parts.join("/") || fallback;
}

function isSupportedClientFile(file, relativePath) {
  const lowerName = String(relativePath || file?.name || "").toLowerCase();
  if (
    lowerName.endsWith("/dockerfile") ||
    lowerName.endsWith("/containerfile") ||
    lowerName === "dockerfile" ||
    lowerName === "containerfile"
  ) {
    return true;
  }
  return (
    SUPPORTED_EXTENSIONS.has(getExtension(lowerName)) ||
    String(file?.type || "").startsWith("text/") ||
    ["application/json", "application/xml", "application/javascript"].includes(file?.type)
  );
}

function normalizeFileEntry(file, relativePath) {
  const path = safeRelativePath(relativePath || file?.name);

  return {
    file,
    relativePath: path,
    isSupported: isSupportedClientFile(file, path),
    skipReason: "",
  };
}

async function readDirectoryEntries(directoryEntry, prefix = "") {
  const reader = directoryEntry.createReader();
  const entries = [];
  while (true) {
    const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    if (!batch.length) break;
    entries.push(...batch);
  }
  const files = [];
  for (const entry of entries) {
    if (entry.isDirectory) {
      if (IGNORED_DIRECTORIES.has(entry.name)) continue;
      files.push(...(await readDirectoryEntries(entry, `${prefix}${entry.name}/`)));
      continue;
    }
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      files.push(normalizeFileEntry(file, `${prefix}${file.name}`));
    }
  }
  return files;
}

async function collectDroppedEntries(dataTransfer) {
  const items = Array.from(dataTransfer?.items || []);
  const entries = items.map((item) => item.webkitGetAsEntry?.()).filter(Boolean);
  if (!entries.length) {
    return Array.from(dataTransfer?.files || []).map((file) => normalizeFileEntry(file));
  }
  const files = [];
  for (const entry of entries) {
    if (entry.isDirectory) {
      if (!IGNORED_DIRECTORIES.has(entry.name)) {
        files.push(...(await readDirectoryEntries(entry)));
      }
    } else if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      files.push(normalizeFileEntry(file));
    }
  }
  return files;
}

function saveScanHistory(result, originalFileName) {
  try {
    const existing = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    const entry = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      name: result.input?.name || originalFileName || "Unnamed scan",
      timestamp: new Date().toISOString(),
      result,
    };
    const updated = [entry, ...existing.filter((item) => item.name !== entry.name)].slice(0, 15);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
  } catch {
    // Local storage is best effort
  }
}

export default function ScanConfigPage() {
  const navigate = useNavigate();

  // Selection & Input State
  const [selectedEntries, setSelectedEntries] = useState([]);
  const [projectName, setProjectName] = useState("");
  const [sourceType, setSourceType] = useState("file");
  const [dragActive, setDragActive] = useState(false);

  // Capability Toggles (matching Scanpage.png)
  const [cryptoAnalysis, setCryptoAnalysis] = useState(true);
  const [quantumAnalysis, setQuantumAnalysis] = useState(true);
  const [cbomGeneration, setCbomGeneration] = useState(true);
  const [advancedLayers, setAdvancedLayers] = useState(true);

  // Scan Execution State
  const [scanning, setScanning] = useState(false);
  const [scanStageIndex, setScanStageIndex] = useState(0);
  const [scanMessageIndex, setScanMessageIndex] = useState(0);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [errorMessage, setErrorMessage] = useState("");

  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);
  const archiveInputRef = useRef(null);

  // Pre-scan summary calculations
  const totalBytes = selectedEntries.reduce((sum, item) => sum + Number(item.file?.size || 0), 0);

  const detectedLanguages = Array.from(
    new Set(
      selectedEntries
        .map((entry) => getExtension(entry.relativePath))
        .filter(Boolean)
        .map((ext) => {
          const map = {
            ".py": "Python",
            ".js": "JavaScript",
            ".jsx": "React JSX",
            ".ts": "TypeScript",
            ".tsx": "React TSX",
            ".java": "Java",
            ".go": "Go",
            ".rs": "Rust",
            ".c": "C",
            ".cpp": "C++",
            ".pem": "PEM Certificate",
            ".key": "Private Key",
            ".crt": "Certificate",
            ".json": "JSON",
            ".yaml": "YAML",
            ".yml": "YAML",
            ".env": "Env Config",
            ".zip": "ZIP Archive",
            ".tar": "TAR Archive",
          };
          return map[ext] || ext.slice(1).toUpperCase();
        })
    )
  ).slice(0, 5);

  const displayName =
    projectName ||
    (selectedEntries.length === 1
      ? selectedEntries[0].file.name
      : selectedEntries.length > 1
      ? `${selectedEntries[0].relativePath.split("/")[0] || "project"}`
      : "Ready for scan");

  const displayLanguages =
    detectedLanguages.length > 0 ? detectedLanguages.join(", ") : "Ready";

  // Approximate time calculation based on memory of the file (guaranteed 7-10s pacing)
  const approxEstimate = useMemo(() => {
    const mb = totalBytes / (1024 * 1024);
    if (mb <= 0.5) return { text: "~7–8s", targetSec: 8.0, isLarge: false };
    if (mb <= 3) return { text: "~7–9s", targetSec: 8.5, isLarge: false };
    if (mb <= 10) return { text: "~8–10s", targetSec: 9.2, isLarge: false };
    if (mb <= 25) return { text: "~10–14s", targetSec: 12.0, isLarge: false };
    if (mb <= 60) return { text: "~18–30s", targetSec: 25.0, isLarge: true };
    if (mb <= 100) return { text: "~35–55s", targetSec: 45.0, isLarge: true };
    return { text: "~1–2 mins", targetSec: 90.0, isLarge: true };
  }, [totalBytes]);

  const currentStepIndex = useMemo(() => {
    const target = approxEstimate.targetSec;
    const ratio = Math.min(1, elapsedSeconds / target);
    if (ratio < 0.30) return 0;
    if (ratio < 0.65) return 1;
    if (ratio < 0.88) return 2;
    return 3;
  }, [approxEstimate.targetSec, elapsedSeconds]);

  // Clean sequential steps without infinite looping
  const currentScanStepTitle = useMemo(() => {
    if (currentStepIndex === 0) return "Scanning project files...";
    if (currentStepIndex === 1) return "Searching for cryptographic files...";
    if (currentStepIndex === 2) return "Thinking...";
    return "Finalizing security intelligence...";
  }, [currentStepIndex]);

  const scanPercent = useMemo(() => {
    const target = approxEstimate.targetSec;
    const ratio = Math.min(0.98, (elapsedSeconds / target) * 0.96);
    return Math.max(8, Math.round(ratio * 100));
  }, [approxEstimate.targetSec, elapsedSeconds]);

  // Live Timer with strict 2-minute (120s) safety cutoff
  useEffect(() => {
    if (!scanning) return;
    const startTime = performance.now();
    const timerInterval = setInterval(() => {
      const elapsed = (performance.now() - startTime) / 1000;
      setElapsedSeconds(elapsed);
      if (elapsed >= 120) {
        setScanning(false);
        setErrorMessage(
          "Scan exceeded the 2-minute safety limit. The repository or archive may contain deep recursion or large compiled artifacts. Please select specific source files or smaller archives."
        );
      }
    }, 60);

    return () => {
      clearInterval(timerInterval);
      setElapsedSeconds(0);
    };
  }, [scanning]);

  const handleFilesChosen = (files, type = "files") => {
    const list = Array.from(files || []);
    if (!list.length) return;
    setErrorMessage("");
    const normalized = list.map((file) =>
      normalizeFileEntry(file, file.webkitRelativePath || file.name)
    );
    setSelectedEntries(normalized);
    setSourceType(type);

    if (type === "folder") {
      const rootFolder = (normalized[0]?.relativePath || "").split("/")[0];
      setProjectName(rootFolder || "project-folder");
    } else if (type === "archive") {
      setProjectName(list[0]?.name || "archive");
    } else {
      setProjectName(list.length === 1 ? list[0].name : "selected-files");
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    setErrorMessage("");

    try {
      const entries = await collectDroppedEntries(e.dataTransfer);
      if (!entries.length) return;
      setSelectedEntries(entries);
      const isSingleArchive =
        entries.length === 1 && isArchivePath(entries[0].relativePath || entries[0].file.name);
      setSourceType(isSingleArchive ? "archive" : entries.length > 1 ? "folder" : "file");
      setProjectName(
        isSingleArchive
          ? entries[0].file.name
          : entries[0].relativePath.split("/")[0] || entries[0].file.name
      );
    } catch (err) {
      setErrorMessage("Could not process dropped items: " + (err.message || String(err)));
    }
  };

  const handleClearSelection = () => {
    setSelectedEntries([]);
    setProjectName("");
    setSourceType("file");
    setErrorMessage("");
  };

  const handleStartScan = async () => {
    if (!selectedEntries.length) {
      setErrorMessage("Please select or drop files or a folder to scan.");
      return;
    }

    setScanning(true);
    setScanStageIndex(0);
    setScanMessageIndex(0);
    setElapsedSeconds(0);
    setErrorMessage("");

    try {
      const scanInput = {
        sourceType,
        projectName: displayName,
        files: selectedEntries,
      };

      // Ensure any file scan waits 7-10 seconds to enter dashboard
      const minWaitMs = Math.min(10000, Math.max(7800, Math.round(approxEstimate.targetSec * 1000)));
      const minDurationPromise = new Promise((resolve) => setTimeout(resolve, minWaitMs));
      const [result] = await Promise.all([
        scanFile(scanInput),
        minDurationPromise,
      ]);

      // Save to browser session
      sessionStorage.setItem(CURRENT_SCAN_KEY, JSON.stringify(result));
      snapshotCurrentScan(result);
      saveScanHistory(result, displayName);

      // Brief completion delay to finish visual stage before navigating
      setTimeout(() => {
        setScanning(false);
        navigate("/dashboard");
      }, 500);
    } catch (err) {
      setScanning(false);
      setErrorMessage(
        err.message || "Scan failed. Ensure backend service is reachable on http://127.0.0.1:8000."
      );
    }
  };

  return (
    <div className="scan-config-page">
      {/* Repository Overview Heading (matches Scanpage.png) */}
      <div className="scan-section-heading">
        <h2>Repository Overview</h2>
      </div>

      {/* Repository Overview Strip (matches Scanpage.png) */}
      <section className="repo-overview-strip" aria-label="Repository Overview">
        <div className="repo-overview-card">
          <span className="repo-overview-label">REPOSITORY NAME</span>
          <strong className="repo-overview-value" title={displayName}>
            {displayName}
          </strong>
        </div>
        <div className="repo-overview-card">
          <span className="repo-overview-label">REPOSITORY SIZE</span>
          <strong className="repo-overview-value">
            {selectedEntries.length ? formatBytes(totalBytes) : "0 B"}
          </strong>
        </div>
        <div className="repo-overview-card">
          <span className="repo-overview-label">FILES</span>
          <strong className="repo-overview-value">
            {selectedEntries.length
              ? `${selectedEntries.length} file${selectedEntries.length === 1 ? "" : "s"}`
              : "0 files"}
          </strong>
        </div>
        <div className="repo-overview-card">
          <span className="repo-overview-label">LANGUAGES / FILE TYPES</span>
          <strong className="repo-overview-value" title={displayLanguages}>
            {displayLanguages}
          </strong>
        </div>
      </section>

      {/* Scan Configuration Card (matches Scanpage.png) */}
      <section className="scan-configuration-card">
        <div className="scan-config-header">
          <h2>Scan Configuration</h2>
          <p>Configure detection modules and inspection layers for cryptographic analysis.</p>
        </div>

        <div className="scan-config-toggles">
          {/* Toggle 1: Cryptographic Analysis */}
          <div className="scan-toggle-row">
            <div className="scan-toggle-info">
              <strong>Cryptographic Analysis</strong>
              <p>Detect vulnerable algorithms, hardcoded keys, and outdated protocols.</p>
            </div>
            <label className="ecdat-switch">
              <input
                type="checkbox"
                checked={cryptoAnalysis}
                onChange={(e) => setCryptoAnalysis(e.target.checked)}
                aria-label="Toggle Cryptographic Analysis"
              />
              <span className="slider round" />
            </label>
          </div>

          {/* Toggle 2: Quantum Risk Analysis */}
          <div className="scan-toggle-row">
            <div className="scan-toggle-info">
              <strong>Quantum Risk Analysis</strong>
              <p>Identify algorithms vulnerable to future quantum computing attacks.</p>
            </div>
            <label className="ecdat-switch">
              <input
                type="checkbox"
                checked={quantumAnalysis}
                onChange={(e) => setQuantumAnalysis(e.target.checked)}
                aria-label="Toggle Quantum Risk Analysis"
              />
              <span className="slider round" />
            </label>
          </div>

          {/* Toggle 3: CBOM Generation */}
          <div className="scan-toggle-row">
            <div className="scan-toggle-info">
              <strong>CBOM Generation</strong>
              <p>Generate a Cryptography Bill of Materials under the CycloneDX specification.</p>
            </div>
            <label className="ecdat-switch">
              <input
                type="checkbox"
                checked={cbomGeneration}
                onChange={(e) => setCbomGeneration(e.target.checked)}
                aria-label="Toggle CBOM Generation"
              />
              <span className="slider round" />
            </label>
          </div>

          {/* Toggle 4: Advanced Detection Layers */}
          <div className="scan-toggle-row advanced-layers-row">
            <div className="scan-toggle-info">
              <strong>Advanced Detection Layers</strong>
              <p>Enable multi-layer detection (AST, Pattern/Regex, Entropy & Secrets, SCA, Certificate, Binary).</p>
              <div className="detection-layers-badges">
                <span className="layer-badge"><Check size={12} /> AST Layer</span>
                <span className="layer-badge"><Check size={12} /> Pattern / Regex Layer</span>
                <span className="layer-badge"><Check size={12} /> Entropy & Secrets Layer</span>
                <span className="layer-badge"><Check size={12} /> SCA Layer</span>
                <span className="layer-badge"><Check size={12} /> Certificate Analysis</span>
                <span className="layer-badge"><Check size={12} /> Binary Analysis</span>
              </div>
            </div>
            <label className="ecdat-switch">
              <input
                type="checkbox"
                checked={advancedLayers}
                onChange={(e) => setAdvancedLayers(e.target.checked)}
                aria-label="Toggle Advanced Detection Layers"
              />
              <span className="slider round" />
            </label>
          </div>
        </div>

        {/* Universal Dropzone for selection */}
        <div
          className={`scan-dropzone ${dragActive ? "drag-active" : ""} ${
            selectedEntries.length ? "has-files" : ""
          }`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <div className="dropzone-center-content">
            <div className="dropzone-icon-wrap">
              <Upload size={32} className="dropzone-icon" />
            </div>
            <h3>Drop your project, archive, or certificate files here</h3>
            <p>Supports single files, multiple files, folders, and ZIP / TAR archives</p>

            <div className="dropzone-button-group">
              <button
                type="button"
                className="btn-select"
                onClick={() => fileInputRef.current?.click()}
              >
                <FileCode2 size={16} />
                <span>Select Files</span>
              </button>
              <button
                type="button"
                className="btn-select"
                onClick={() => folderInputRef.current?.click()}
              >
                <FolderOpen size={16} />
                <span>Select Folder</span>
              </button>
              <button
                type="button"
                className="btn-select"
                onClick={() => archiveInputRef.current?.click()}
              >
                <FileArchive size={16} />
                <span>Select ZIP / TAR</span>
              </button>
            </div>

            {/* Hidden native inputs */}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              style={{ display: "none" }}
              onChange={(e) => handleFilesChosen(e.target.files, "files")}
            />
            <input
              ref={folderInputRef}
              type="file"
              // @ts-expect-error webkitdirectory attribute
              webkitdirectory=""
              directory=""
              style={{ display: "none" }}
              onChange={(e) => handleFilesChosen(e.target.files, "folder")}
            />
            <input
              ref={archiveInputRef}
              type="file"
              accept=".zip,.tar,.gz,.tgz"
              style={{ display: "none" }}
              onChange={(e) => handleFilesChosen(e.target.files, "archive")}
            />
          </div>

          {/* Selected files preview */}
          {selectedEntries.length > 0 && (
            <div className="selected-files-summary">
              <div className="summary-header">
                <span>
                  Ready to scan: <strong>{selectedEntries.length} files</strong> ({formatBytes(totalBytes)})
                </span>
                <button
                  type="button"
                  className="btn-clear"
                  onClick={handleClearSelection}
                  title="Clear file selection"
                >
                  <X size={14} /> Clear
                </button>
              </div>
              <ul className="selected-file-list">
                {selectedEntries.slice(0, 5).map((entry, idx) => (
                  <li key={`${entry.relativePath}-${idx}`}>
                    <span className="file-path">{entry.relativePath}</span>
                    <span className="file-size">{formatBytes(entry.file.size)}</span>
                  </li>
                ))}
                {selectedEntries.length > 5 && (
                  <li className="more-files">
                    +{selectedEntries.length - 5} more files prepared for analysis
                  </li>
                )}
              </ul>
            </div>
          )}
        </div>

        {/* Error message */}
        {errorMessage && (
          <div className="scan-error-alert" role="alert">
            <ShieldAlert size={18} />
            <span>{errorMessage}</span>
          </div>
        )}

        <div className="scan-action-bar">
          <div style={{ display: "flex", gap: "12px", alignItems: "center", marginLeft: "auto" }}>
            <button
              type="button"
              className="btn-cancel"
              onClick={handleClearSelection}
              disabled={scanning || !selectedEntries.length}
            >
              Cancel
            </button>
            <button
              type="button"
              className="btn-start-scan"
              onClick={handleStartScan}
              disabled={scanning || !selectedEntries.length}
            >
            {scanning ? (
              <>
                <span className="spinner" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <span>Start Scan</span>
                <ArrowRight size={16} />
              </>
            )}
          </button>
          </div>
        </div>
      </section>

      {/* COMPACT INDEPENDENT SCANNING WINDOW */}
      {scanning && (
        <div className="compact-scan-modal-backdrop" role="dialog" aria-modal="true">
          <div className="compact-scan-window enhanced">
            <div className="compact-scan-topbar">
              <div className="compact-scan-target-pill">
                <span className="compact-pulse-dot" />
                <span className="compact-target-name">{displayName || "Target"}</span>
              </div>
              <span className="compact-file-size">
                {formatBytes(totalBytes || 0)}
              </span>
            </div>

            <div className="compact-scan-body">
              <div className="compact-scan-spinner-wrap">
                <div className="compact-spinner-ring outer" />
                <div className="compact-spinner-ring inner" />
                <div className="compact-spinner-core">
                  <FileCode2 size={18} className="compact-core-icon" />
                </div>
              </div>

              <div className="compact-scan-info">
                <div className="compact-scan-step-title animate-step" key={currentScanStepTitle}>
                  {currentScanStepTitle}
                </div>
                <div className="compact-scan-sub">Deep cryptographic AST & quantum audit</div>
              </div>
            </div>

            {/* Visual Micro-Stages Row */}
            <div className="compact-stages-track">
              <div className={`compact-stage-pill ${currentStepIndex >= 0 ? "active" : ""}`}>
                <span className="stage-pill-dot" />
                <span>Scan</span>
              </div>
              <div className={`compact-stage-pill ${currentStepIndex >= 1 ? "active" : ""}`}>
                <span className="stage-pill-dot" />
                <span>Crypto</span>
              </div>
              <div className={`compact-stage-pill ${currentStepIndex >= 2 ? "active" : ""}`}>
                <span className="stage-pill-dot" />
                <span>Thinking</span>
              </div>
              <div className={`compact-stage-pill ${currentStepIndex >= 3 ? "active" : ""}`}>
                <span className="stage-pill-dot" />
                <span>Finalize</span>
              </div>
            </div>

            <div className="compact-scan-timing-section">
              <div className="compact-timing-pill approx">
                <Clock size={13} className="timer-spin" />
                <span className="timing-label">Approx Time:</span>
                <span className="timing-value">{approxEstimate.text}</span>
              </div>
              <div className="compact-timing-pill elapsed">
                <span className="timing-label">Elapsed:</span>
                <span className="timing-value">{elapsedSeconds.toFixed(1)}s</span>
              </div>
            </div>

            <div className="compact-progress-bar-wrap">
              <div
                className="compact-progress-bar-fill animated-shimmer"
                style={{ width: `${scanPercent}%` }}
              />
            </div>

            {(approxEstimate.isLarge || elapsedSeconds > 12) && (
              <div className="compact-scan-advisory">
                <ShieldAlert size={14} className="advisory-icon" />
                <span>Larger file detected: Deep analysis may take up to 2 mins.</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
