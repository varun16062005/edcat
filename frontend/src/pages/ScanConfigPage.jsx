import { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  Check,
  Clock,
  FileArchive,
  FileCode2,
  FolderOpen,
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
  const tooLarge =
    Number(file?.size || 0) > MAX_TEXT_FILE_SIZE &&
    isSupportedClientFile(file, path) &&
    !isArchivePath(path);

  return {
    file,
    relativePath: path,
    isSupported: isSupportedClientFile(file, path),
    skipReason: tooLarge ? "Text file exceeds 10 MB analysis limit" : "",
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

  // Live Time Loading timer
  useEffect(() => {
    if (!scanning) return;
    const startTime = performance.now();
    const timerInterval = setInterval(() => {
      setElapsedSeconds((performance.now() - startTime) / 1000);
    }, 60);

    return () => {
      clearInterval(timerInterval);
      setElapsedSeconds(0);
    };
  }, [scanning]);

  // Staged scan animation timers
  useEffect(() => {
    if (!scanning) return;
    const stageInterval = setInterval(() => {
      setScanStageIndex((curr) => (curr < SCAN_STAGES.length - 1 ? curr + 1 : curr));
    }, 850);

    const messageInterval = setInterval(() => {
      setScanMessageIndex((curr) => (curr + 1) % SCAN_ACTIVITY_MESSAGES.length);
    }, 1100);

    return () => {
      clearInterval(stageInterval);
      clearInterval(messageInterval);
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

    if (totalBytes > MAX_TOTAL_UPLOAD_SIZE) {
      setErrorMessage(`Total upload size exceeds limit of ${formatBytes(MAX_TOTAL_UPLOAD_SIZE)}.`);
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

      // Guarantee minimum duration (4.0s) so the user experiences the live loading timer & all 4 statements
      const minDurationPromise = new Promise((resolve) => setTimeout(resolve, 4000));
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
            <p>Supports single files, multiple files, folders, and ZIP / TAR archives up to 500 MB</p>

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

        {/* Action Bar (matching Cancel & Start Scan from Scanpage.png) */}
        <div className="scan-action-bar">
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
      </section>

      {/* Staged Scan Animation Modal / Overlay */}
      {scanning && (
        <div className="scan-progress-modal-backdrop" role="dialog" aria-modal="true">
          <div className="scan-progress-modal">
            {/* Animated Radar Scanning Orb */}
            <div className="scan-radar-visual">
              <div className="scan-radar-ring ring-1" />
              <div className="scan-radar-ring ring-2" />
              <div className="scan-radar-ring ring-3" />
              <div className="scan-radar-sweep" />
              <div className="scan-radar-core">
                <FileCode2 size={24} className="scan-core-icon" />
              </div>
            </div>

            <div className="scan-progress-header">
              <div className="scan-timer-pill">
                <Clock size={14} className="timer-spin" />
                <span>Time Loading: {elapsedSeconds.toFixed(1)}s</span>
              </div>
              <h3 className="scan-live-title">{SCAN_STAGES[scanStageIndex]?.title || "Analyzing..."}</h3>
              <p className="scan-live-message">
                {SCAN_ACTIVITY_MESSAGES[scanMessageIndex]}
              </p>
            </div>

            {/* Dynamic Progress Bar */}
            <div className="scan-progress-bar-wrap">
              <div
                className="scan-progress-bar-fill"
                style={{
                  width: `${Math.min(100, Math.round(((scanStageIndex + 1) / SCAN_STAGES.length) * 100))}%`,
                }}
              />
            </div>
            <div className="scan-progress-meta-row">
              <span>Target: <strong>{displayName}</strong></span>
              <span>{Math.min(100, Math.round(((scanStageIndex + 1) / SCAN_STAGES.length) * 100))}%</span>
            </div>

            {/* Stages List */}
            <div className="scan-stages-stepper">
              {SCAN_STAGES.map((stage, idx) => {
                const isComplete = idx < scanStageIndex;
                const isCurrent = idx === scanStageIndex;
                return (
                  <div
                    key={stage.title}
                    className={`scan-stage-step ${isComplete ? "complete" : ""} ${
                      isCurrent ? "current" : ""
                    }`}
                  >
                    <div className="step-indicator">
                      {isComplete ? (
                        <Check size={14} className="check-icon" />
                      ) : isCurrent ? (
                        <Loader2 size={13} className="step-spinner spin-active" />
                      ) : (
                        <span>{idx + 1}</span>
                      )}
                    </div>
                    <div className="step-content">
                      <span className="step-label">{stage.title}</span>
                      <small className="step-detail">{stage.detail}</small>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
