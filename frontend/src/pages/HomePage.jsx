
import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Check,
  CircleHelp,
  Clock,
  FileArchive,
  FileCode2,
  History,
  Layers,
  Loader2,
  LockKeyhole,
  Network,
  Search,
  ShieldAlert,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

import GlobalSearch from "../components/GlobalSearch";
import { makeEntityId } from "../context/entityIds";
import { useEcdatContext } from "../context/useEcdatContext";
import { scanFile } from "../services/api";
import { snapshotCurrentScan } from "../lib/artifactIntegrity";

import "../App.css";

const HISTORY_KEY = "ecdatScanHistory";
const CURRENT_SCAN_KEY = "ecdatScanResult";

const SCAN_STAGES = [
  {
    title: "Analyzing project and cryptographic files",
    detail: "Walking repository tree and extracting files",
  },
  {
    title: "Looking for cryptographic files & keys",
    detail: "Identifying asymmetric, symmetric, hash, and certificate usages",
  },
  {
    title: "Searching vulnerable files & primitives",
    detail: "Matching NIST PQC rules and legacy algorithm deprecations",
  },
  {
    title: "Scanning statements & crypto usages",
    detail: "Deep AST line inspection for quantum-vulnerable calls",
  },
  {
    title: "Evaluating post-quantum exposure",
    detail: "Computing Mosca scenario timelines and migration targets",
  },
  {
    title: "Preparing CBOM inventory and dashboard",
    detail: "Synthesizing cryptographic bill of materials and posture metrics",
  },
];

const SCAN_ACTIVITY_MESSAGES = [
  "Analyzing repository structure and discovering project files",
  "Looking for cryptographic files and certificates across directories",
  "Searching vulnerable files and legacy cryptographic primitives",
  "Scanning statements for cryptographic API usage and key lengths",
  "Evaluating post-quantum exposure and algorithmic risks",
  "Synthesizing cryptographic bill of materials (CBOM) inventory",
  "Preparing dashboard report and security posture evidence",
];

const IGNORED_DIRECTORIES = new Set([
  "node_modules",
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

  if (normalized.endsWith(".env")) {
    return ".env";
  }

  const dotIndex = normalized.lastIndexOf(".");
  return dotIndex >= 0 ? normalized.slice(dotIndex) : "";
}

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 ** 3) return `${(value / (1024 ** 2)).toFixed(1)} MB`;
  return `${(value / (1024 ** 3)).toFixed(2)} GB`;
}

function isArchivePath(path) {
  const normalized = String(path || "").toLowerCase();
  return [...ARCHIVE_EXTENSIONS].some((extension) => normalized.endsWith(extension));
}

function isTextAnalysisCandidate(file, path) {
  return !isArchivePath(path) && (
    String(file?.type || "").startsWith("text/") ||
    ![".der", ".key", ".p12", ".pfx", ".jks", ".p7b", ".p7c", ".pem", ".crt", ".cer"].includes(getExtension(path))
  );
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

  return SUPPORTED_EXTENSIONS.has(getExtension(lowerName)) ||
    String(file?.type || "").startsWith("text/") ||
    ["application/json", "application/xml", "application/javascript"].includes(file?.type);
}

function normalizeFileEntry(file, relativePath) {
  const path = safeRelativePath(relativePath || file?.name);
  const tooLarge = Number(file?.size || 0) > MAX_TEXT_FILE_SIZE &&
    isSupportedClientFile(file, path) &&
    isTextAnalysisCandidate(file, path);

  return {
    file,
    relativePath: path,
    isSupported: isSupportedClientFile(file, path),
    skipReason: tooLarge ? "Text file exceeds 10 MB analysis limit" : "",
  };
}

function getFolderRoot(relativePaths) {
  const firstPath = relativePaths.find(Boolean) || "";
  return firstPath.split("/")[0];
}

function normalizeDirectoryFileList(fileList) {
  const entries = Array.from(fileList || []);

  return entries.map((file) => {
    const originalPath = file.webkitRelativePath || file.name;
    return normalizeFileEntry(file, originalPath);
  });
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
      files.push(...await readDirectoryEntries(entry, `${prefix}${entry.name}/`));
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
  const entries = items
    .map((item) => item.webkitGetAsEntry?.())
    .filter(Boolean);

  if (!entries.length) {
    return Array.from(dataTransfer?.files || []).map((file) => normalizeFileEntry(file));
  }

  const files = [];
  for (const entry of entries) {
    if (entry.isDirectory) {
      if (!IGNORED_DIRECTORIES.has(entry.name)) {
        files.push(...await readDirectoryEntries(entry));
      }
    } else if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      files.push(normalizeFileEntry(file));
    }
  }

  return files;
}

function getHistory() {
  try {
    return JSON.parse(
      localStorage.getItem(HISTORY_KEY) || "[]"
    );
  } catch {
    return [];
  }
}

function saveScanHistory(
  result,
  originalFileName
) {
  const existing = getHistory();

  const entry = {
    id: `${Date.now()}-${Math.random()
      .toString(36)
      .slice(2, 8)}`,

    name:
      result.input?.name ||
      originalFileName ||
      "Unnamed scan",

    timestamp: new Date().toISOString(),

    result,
  };

  const updated = [
    entry,
    ...existing.filter(
      (item) => item.name !== entry.name
    ),
  ].slice(0, 10);

  localStorage.setItem(
    HISTORY_KEY,
    JSON.stringify(updated)
  );

  return entry;
}

function sleep(ms) {
  return new Promise((resolve) =>
    setTimeout(resolve, ms)
  );
}

export default function Home() {
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);
  const stageTimerRef = useRef(null);
  const activityTimerRef = useRef(null);

  useEffect(() => () => {
    if (stageTimerRef.current) {
      clearInterval(stageTimerRef.current);
    }
    if (activityTimerRef.current) {
      clearInterval(activityTimerRef.current);
    }
  }, []);

  const navigate = useNavigate();
  const { selectContext } = useEcdatContext();

  const [scanInput, setScanInput] =
    useState(null);

  const [isDragging, setIsDragging] =
    useState(false);

  const [isScanning, setIsScanning] =
    useState(false);

  const [elapsedSeconds, setElapsedSeconds] =
    useState(0);

  const [scanStage, setScanStage] =
    useState(0);

  const [scanActivityIndex, setScanActivityIndex] =
    useState(0);

  const [errorMessage, setErrorMessage] =
    useState("");

  // Live Time Loading timer
  useEffect(() => {
    if (!isScanning) return;
    const startTime = performance.now();
    const timerInterval = setInterval(() => {
      setElapsedSeconds((performance.now() - startTime) / 1000);
    }, 60);

    return () => {
      clearInterval(timerInterval);
      setElapsedSeconds(0);
    };
  }, [isScanning]);

  const setSelectedInput = (entries, sourceType, projectName = "") => {
    if (!entries.length && sourceType !== "folder") {
      return;
    }

    const firstFile = entries[0]?.file;
    const inferredSourceType = sourceType || (
      entries.length > 1
        ? "files"
        : getExtension(firstFile?.name) === ".zip"
          ? "archive"
          : "file"
    );
    const totalBytes = entries.reduce((total, entry) => total + Number(entry.file?.size || 0), 0);
    if (totalBytes > MAX_TOTAL_UPLOAD_SIZE) {
      setScanInput(null);
      setErrorMessage("Upload exceeds the ECDAT project size limit of 500 MB.");
      return;
    }

    setScanInput({
      sourceType: inferredSourceType,
      files: entries,
      displayName: projectName || firstFile?.name || "Selected project",
      totalFiles: entries.length,
      totalBytes,
    });
    setErrorMessage("");
  };

  const handleInputChange = (event) => {
    const files = Array.from(event.target.files || []);
    const hasDirectoryPaths = files.some((file) => file.webkitRelativePath);
    const entries = hasDirectoryPaths
      ? normalizeDirectoryFileList(files)
      : files.map((file) => normalizeFileEntry(file));
    setSelectedInput(
      entries,
      hasDirectoryPaths ? "folder" : entries.length > 1 ? "files" : undefined,
      files.length > 1 ? `${files.length} selected files` : files[0]?.name
    );
    event.target.value = "";
  };

  const handleFolderInputChange = (event) => {
    const files = Array.from(event.target.files || []);
    const entries = files.map((file) => normalizeFileEntry(
      file,
      file.webkitRelativePath || file.name
    ));
    const root = getFolderRoot(files.map((file) => file.webkitRelativePath));
    setSelectedInput(entries, "folder", root || "Selected folder");
    event.target.value = "";
  };

  const handleDrop = async (event) => {
    event.preventDefault();

    setIsDragging(false);

    try {
      const entries = await collectDroppedEntries(event.dataTransfer);
      const firstFile = entries[0]?.file;
      const hasDirectory = Array.from(event.dataTransfer?.items || [])
        .some((item) => item.webkitGetAsEntry?.()?.isDirectory);
      const sourceType = hasDirectory
        ? "folder"
        : entries.length > 1
          ? "files"
        : getExtension(firstFile?.name) === ".zip"
          ? "archive"
          : "file";
      setSelectedInput(
        entries,
        sourceType,
        sourceType === "folder"
          ? "Dropped project"
          : firstFile?.name
      );
    } catch {
      setErrorMessage("Unable to read the dropped files. Please try selecting them instead.");
    }
  };

  const startStageAnimation = () => {
    setScanStage(0);
    setScanActivityIndex(0);
    if (stageTimerRef.current) {
      clearInterval(stageTimerRef.current);
    }
    if (activityTimerRef.current) {
      clearInterval(activityTimerRef.current);
    }
    stageTimerRef.current =
      setInterval(() => {
        setScanStage((current) => {
          if (
            current >=
            SCAN_STAGES.length - 1
          ) {
            return current;
          }

          return current + 1;
        });
      }, 1250);

    activityTimerRef.current =
      setInterval(() => {
        setScanActivityIndex((current) => (
          (current + 1) % SCAN_ACTIVITY_MESSAGES.length
        ));
      }, 850);
  };

  const stopStageAnimation = () => {
    if (stageTimerRef.current) {
      clearInterval(stageTimerRef.current);
      stageTimerRef.current = null;
    }
    if (activityTimerRef.current) {
      clearInterval(activityTimerRef.current);
      activityTimerRef.current = null;
    }
  };

  const startScan = async () => {
    if (!scanInput || isScanning) {
      return;
    }

    setIsScanning(true);
    setErrorMessage("");

    startStageAnimation();

    const minimumDisplayTime = 7600;
    const startedAt = Date.now();

    try {
      const result = await Promise.all([
        scanFile(scanInput),
        sleep(minimumDisplayTime),
      ]).then(([scanResult]) => scanResult);

      const elapsed = Date.now() - startedAt;

      if (elapsed < minimumDisplayTime) {
        await sleep(
          minimumDisplayTime - elapsed
        );
      }

      setScanStage(SCAN_STAGES.length - 1);

      sessionStorage.setItem(
        CURRENT_SCAN_KEY,
        JSON.stringify(result)
      );

      selectContext({
        entityType: "scan",
        entityId: makeEntityId(
          "scan",
          `${result.input?.source_type || scanInput.sourceType}:${result.input?.name || scanInput.displayName}`
        ),
        name: result.input?.name || scanInput.displayName,
        sourceType: result.input?.source_type || scanInput.sourceType,
        projectName: result.input?.name || scanInput.displayName,
        fileCount: result.summary?.files_discovered || scanInput.files.length,
        scannedFileCount: result.summary?.files_scanned || 0,
        skippedFileCount: result.summary?.files_skipped || 0,
      });

      saveScanHistory(
        result,
        scanInput.displayName
      );

      snapshotCurrentScan(result);

      stopStageAnimation();

      await sleep(500);

      navigate("/dashboard", {
        state: {
          scanResult: result,
        },
      });
    } catch (error) {
      console.error(error);

      stopStageAnimation();

      setErrorMessage(
        error.message ||
          "Unable to connect to the ECDAT scanner."
      );
    } finally {
      setIsScanning(false);
    }
  };

  const removeFile = () => {
    if (isScanning) {
      return;
    }

    setScanInput(null);
    setErrorMessage("");

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }

  };

  const scrollToAbout = () => {
    document
      .getElementById("about-section")
      ?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
  };

  const scrollToUpload = () => {
    document
      .getElementById("upload-area")
      ?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
  };

  return (
    <div className="app-shell">
      {/* SIDE RAIL */}

      <aside className="side-rail">
        <div className="rail-logo-container">
          <div className="rail-logo-badge" title="ECDAT" onClick={scrollToUpload}>
            <Layers size={22} className="rail-logo-icon" />
          </div>
        </div>

        <nav className="rail-nav">
          <button
            className="rail-nav-item active"
            title="Upload"
            aria-label="Go to upload"
            onClick={scrollToUpload}
          >
            <Upload size={19} />
          </button>

          <button
            className="rail-nav-item"
            title="About ECDAT"
            aria-label="About ECDAT"
            onClick={scrollToAbout}
          >
            <CircleHelp size={19} />
          </button>
        </nav>

        <div className="rail-bottom">
          <button
            className="rail-nav-item"
            title="Scan History"
            aria-label="Scan history"
            onClick={() => {
              if (sessionStorage.getItem(CURRENT_SCAN_KEY)) {
                navigate("/dashboard");
              } else {
                scrollToUpload();
              }
            }}
          >
            <History size={19} />
          </button>
        </div>
      </aside>

      {/* MAIN */}

      <main className="main-workspace">
        <header className="home-topbar">
          <GlobalSearch variant="home" />

          <div className="workspace-label">
            Cryptographic Discovery & Assessment
          </div>
        </header>

        <div className="home-content">
          {/* HERO */}

          <section className="home-hero">
            <div className="hero-main-content">
              <div className="hero-kicker">
                <span></span>
                ECDAT · CRYPTOGRAPHIC DISCOVERY PLATFORM
              </div>

              <h1>
                Discover.
                <br />
                <span>Assess.</span>
                <br />
                Prepare.
              </h1>

              <p>
                Discover cryptographic artefacts across
                application code, libraries, certificates,
                configurations and infrastructure. Assess
                quantum exposure and prepare migration paths.
              </p>

              <div className="hero-actions">
                <button
                  className="hero-primary-button"
                  onClick={scrollToUpload}
                >
                  Start discovery
                  <ArrowRight size={16} />
                </button>

                <button
                  className="hero-secondary-button"
                  onClick={scrollToAbout}
                >
                  About ECDAT
                  <CircleHelp size={14} />
                </button>
              </div>
            </div>

            <div className="hero-visual">
              <div className="hero-orbit orbit-a"></div>
              <div className="hero-orbit orbit-b"></div>
              <div className="hero-orbit orbit-c"></div>

              <div className="hero-center-shield">
                <ShieldCheck size={34} />
              </div>

              <div className="hero-floating-card card-one">
                <LockKeyhole size={15} />
                <span>Crypto assets</span>
              </div>

              <div className="hero-floating-card card-two">
                <ShieldAlert size={15} />
                <span>Quantum risk</span>
              </div>

              <div className="hero-floating-card card-three">
                <Network size={15} />
                <span>Discovery</span>
              </div>
            </div>
          </section>

          {/* QUICK METRICS */}

          <section className="home-stat-grid">
            <div className="home-stat-card">
              <div className="home-stat-top">
                <span>Input</span>

                <div className="home-stat-icon blue">
                  <FileArchive size={16} />
                </div>
              </div>

              <strong>Any</strong>

              <small>
                Source, binary, archive, library,
                configuration or certificate
              </small>
            </div>

            <div className="home-stat-card">
              <div className="home-stat-top">
                <span>Discovery</span>

                <div className="home-stat-icon">
                  <LockKeyhole size={16} />
                </div>
              </div>

              <strong>CBOM</strong>

              <small>
                Structured cryptographic inventory
              </small>
            </div>

            <div className="home-stat-card">
              <div className="home-stat-top">
                <span>Assessment</span>

                <div className="home-stat-icon">
                  <ShieldAlert size={16} />
                </div>
              </div>

              <strong>PQC</strong>

              <small>
                Quantum risk and migration guidance
              </small>
            </div>
          </section>

          {/* UPLOAD + WORKFLOW */}

          <section
            className="home-two-column"
            id="upload-area"
          >
            <div className="upload-card">
              <div className="section-heading-row">
                <div>
                  <span className="section-kicker">
                    NEW SCAN
                  </span>

                  <h2>
                    Upload your project
                  </h2>

                  <p>
                    Submit the artefact you want ECDAT
                    to analyze.
                  </p>
                </div>

                <div className="section-corner-icon">
                  <Upload size={18} />
                </div>
              </div>

              <div
                className={`upload-drop-area ${
                  isDragging
                    ? "dragging"
                    : ""
                } ${
                  scanInput
                    ? "selected"
                    : ""
                }`}
                onDragEnter={(event) => {
                  event.preventDefault();
                  setIsDragging(true);
                }}
                onDragOver={(event) => {
                  event.preventDefault();
                  setIsDragging(true);
                }}
                onDragLeave={(event) => {
                  event.preventDefault();
                  setIsDragging(false);
                }}
                onDrop={handleDrop}
              >
                {!scanInput ? (
                  <>
                    <div className="upload-circle">
                      <Upload size={25} />
                    </div>

                    <h3>
                      {isDragging ? "DROP TO SCAN" : "DROP FILES, FOLDERS OR ARCHIVES HERE"}
                    </h3>

                    <p>
                      Source code • configuration • keys/certificates • archives
                    </p>

                    <div className="upload-choice-actions">
                      <button
                        className="upload-button"
                        onClick={() => fileInputRef.current?.click()}
                        onDoubleClick={() => folderInputRef.current?.click()}
                        title="Click to select files. Double-click to select a folder."
                      >
                        <Upload size={15} />
                        Upload / Select
                      </button>
                    </div>

                    <input
                      ref={fileInputRef}
                      type="file"
                      multiple
                      onChange={handleInputChange}
                      hidden
                    />

                    <input
                      ref={folderInputRef}
                      type="file"
                      multiple
                      webkitdirectory=""
                      directory=""
                      onChange={handleFolderInputChange}
                      hidden
                    />

                    <span className="upload-helper">
                      Drag a folder to preserve its relative paths. Generated directories are skipped:
                      node_modules, .git, dist, build, coverage, __pycache__, .venv, venv and target.
                    </span>
                  </>
                ) : (
                  <>
                    <div className="upload-circle selected">
                      {scanInput.sourceType === "folder" || scanInput.sourceType === "files" ? (
                        <FileCode2 size={25} />
                      ) : (
                        <FileArchive size={25} />
                      )}
                    </div>

                    <h3 className="selected-name">
                      {scanInput.displayName}
                    </h3>

                    <div className="upload-input-summary">
                      <span>
                        Project / Upload <strong>{scanInput.displayName}</strong>
                      </span>
                      <span>
                        Files discovered <strong>{scanInput.totalFiles}</strong>
                      </span>
                      <span>
                        Total size <strong>{formatBytes(scanInput.totalBytes)}</strong>
                      </span>
                      <span>
                        Supported for analysis <strong>{scanInput.files.filter((entry) => entry.isSupported && !entry.skipReason).length}</strong>
                      </span>
                      <span>
                        Skipped <strong>{scanInput.files.filter((entry) => entry.skipReason || !entry.isSupported).length}</strong>
                      </span>
                    </div>

                    {scanInput.files.length > 0 && scanInput.files.length <= 8 && (
                      <div className="upload-file-list">
                        {scanInput.files.map((entry) => (
                          <span key={entry.relativePath}>
                            {entry.relativePath}
                            {(entry.skipReason || !entry.isSupported) && " · skipped"}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="selected-actions">
                      <button
                        className="btn-start-scan btn-start-scan-dark"
                        onClick={startScan}
                        disabled={isScanning}
                      >
                        {isScanning ? (
                          <>
                            <span className="mini-spinner"></span>
                            <span>Scanning...</span>
                          </>
                        ) : (
                          <>
                            <Activity size={15} />
                            <span>Start Scan</span>
                            <ArrowRight size={15} />
                          </>
                        )}
                      </button>

                      <button className="remove-button" onClick={removeFile} disabled={isScanning}>
                        <X size={15} /> Change upload
                      </button>
                    </div>
                  </>
                )}
              </div>

              {errorMessage && (
                <div className="upload-error">
                  <ShieldAlert size={15} />

                  <span>
                    {errorMessage}
                  </span>
                </div>
              )}
            </div>

            <div className="workflow-card">
              <div className="section-heading-row">
                <div>
                  <span className="section-kicker">
                    WORKFLOW
                  </span>

                  <h2>
                    How ECDAT works
                  </h2>
                </div>
              </div>

              <div className="workflow-list">
                <WorkflowItem
                  number="01"
                  icon={<Upload size={16} />}
                  title="Upload"
                  description="Submit a project or cryptographic artefact."
                />

                <WorkflowItem
                  number="02"
                  icon={<Search size={16} />}
                  title="Discover"
                  description="Find algorithms, certificates, keys and protocols."
                />

                <WorkflowItem
                  number="03"
                  icon={<ShieldAlert size={16} />}
                  title="Assess"
                  description="Identify quantum-vulnerable and weak cryptography."
                />

                <WorkflowItem
                  number="04"
                  icon={<ShieldCheck size={16} />}
                  title="Recommend"
                  description="Generate PQC and hybrid migration guidance."
                />
              </div>
            </div>
          </section>

          {/* ABOUT */}

          <section
            className="discovery-section"
            id="about-section"
          >
            <div className="discovery-heading">
              <div>
                <span className="section-kicker">
                  ABOUT ECDAT
                </span>

                <h2>
                  Understand your
                  <br />
                  cryptographic landscape.
                </h2>
              </div>

              <p>
                ECDAT discovers and catalogs cryptographic
                artefacts across application source code,
                libraries, certificates, configurations,
                binaries and infrastructure. The results
                provide the foundation for quantum-risk
                assessment and migration planning.
              </p>
            </div>

            <div className="discovery-types">
              <DiscoveryType
                icon={<FileCode2 size={20} />}
                title="Source Code"
                description="Java, Python, JavaScript, C, C++, Go and more"
              />

              <DiscoveryType
                icon={<Network size={20} />}
                title="Configurations"
                description="TLS, SSH, application and deployment settings"
              />

              <DiscoveryType
                icon={<LockKeyhole size={20} />}
                title="Certificates & Keys"
                description="PEM, CRT, CER and key material metadata"
              />

              <DiscoveryType
                icon={<FileArchive size={20} />}
                title="Libraries"
                description="JAR, WAR and packaged dependencies"
              />

              <DiscoveryType
                icon={<ShieldCheck size={20} />}
                title="Containers"
                description="Docker and container-related artefacts"
              />

              <DiscoveryType
                icon={<Activity size={20} />}
                title="Binaries"
                description="Compiled artefacts and native files"
              />
            </div>
          </section>
        </div>
      </main>

      {/* SCAN PROCESSING OVERLAY */}

      {isScanning && (
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
              <h3 className="scan-live-title">{SCAN_STAGES[scanStage]?.title || "Analyzing..."}</h3>
              <p className="scan-live-message">
                {SCAN_ACTIVITY_MESSAGES[scanActivityIndex]}
              </p>
            </div>

            {/* Dynamic Progress Bar */}
            <div className="scan-progress-bar-wrap">
              <div
                className="scan-progress-bar-fill"
                style={{
                  width: `${Math.min(100, Math.round(((scanStage + 1) / SCAN_STAGES.length) * 100))}%`,
                }}
              />
            </div>
            <div className="scan-progress-meta-row">
              <span>Target: <strong>{scanInput?.displayName || "Project"}</strong></span>
              <span>{Math.min(100, Math.round(((scanStage + 1) / SCAN_STAGES.length) * 100))}%</span>
            </div>

            {/* Stages List */}
            <div className="scan-stages-stepper">
              {SCAN_STAGES.map((stage, idx) => {
                const isComplete = idx < scanStage;
                const isCurrent = idx === scanStage;
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

function WorkflowItem({
  number,
  icon,
  title,
  description,
}) {
  return (
    <div className="workflow-item">
      <div className="workflow-number">
        {number}
      </div>

      <div className="workflow-icon">
        {icon}
      </div>

      <div className="workflow-text">
        <strong>{title}</strong>

        <span>
          {description}
        </span>
      </div>

      <ArrowUpRight
        size={15}
        className="workflow-arrow"
      />
    </div>
  );
}

function DiscoveryType({
  icon,
  title,
  description,
}) {
  return (
    <div className="discovery-type-card">
      <div className="discovery-type-icon">
        {icon}
      </div>

      <div>
        <strong>{title}</strong>

        <span>
          {description}
        </span>
      </div>

      <ArrowUpRight
        size={15}
        className="discovery-arrow"
      />
    </div>
  );
}

