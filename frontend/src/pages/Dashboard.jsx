import {
  Archive,
  ArrowLeft,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  Code2,
  Download,
  FileArchive,
  FileCode2,
  Filter,
  HardDrive,
  History,
  KeyRound,
  Lightbulb,
  LockKeyhole,
  Network,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import {
  Fragment,
  useMemo,
  useEffect,
  useState,
} from "react";

import {
  useLocation,
  useNavigate,
} from "react-router-dom";

import {
  generatePdfReport,
} from "../services/api";
import GlobalSearch from "../components/GlobalSearch";
import DependencyExplorer from "../components/DependencyExplorer";
import QuantumEraScenario from "../components/QuantumEraScenario";
import { useEcdatContext } from "../context/useEcdatContext";
import { artifactEntityId, makeEntityId } from "../context/entityIds";


const CURRENT_SCAN_KEY =
  "ecdatScanResult";

const HISTORY_KEY =
  "ecdatScanHistory";

const PAGE_SIZE = 15;

function getPaginationPages(
  totalPages,
  currentPage
) {
  if (totalPages <= 7) {
    return Array.from(
      { length: totalPages },
      (_, index) => index + 1
    );
  }

  const pages = [1];
  const start = Math.max(2, currentPage - 1);
  const end = Math.min(totalPages - 1, currentPage + 1);

  if (start > 2) {
    pages.push("ellipsis-start");
  }

  for (let page = start; page <= end; page += 1) {
    pages.push(page);
  }

  if (end < totalPages - 1) {
    pages.push("ellipsis-end");
  }

  pages.push(totalPages);
  return pages;
}

function PaginationControls({
  currentPage,
  totalPages,
  onPageChange,
}) {
  if (totalPages <= 1) {
    return null;
  }

  return (
    <nav
      className="dashboard-pagination"
      aria-label="Pagination"
    >
      <button
        type="button"
        disabled={currentPage === 1}
        onClick={() =>
          onPageChange(
            Math.max(1, currentPage - 1)
          )
        }
      >
        Previous
      </button>

      <div className="dashboard-pagination-pages">
        {getPaginationPages(
          totalPages,
          currentPage
        ).map((page) =>
          typeof page === "number" ? (
            <button
              type="button"
              className={
                page === currentPage
                  ? "active"
                  : ""
              }
              aria-current={
                page === currentPage
                  ? "page"
                  : undefined
              }
              key={page}
              onClick={() =>
                onPageChange(page)
              }
            >
              {page}
            </button>
          ) : (
            <span
              className="dashboard-pagination-ellipsis"
              key={page}
            >
              ...
            </span>
          )
        )}
      </div>

      <button
        type="button"
        disabled={currentPage === totalPages}
        onClick={() =>
          onPageChange(
            Math.min(totalPages, currentPage + 1)
          )
        }
      >
        Next
      </button>
    </nav>
  );
}


/* ============================================================
   STORAGE
   ============================================================ */

function getStoredHistory() {
  try {
    return JSON.parse(
      localStorage.getItem(
        HISTORY_KEY
      ) || "[]"
    );
  } catch {
    return [];
  }
}


function getInitialResult(
  location
) {
  if (
    location.state?.scanResult
  ) {
    return location.state.scanResult;
  }

  const saved =
    sessionStorage.getItem(
      CURRENT_SCAN_KEY
    );

  if (!saved) {
    return null;
  }

  try {
    return JSON.parse(saved);
  } catch {
    sessionStorage.removeItem(
      CURRENT_SCAN_KEY
    );

    return null;
  }
}


/* ============================================================
   SECURITY POSTURE
   ============================================================ */

function derivePosture(
  summary
) {
  if (
    (summary.critical || 0) > 0
  ) {
    return {
      key: "CRITICAL",
      label: "Highly Critical",
      description:
        "Critical cryptographic findings are present and should be prioritized for immediate remediation.",
      className: "critical",
    };
  }

  if (
    (summary.high || 0) > 0 ||
    (summary.quantum_vulnerable || 0) > 0
  ) {
    return {
      key: "HIGH",
      label: "High Risk",
      description:
        "Quantum-vulnerable or high-risk cryptographic assets require migration planning.",
      className: "high",
    };
  }

  if (
    (summary.medium || 0) > 0 ||
    (summary.legacy_weak || 0) > 0
  ) {
    return {
      key: "ELEVATED",
      label: "Elevated",
      description:
        "Weak, legacy or review-required cryptography was identified.",
      className: "elevated",
    };
  }

  return {
    key: "NORMAL",
    label: "Normal",
    description:
      "No critical or high-risk cryptographic findings were identified by the current scanner.",
    className: "normal",
  };
}


/* ============================================================
   FILE TYPES
   ============================================================ */

function getFileTypeInfo(
  type
) {
  const value =
    String(type || "")
      .toLowerCase();

  if (
    value === "source-code"
  ) {
    return {
      label: "Source Code",
      icon: Code2,
    };
  }

  if (
    value === "configuration"
  ) {
    return {
      label: "Configuration",
      icon: FileCode2,
    };
  }

  if (
    value === "certificate"
  ) {
    return {
      label: "Certificates",
      icon: KeyRound,
    };
  }

  if (
    value === "private-key"
  ) {
    return {
      label: "Private Keys",
      icon: LockKeyhole,
    };
  }

  if (
    value === "public-key"
  ) {
    return {
      label: "Public Keys",
      icon: KeyRound,
    };
  }

  if (
    value === "key-material"
  ) {
    return {
      label: "Key Material",
      icon: KeyRound,
    };
  }

  if (
    value === "archive"
  ) {
    return {
      label: "Archives",
      icon: FileArchive,
    };
  }

  if (
    value === "library"
  ) {
    return {
      label: "Libraries",
      icon: Archive,
    };
  }

  if (
    value === "container"
  ) {
    return {
      label: "Containers",
      icon: Archive,
    };
  }

  if (
    value === "text"
  ) {
    return {
      label: "Text",
      icon: FileCode2,
    };
  }

  return {
    label: type || "Binary",
    icon: HardDrive,
  };
}


/* ============================================================
   STATUS
   ============================================================ */

function getRiskClass(
  risk
) {
  return `risk-badge ${String(
    risk || ""
  ).toLowerCase()}`;
}


function getQuantumClass(
  status
) {
  if (
    status === "VULNERABLE"
  ) {
    return "quantum-badge vulnerable";
  }

  if (
    status === "LEGACY_WEAK"
  ) {
    return "quantum-badge legacy";
  }

  if (
    status === "REVIEW"
  ) {
    return "quantum-badge review";
  }

  return "quantum-badge safe";
}


function getQuantumLabel(
  status
) {
  switch (status) {
    case "VULNERABLE":
      return "Vulnerable";

    case "LEGACY_WEAK":
      return "Legacy / Weak";

    case "NOT_CURRENTLY_QUANTUM_VULNERABLE":
      return "Protected";

    case "REVIEW":
      return "Review";

    default:
      return status || "Unknown";
  }
}


function formatDate(
  value
) {
  try {
    return new Date(
      value
    ).toLocaleString(
      [],
      {
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }
    );
  } catch {
    return "Unknown";
  }
}

function displayFilePath(file) {
  if (!file) return "Unknown file";
  if (typeof file === "string") return file;
  return file.path || file.name || "Unknown file";
}

function displayEntityName(value, fallback = "Selected entity") {
  if (!value) return fallback;
  if (typeof value === "string" || typeof value === "number") return value;
  return value.name || value.path || fallback;
}

function extractRecommendationTargets(recommendation, targets) {
  const source = [
    ...(Array.isArray(targets) ? targets : []),
    recommendation,
  ]
    .filter(Boolean)
    .join(" ");
  const ignoredTerms = new Set([
    "AES",
    "APPROVED",
    "ALGORITHM",
    "CURRENT",
    "DES",
    "ECC",
    "HYBRID",
    "KEM",
    "MODERN",
    "PQC",
    "RECOMMENDED",
    "REPLACE",
    "SIGNATURE",
    "SYMMETRIC",
  ]);
  const matches = source.match(/\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b|\b[A-Z]{2,}[0-9]{0,4}\b/g) || [];

  return [...new Set(
    matches.filter((match) => !ignoredTerms.has(match))
  )];
}


/* ============================================================
   EXPORT
   ============================================================ */

function downloadFile(
  content,
  fileName,
  contentType
) {
  const blob =
    new Blob(
      [content],
      {
        type: contentType,
      }
    );

  const url =
    URL.createObjectURL(
      blob
    );

  const link =
    document.createElement(
      "a"
    );

  link.href = url;
  link.download =
    fileName;

  document.body.appendChild(
    link
  );

  link.click();

  link.remove();

  URL.revokeObjectURL(
    url
  );
}



/* ============================================================
   CBOM EXPORT
   ============================================================ */

function buildEcdatCbom(
  scanResult,
  artifacts
) {
  if (
    scanResult?.cbom &&
    typeof scanResult.cbom === "object"
  ) {
    return scanResult.cbom;
  }

  const components =
    artifacts.map(
      (artifact, index) => ({
        type: "cryptographic-asset",
        "bom-ref":
          `ecdat-crypto-${index + 1}`,
        name:
          artifact.algorithm ||
          artifact.category ||
          `Cryptographic Asset ${index + 1}`,
        properties: [
          ["file", artifact.file],
          ["line", artifact.line],
          ["category", artifact.category],
          ["key_size", artifact.key_size],
          ["mode", artifact.mode],
          [
            "quantum_status",
            artifact.quantum_status,
          ],
          ["risk", artifact.risk],
          [
            "business_criticality",
            artifact.business_criticality,
          ],
          [
            "recommendation",
            artifact.recommendation,
          ],
        ]
          .filter(
            ([, value]) =>
              value !== undefined &&
              value !== null &&
              value !== ""
          )
          .map(
            ([name, value]) => ({
              name,
              value: String(value),
            })
          ),
      })
    );

  return {
    bomFormat: "ECDAT-CBOM",
    specVersion: "1.0",
    version: 1,
    serialNumber:
      `urn:uuid:ecdat-${Date.now()}`,
    metadata: {
      timestamp:
        new Date().toISOString(),
      tool: {
        vendor: "ECDAT",
        name:
          "Cryptographic Discovery & Assessment Toolkit",
      },
      source:
        scanResult?.input?.name ||
        "Uploaded project",
    },
    summary:
      scanResult?.summary || {},
    components,
  };
}

function getCbomComponentValue(
  component,
  name,
  fallback = "—"
) {
  if (
    component?.[name] !== undefined &&
    component?.[name] !== null &&
    component?.[name] !== ""
  ) {
    return String(component[name]);
  }

  const property =
    Array.isArray(component?.properties)
      ? component.properties.find(
          (item) => item?.name === name
        )
      : null;

  return property?.value !== undefined &&
    property?.value !== null &&
    property?.value !== ""
    ? String(property.value)
    : fallback;
}

/* ============================================================
   SUMMARY CARD
   ============================================================ */

function DashboardSummary({
  label,
  value,
  description,
  icon,
  light = false,
  tone = "",
}) {
  return (
    <div
      className={`dashboard-summary-card ${
        light ? "light" : ""
      } ${tone}`}
    >
      <div className="summary-top">
        <span>
          {label}
        </span>

        <div className="summary-icon">
          {icon}
        </div>
      </div>

      <strong>
        {value}
      </strong>

      <small>
        {description}
      </small>
    </div>
  );
}


/* ============================================================
   MAIN DASHBOARD
   ============================================================ */

function Dashboard() {
  const navigate =
    useNavigate();

  const location =
    useLocation();

  const {
    selectedContext,
    selectContext,
    clearContext,
  } = useEcdatContext();

  /*
   * IMPORTANT:
   *
   * There is NO selectedArtifact state here.
   *
   * The previous implementation opened a right-side
   * artifact drawer using selectedArtifact.
   *
   * That has intentionally been removed.
   */

  const [
    scanResult,
    setScanResult,
  ] = useState(() =>
    getInitialResult(
      location
    )
  );

  const [
    history,
    setHistory,
  ] = useState(
    getStoredHistory
  );

  const [
    searchTerm,
    setSearchTerm,
  ] = useState("");

  const [
    riskFilter,
    setRiskFilter,
  ] = useState("ALL");

  const [
    typeFilter,
    setTypeFilter,
  ] = useState("ALL");

  const [
    quantumFilter,
    setQuantumFilter,
  ] = useState("ALL");

  const [
    assetPage,
    setAssetPage,
  ] = useState(1);

  const [
    recommendationPage,
    setRecommendationPage,
  ] = useState(1);

  const [
    expandedArtifactIndex,
    setExpandedArtifactIndex,
  ] = useState(null);

  const [
    cbomSearchTerm,
    setCbomSearchTerm,
  ] = useState("");

  const [
    cbomCopied,
    setCbomCopied,
  ] = useState(false);

  const [
    pdfLoading,
    setPdfLoading,
  ] = useState(false);


  const [
    analysisView,
    setAnalysisView,
  ] = useState("footprint");

  useEffect(() => {
    if (!selectedContext) {
      return;
    }

    const syncTimer = window.setTimeout(() => {
      if (
        selectedContext.entityType === "history" &&
        selectedContext.result
      ) {
        setScanResult(selectedContext.result);
        setSearchTerm("");
        setRiskFilter("ALL");
        setTypeFilter("ALL");
        setQuantumFilter("ALL");
      }

      if (
        selectedContext.entityType === "artifact" ||
        selectedContext.entityType === "algorithm"
      ) {
        setSearchTerm(
          selectedContext.algorithm ||
            selectedContext.name ||
            ""
        );
        setRiskFilter("ALL");
        setTypeFilter("ALL");
        setQuantumFilter("ALL");
      }

      const target =
        selectedContext.source === "cbom"
          ? "cbom"
          : selectedContext.source === "dependency"
            ? "risk-analysis"
          : selectedContext.entityType === "file"
          ? "discovered-content"
          : selectedContext.entityType === "history"
            ? "dashboard-overview"
            : selectedContext.entityType === "scan"
              ? "dashboard-overview"
            : selectedContext.entityType === "algorithm"
              ? "risk-analysis"
              : "inventory";

      document
        .getElementById(target)
        ?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
    }, 0);

    return () => window.clearTimeout(syncTimer);
  }, [selectedContext]);

  useEffect(() => {
    if (!location.state?.scanResult) {
      return undefined;
    }

    const frame = window.requestAnimationFrame(() => {
      window.scrollTo({
        top: 0,
        left: 0,
        behavior: "auto",
      });
    });

    return () => window.cancelAnimationFrame(frame);
  }, [location.key, location.state?.scanResult]);

  /* ==========================================================
     DATA
     ========================================================== */

  const summary =
    scanResult?.summary || {
      files_scanned: 0,
      crypto_assets: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      quantum_vulnerable: 0,
      legacy_weak: 0,
      recommendations: 0,
      risk_score: 0,
    };

  const files = useMemo(
    () => scanResult?.files || [],
    [scanResult]
  );

  const artifacts = useMemo(
    () => scanResult?.artifacts || [],
    [scanResult]
  );

  const dependencies = useMemo(
    () => scanResult?.dependencies || {
      nodes: [],
      edges: [],
      meta: {},
    },
    [scanResult]
  );

  const cbom = useMemo(
    () => buildEcdatCbom(scanResult, artifacts),
    [scanResult, artifacts]
  );

  const cbomComponents = useMemo(
    () => (Array.isArray(cbom?.components) ? cbom.components : []),
    [cbom]
  );

  const cbomJson = useMemo(
    () => JSON.stringify(cbom, null, 2),
    [cbom]
  );

  const filteredCbomComponents = useMemo(() => {
    const query = cbomSearchTerm.trim().toLowerCase();

    if (!query) {
      return cbomComponents;
    }

    return cbomComponents.filter((component) => {
      const properties = Array.isArray(component.properties)
        ? component.properties
            .map((property) => `${property.name || ""} ${property.value || ""}`)
            .join(" ")
        : "";
      const searchable = [
        component.name,
        getCbomComponentValue(component, "file", ""),
        getCbomComponentValue(component, "category", ""),
        getCbomComponentValue(component, "risk", ""),
        getCbomComponentValue(component, "quantum_status", ""),
        getCbomComponentValue(component, "recommendation", ""),
        properties,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return searchable.includes(query);
    });
  }, [cbomComponents, cbomSearchTerm]);

  const posture =
    summary.security_posture ||
    derivePosture(
      summary
    );

  const quantumExposure =
    summary.crypto_assets > 0
      ? Math.round(
          ((summary.quantum_vulnerable || 0) /
            summary.crypto_assets) *
            100
        )
      : 0;


  /* ==========================================================
     FILE TYPE COUNTS
     ========================================================== */

  const fileTypes =
    useMemo(() => {
      const counts = {};

      files.forEach(
        (file) => {
          const type =
            file.type ||
            "binary";

          counts[type] =
            (counts[type] || 0) +
            1;
        }
      );

      return Object.entries(
        counts
      ).sort(
        (a, b) =>
          b[1] - a[1]
      );
    }, [files]);


  /* ==========================================================
     CATEGORIES
     ========================================================== */

  const categories =
    useMemo(
      () => [
        ...new Set(
          artifacts
            .map(
              (artifact) =>
                artifact.category
            )
            .filter(Boolean)
        ),
      ],
      [artifacts]
    );


  /* ==========================================================
     ALGORITHM COUNTS
     ========================================================== */

  const algorithms =
    useMemo(() => {
      const counts = {};

      artifacts.forEach(
        (artifact) => {
          const algorithm =
            artifact.algorithm ||
            "Unknown";

          counts[algorithm] =
            (counts[algorithm] ||
              0) + 1;
        }
      );

      return Object.entries(
        counts
      ).sort(
        (a, b) =>
          b[1] - a[1]
      );
    }, [artifacts]);

  /* ==========================================================
     FILTERED ARTIFACTS
     ========================================================== */

  const filteredArtifacts =
    useMemo(() => {
      const query =
        searchTerm
          .trim()
          .toLowerCase();

      return artifacts.filter(
        (artifact) => {
          const searchable =
            [
              artifact.file,
              artifact.algorithm,
              artifact.category,
              artifact.key_size,
              artifact.mode,
              artifact.business_criticality,
              artifact.data_sensitivity,
              artifact.recommendation,
            ]
              .filter(Boolean)
              .join(" ")
              .toLowerCase();

          const matchesSearch =
            !query ||
            searchable.includes(
              query
            );

          const matchesRisk =
            riskFilter === "ALL" ||
            artifact.risk ===
              riskFilter;

          const matchesType =
            typeFilter === "ALL" ||
            artifact.category ===
              typeFilter;

          const matchesQuantum =
            quantumFilter ===
              "ALL" ||
            artifact.quantum_status ===
              quantumFilter;

          return (
            matchesSearch &&
            matchesRisk &&
            matchesType &&
            matchesQuantum
          );
        }
      );
    }, [
      artifacts,
      searchTerm,
      riskFilter,
      typeFilter,
      quantumFilter,
    ]);

  const assetTotalPages =
    Math.ceil(
      filteredArtifacts.length / PAGE_SIZE
    );

  const effectiveAssetPage =
    assetTotalPages > 0
      ? Math.min(assetPage, assetTotalPages)
      : 1;

  const paginatedArtifacts =
    useMemo(() => {
      const start =
        (effectiveAssetPage - 1) * PAGE_SIZE;

      return filteredArtifacts.slice(
        start,
        start + PAGE_SIZE
      );
    }, [
      effectiveAssetPage,
      filteredArtifacts,
    ]);


  /* ==========================================================
     RECOMMENDATION COUNTS
     ========================================================== */

  const recommendations =
    useMemo(
      () => {
        const seenFiles = new Set();

        return artifacts
          .map((artifact, index) => {
            const rawTargets =
              artifact.migration_targets ||
              artifact.recommendation_detail
                ?.migration_targets ||
              [];
            const targets = Array.isArray(rawTargets)
              ? rawTargets.filter(Boolean).map(String)
              : rawTargets
                ? [String(rawTargets)]
                : [];
            const recommendation =
              typeof artifact.recommendation === "string"
                ? artifact.recommendation.trim()
                : "";
            const risk = String(artifact.risk || "").toUpperCase();
            const isActionable =
              Boolean(recommendation || targets.length) &&
              (
                risk !== "LOW" ||
                artifact.quantum_status === "VULNERABLE" ||
                artifact.quantum_status === "LEGACY_WEAK"
              );

            const fileKey =
              artifact.file ||
              artifactEntityId(artifact, index);

            if (
              !isActionable ||
              seenFiles.has(fileKey)
            ) {
              return null;
            }

            seenFiles.add(fileKey);

            return isActionable
              ? {
                  artifact,
                  index,
                  targets,
                  recommendation,
                }
              : null;
          })
          .filter(Boolean);
      },
      [artifacts]
    );

  const recommendationCount =
    useMemo(
      () => recommendations.length,
      [recommendations]
    );

  const recommendationTotalPages =
    Math.ceil(
      recommendations.length / PAGE_SIZE
    );

  const effectiveRecommendationPage =
    recommendationTotalPages > 0
      ? Math.min(
          recommendationPage,
          recommendationTotalPages
        )
      : 1;

  const paginatedRecommendations =
    useMemo(() => {
      const start =
        (effectiveRecommendationPage - 1) * PAGE_SIZE;

      return recommendations.slice(
        start,
        start + PAGE_SIZE
      );
    }, [
      effectiveRecommendationPage,
      recommendations,
    ]);



  /* ==========================================================
     SCROLL
     ========================================================== */

  const scrollTo = (
    id
  ) => {
    document
      .getElementById(id)
      ?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
  };


  /* ==========================================================
     HISTORY
     ========================================================== */

  const loadHistoryEntry =
    (entry) => {
      if (
        !entry?.result
      ) {
        return;
      }

      setScanResult(
        entry.result
      );

      selectContext({
        entityType: "scan",
        entityId: makeEntityId(
          "scan",
          `${entry.result?.input?.source_type || entry.result?.input?.type || "scan"}:${entry.name}`
        ),
        name: entry.name,
        sourceType: entry.result?.input?.source_type || "file",
        projectName: entry.name,
        fileCount: entry.result?.summary?.files_discovered || entry.result?.summary?.files_scanned || 0,
        scannedFileCount: entry.result?.summary?.files_scanned || 0,
        skippedFileCount: entry.result?.summary?.files_skipped || 0,
      });

      sessionStorage.setItem(
        CURRENT_SCAN_KEY,
        JSON.stringify(
          entry.result
        )
      );

      setSearchTerm("");
      setRiskFilter("ALL");
      setTypeFilter("ALL");
      setQuantumFilter(
        "ALL"
      );

      window.scrollTo({
        top: 0,
        behavior: "smooth",
      });
    };


  const clearHistory = () => {
    localStorage.removeItem(
      HISTORY_KEY
    );

    setHistory([]);
  };


  /* ==========================================================
     EXPORT JSON
     ========================================================== */

  const exportJSON = () => {
    downloadFile(
      JSON.stringify(
        scanResult,
        null,
        2
      ),
      "ecdat-scan-report.json",
      "application/json"
    );
  };


  /* ==========================================================
     EXPORT CSV
     ========================================================== */

  const exportCSV = () => {
    if (
      !artifacts.length
    ) {
      return;
    }

    const headers = [
      "File",
      "Line",
      "Algorithm",
      "Category",
      "Key Size",
      "Mode",
      "Quantum Status",
      "Risk",
      "Business Criticality",
      "Recommendation",
      "Migration Targets",
    ];

    const rows =
      artifacts.map(
        (artifact) => [
          artifact.file,
          artifact.line,
          artifact.algorithm,
          artifact.category,
          artifact.key_size,
          artifact.mode,
          artifact.quantum_status,
          artifact.risk,
          artifact.business_criticality,
          artifact.recommendation,
          (
            artifact.migration_targets ||
            []
          ).join(
            " | "
          ),
        ]
      );

    const quote =
      (value) =>
        `"${String(
          value ?? ""
        ).replaceAll(
          '"',
          '""'
        )}"`;

    const csv = [
      headers,
      ...rows,
    ]
      .map(
        (row) =>
          row
            .map(
              quote
            )
            .join(",")
      )
      .join("\n");

    downloadFile(
      csv,
      "ecdat-inventory.csv",
      "text/csv;charset=utf-8"
    );
  };



  /* ==========================================================
     EXPORT CBOM
     ========================================================== */

  const exportCBOM = () => {
    downloadFile(
      cbomJson,
      "ecdat-cbom.json",
      "application/json"
    );
  };

  const copyCBOM = async () => {
    if (
      !artifacts.length ||
      !navigator.clipboard?.writeText
    ) {
      return;
    }

    try {
      await navigator.clipboard.writeText(
        cbomJson
      );
      setCbomCopied(true);
      window.setTimeout(
        () => setCbomCopied(false),
        1600
      );
    } catch {
      setCbomCopied(false);
    }
  };


  /* ==========================================================
     EXPORT PDF
     ========================================================== */

  const exportPDF =
    async () => {
      setPdfLoading(true);

      try {
        await generatePdfReport(
          scanResult
        );
      } catch (error) {
        window.alert(
          error?.message ||
            "Unable to generate PDF report."
        );
      } finally {
        setPdfLoading(
          false
        );
      }
    };


  /* ==========================================================
     EMPTY STATE
     ========================================================== */

  if (!scanResult) {
    return (
      <div className="dashboard-empty">
        <div className="dashboard-empty-logo">
          <img
            src="/ecdat-logo.png"
            alt="ECDAT"
          />
        </div>

        <h2>
          No scan available
        </h2>

        <p>
          Upload a project or
          cryptographic artifact
          from the ECDAT homepage.
        </p>

        <button
          className="dashboard-primary-button"
          onClick={() =>
            navigate("/")
          }
        >
          <ArrowLeft size={15} />
          Back to upload
        </button>
      </div>
    );
  }


  /* ==========================================================
     DASHBOARD
     ========================================================== */

  return (
    <div className="dashboard-shell">

      {/* ======================================================
          SIDE RAIL
      ====================================================== */}

      <aside className="dashboard-rail">

        <div className="dashboard-logo-container">
          <img
            src="/ecdat-logo.png"
            alt="ECDAT"
            className="ecdat-logo"
          />
        </div>

        <nav className="dashboard-rail-nav">

          <button
            className="dashboard-rail-item active"
            title="Dashboard"
            onClick={() =>
              scrollTo(
                "dashboard-overview"
              )
            }
          >
            <Network size={19} />
          </button>


          <button
            className="dashboard-rail-item"
            title="Discovery"
            onClick={() =>
              scrollTo(
                "discovered-content"
              )
            }
          >
            <Search size={19} />
          </button>


          <button
            className="dashboard-rail-item"
            title="Algorithm footprint"
            onClick={() =>
              scrollTo(
                "risk-analysis"
              )
            }
          >
            <BarChart3
              size={19}
            />
          </button>


          <button
            className="dashboard-rail-item"
            title="Cryptographic assets"
            onClick={() =>
              scrollTo(
                "inventory"
              )
            }
          >
            <LockKeyhole
              size={19}
            />
          </button>


          <button
            className="dashboard-rail-item"
            title="Recommendations"
            onClick={() =>
              scrollTo(
                "recommendations"
              )
            }
          >
            <Lightbulb
              size={19}
            />
          </button>


          <button
            className="dashboard-rail-item"
            title="CBOM"
            onClick={() =>
              scrollTo(
                "cbom"
              )
            }
          >
            <FileCode2 size={19} />
          </button>


          <button
            className="dashboard-rail-item"
            title="History"
            onClick={() =>
              scrollTo(
                "history"
              )
            }
          >
            <History size={19} />
          </button>

        </nav>


        <div className="dashboard-rail-bottom">

          <button
            className="dashboard-rail-item"
            title="Back to upload"
            onClick={() =>
              navigate("/")
            }
          >
            <ArrowLeft size={19} />
          </button>

        </div>

      </aside>


      {/* ======================================================
          MAIN
      ====================================================== */}

      <main className="dashboard-main">

        {/* ====================================================
            TOP BAR
        ==================================================== */}

        <header className="dashboard-topbar">

          <GlobalSearch variant="dashboard" />


          <div className="dashboard-title-mini">
            ECDAT ANALYSIS WORKSPACE
          </div>


          <div
            className={`dashboard-top-posture ${posture.className}`}
          >
            <span></span>

            {posture.label}
          </div>

        </header>


        <div
          className="dashboard-content"
          id="dashboard-overview"
        >

          {/* ==================================================
              HEADER
          ================================================== */}

          <section className="report-header">

            <div>

              <span className="section-kicker">
                CRYPTOGRAPHIC RESULTS
              </span>

              <h1>
                Security intelligence
              </h1>

              <p>
                {
                  scanResult.input?.name ||
                  "Uploaded project"
                }
                {" · "}
                {
                  formatDate(
                    location.state
                      ?.historyEntry
                      ?.timestamp ||
                      new Date()
                  )
                }
              </p>

            </div>


            <div className="report-actions">

              <button
                className="dashboard-secondary-button"
                onClick={
                  exportPDF
                }
                disabled={
                  pdfLoading
                }
              >
                <Download size={14} />

                {pdfLoading
                  ? "Generating..."
                  : "PDF"}
              </button>


              <button
                className="dashboard-secondary-button"
                onClick={
                  exportCSV
                }
                disabled={
                  !artifacts.length
                }
              >
                <Download size={14} />
                CSV
              </button>


              <button
                className="dashboard-secondary-button"
                onClick={
                  exportJSON
                }
              >
                <Download size={14} />
                JSON
              </button>

              <button
                className="dashboard-secondary-button cbom-button"
                onClick={
                  exportCBOM
                }
                disabled={
                  !artifacts.length
                }
              >
                <FileCode2 size={14} />
                CBOM
              </button>


              <button
                className="dashboard-primary-button"
                onClick={() =>
                  navigate("/")
                }
              >
                New Scan
              </button>

            </div>

          </section>

          {selectedContext && (
            <div className="ecdat-context-indicator">
              <div className="ecdat-context-label">
                <span>CONTEXT</span>
                <strong>
                  {displayEntityName(selectedContext.name)}
                </strong>
              </div>

              <div className="ecdat-context-detail">
                {selectedContext.file && (
                  <span>
                    {displayFilePath(selectedContext.file)}
                    {selectedContext.line
                      ? ` : ${selectedContext.line}`
                      : ""}
                  </span>
                )}

                {selectedContext.entityType === "scan" && (
                  <span>
                    {selectedContext.sourceType || "scan"}
                    {selectedContext.fileCount !== undefined
                      ? ` · ${selectedContext.fileCount} files`
                      : ""}
                    {selectedContext.skippedFileCount
                      ? ` · ${selectedContext.skippedFileCount} skipped`
                      : ""}
                  </span>
                )}

                {(selectedContext.risk ||
                  selectedContext.quantumStatus) && (
                  <span>
                    {selectedContext.risk || "STATUS UNKNOWN"}
                    {selectedContext.quantumStatus
                      ? ` · ${selectedContext.quantumStatus.replaceAll("_", " ")}`
                      : ""}
                  </span>
                )}
              </div>

              <button
                type="button"
                onClick={clearContext}
              >
                Clear context
              </button>
            </div>
          )}


          {/* ==================================================
              FLOW
          ================================================== */}

          <section className="analysis-flow">

            <FlowStep
              number="01"
              title="Discover"
              description="Inventory assets"
              icon={
                <Search size={18} />
              }
            />

            <div className="analysis-flow-line"></div>

            <FlowStep
              number="02"
              title="Assess"
              description="Identify risk"
              icon={
                <ShieldAlert
                  size={18}
                />
              }
            />

            <div className="analysis-flow-line"></div>

            <FlowStep
              number="03"
              title="Recommend"
              description="Plan migration"
              icon={
                <Lightbulb
                  size={18}
                />
              }
            />

            <div className="analysis-flow-line"></div>

            <FlowStep
              number="04"
              title="Inspect"
              description="Open evidence"
              icon={
                <Code2 size={18} />
              }
            />

          </section>


          {/* ==================================================
              SUMMARY CARDS
          ================================================== */}

          <section className="dashboard-summary-grid">

            <DashboardSummary
              label="Files"
              value={
                summary.files_scanned
              }
              description={`${summary.files_skipped || 0} skipped · ${summary.files_discovered || summary.files_scanned || 0} discovered`}
              icon={
                <FileCode2
                  size={16}
                />
              }
              light
              tone="files-tile"
            />


            <DashboardSummary
              label="Crypto assets"
              value={
                summary.crypto_assets
              }
              description="Detected artifacts"
              icon={
                <LockKeyhole
                  size={16}
                />
              }
              tone="crypto-tile"
            />


            <DashboardSummary
              label="Critical"
              value={
                summary.critical
              }
              description="Immediate attention"
              icon={
                <ShieldAlert
                  size={16}
                />
              }
            />


            <DashboardSummary
              label="High"
              value={
                summary.high
              }
              description="Priority findings"
              icon={
                <ShieldAlert
                  size={16}
                />
              }
            />


            <DashboardSummary
              label="Quantum vulnerable"
              value={
                summary.quantum_vulnerable
              }
              description="PQC planning required"
              icon={
                <ShieldAlert
                  size={16}
                />
              }
            />


            <DashboardSummary
              label="Recommendations"
              value={
                recommendationCount
              }
              description="Findings with guidance"
              icon={
                <Lightbulb
                  size={16}
                />
              }
            />

          </section>


          {/* ==================================================
              SECURITY POSTURE
          ================================================== */}

          <section
            className={`security-posture-card ${posture.className}`}
          >

            <div className="security-posture-left">

              <div className="security-posture-icon">

                {posture.key ===
                "NORMAL" ? (
                  <ShieldCheck
                    size={22}
                  />
                ) : (
                  <ShieldAlert
                    size={22}
                  />
                )}

              </div>


              <div>

                <span className="section-kicker">
                  SECURITY POSTURE
                </span>

                <h2>
                  {posture.label}
                </h2>

                <p>
                  {
                    posture.description
                  }
                </p>

              </div>

            </div>


            <div className="security-posture-metrics">

              <div>
                <span>
                  Critical
                </span>

                <strong>
                  {summary.critical}
                </strong>
              </div>


              <div>
                <span>
                  High
                </span>

                <strong>
                  {summary.high}
                </strong>
              </div>


              <div>
                <span>
                  Quantum
                </span>

                <strong>
                  {
                    summary.quantum_vulnerable
                  }
                </strong>
              </div>


              <div>
                <span>
                  Exposure
                </span>

                <strong>
                  {quantumExposure}%
                </strong>
              </div>

            </div>

          </section>


          <QuantumEraScenario artifacts={artifacts} />


          {/* ==================================================
              DISCOVERED CONTENT
          ================================================== */}

          <section
            className="dashboard-card"
            id="discovered-content"
          >

            <div className="dashboard-card-header">

              <div>

                <span className="section-kicker">
                  DISCOVERED CONTENT
                </span>

                <h2>
                  Available in this upload
                </h2>

              </div>


              <div className="card-count">
                {files.length} files
              </div>

            </div>


            <div className="content-type-grid">

              {fileTypes.map(
                ([type, count]) => {
                  const info =
                    getFileTypeInfo(
                      type
                    );

                  const Icon =
                    info.icon;

                  return (
                    <button
                      className="content-type-card"
                      key={type}
                      onClick={() =>
                        scrollTo(
                          "inventory"
                        )
                      }
                    >

                      <div className="content-type-icon">
                        <Icon size={19} />
                      </div>


                      <div className="content-type-copy">

                        <strong>
                          {info.label}
                        </strong>

                        <span>
                          {count}{" "}
                          {count === 1
                            ? "file"
                            : "files"}
                        </span>

                      </div>


                      <ArrowUpRight
                        size={15}
                        className="content-type-arrow"
                      />

                    </button>
                  );
                }
              )}


              {!fileTypes.length && (
                <div className="no-data-message">
                  No files discovered.
                </div>
              )}

            </div>

          </section>



          {/* ==================================================
              CBOM EXTRACTION
          ================================================== */}

          <section
            className="dashboard-card cbom-extraction-card"
            id="cbom"
          >

            <div className="dashboard-card-header">

              <div>

                <span className="section-kicker">
                  CBOM EXTRACTION
                </span>

                <h2>
                  Cryptographic Bill of Materials
                </h2>

                <p className="cbom-description">
                  Build a structured cryptographic inventory
                  from the current scan and export it as a
                  machine-readable JSON file.
                </p>

              </div>

              <div className="cbom-header-icon">
                <FileCode2 size={20} />
              </div>

            </div>


            <div className="cbom-direct-layout">

              <div className="cbom-structured-column">

                <div className="cbom-summary-grid">

                  <div>
                    <span>CBOM format</span>
                    <strong>{cbom.bomFormat || "ECDAT-CBOM"}</strong>
                  </div>

                  <div>
                    <span>Specification</span>
                    <strong>{cbom.specVersion || "1.0"}</strong>
                  </div>

                  <div>
                    <span>Components</span>
                    <strong>{cbomComponents.length}</strong>
                  </div>

                  <div>
                    <span>Source</span>
                    <strong>{cbom.metadata?.source || scanResult?.input?.name || "Current scan"}</strong>
                  </div>

                  <div>
                    <span>Generated</span>
                    <strong>{cbom.metadata?.timestamp ? formatDate(cbom.metadata.timestamp) : "Current scan"}</strong>
                  </div>

                </div>


                <div className="cbom-components-heading">

                  <div>
                    <span className="section-kicker">COMPONENT INVENTORY</span>
                    <h3>Cryptographic components</h3>
                  </div>

                  <div className="inventory-search cbom-search">
                    <Search size={14} />
                    <input
                      value={cbomSearchTerm}
                      onChange={(event) => setCbomSearchTerm(event.target.value)}
                      placeholder="Search CBOM"
                      aria-label="Search CBOM"
                    />
                  </div>

                </div>


                {!artifacts.length ? (
                  <div className="cbom-empty-state">
                    <FileCode2 size={20} />
                    <strong>No cryptographic assets detected.</strong>
                  </div>
                ) : (
                  <div className="cbom-component-table-wrapper">
                    <table className="cbom-component-table">
                      <thead>
                        <tr>
                          <th>ALGORITHM</th>
                          <th>CATEGORY</th>
                          <th>FILE</th>
                          <th>LINE</th>
                          <th>RISK</th>
                          <th>QUANTUM</th>
                        </tr>
                      </thead>
                      <tbody>
                        {!filteredCbomComponents.length ? (
                          <tr>
                            <td colSpan="6" className="empty-table">
                              No matching CBOM components.
                            </td>
                          </tr>
                        ) : (
                          filteredCbomComponents.map((component, index) => {
                            const risk = getCbomComponentValue(component, "risk", "UNKNOWN");
                            const quantumStatus = getCbomComponentValue(component, "quantum_status", "UNKNOWN");

                            return (
                              <tr key={`${component["bom-ref"] || component.name || "component"}-${index}`}>
                                <td><strong>{component.name || "Unknown"}</strong></td>
                                <td>{getCbomComponentValue(component, "category")}</td>
                                <td>{getCbomComponentValue(component, "file")}</td>
                                <td>{getCbomComponentValue(component, "line")}</td>
                                <td><span className={getRiskClass(risk)}>{risk}</span></td>
                                <td><span className={getQuantumClass(quantumStatus)}>{getQuantumLabel(quantumStatus)}</span></td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                )}

              </div>


              <div className="cbom-json-column">

                <div className="cbom-json-header">
                  <div>
                    <span className="section-kicker">CBOM JSON</span>
                    <strong>Generated CBOM preview</strong>
                  </div>

                  <div className="cbom-json-actions">
                    <button
                      type="button"
                      className="dashboard-secondary-button"
                      onClick={copyCBOM}
                      disabled={!artifacts.length}
                    >
                      {cbomCopied ? "Copied" : "Copy JSON"}
                    </button>
                    <button
                      type="button"
                      className="dashboard-primary-button"
                      onClick={exportCBOM}
                      disabled={!artifacts.length}
                    >
                      <Download size={14} />
                      Extract CBOM
                    </button>
                  </div>
                </div>

                <pre className="cbom-json-preview">{cbomJson}</pre>

              </div>

            </div>

          </section>


          {/* ==================================================
              ALGORITHM FOOTPRINT
          ================================================== */}

          <section
            className="dashboard-card algorithm-footprint-card"
            id="risk-analysis"
          >

            <div className="dashboard-card-header">

              <div>

                <span className="section-kicker">
                  CRYPTOGRAPHIC ANALYSIS
                </span>

                <h2>
                  Cryptographic Algorithm Footprint
                </h2>

                <p className="algorithm-footprint-description">
                  Frequency of detected algorithms across
                  the scanned codebase and discovered artifacts.
                </p>

              </div>

              <div className="algorithm-chart-badge">
                <BarChart3 size={19} />
                <span>
                  {algorithms.length} algorithms
                </span>
              </div>

            </div>


            <div className="analysis-view-tabs" role="tablist" aria-label="Cryptographic analysis views">
              <button
                type="button"
                className={analysisView === "footprint" ? "active" : ""}
                onClick={() => setAnalysisView("footprint")}
                role="tab"
                aria-selected={analysisView === "footprint"}
              >
                Algorithm Footprint
              </button>
              <button
                type="button"
                className={analysisView === "graph" ? "active" : ""}
                onClick={() => setAnalysisView("graph")}
                role="tab"
                aria-selected={analysisView === "graph"}
              >
                Dependency Graph
              </button>
              <button
                type="button"
                className={analysisView === "tree" ? "active" : ""}
                onClick={() => setAnalysisView("tree")}
                role="tab"
                aria-selected={analysisView === "tree"}
              >
                Dependency Tree
              </button>
            </div>


            {analysisView === "footprint" ? (
              <>

            <div className="algorithm-footprint-chart">

              <div className="chart-axis">

                <span>0</span>
                <span>
                  {
                    Math.max(
                      ...(algorithms
                        .slice(0, 8)
                        .map(
                          ([, count]) =>
                            Number(count) || 0
                        )),
                      1
                    )
                  }
                </span>

              </div>


              {algorithms.length ? (
                algorithms
                  .slice(0, 8)
                  .map(
                    (
                      [name, count],
                      index
                    ) => {

                      const numericCount =
                        Number(count) || 0;

                      const maxCount =
                        Math.max(
                          ...algorithms
                            .slice(0, 8)
                            .map(
                              ([, itemCount]) =>
                                Number(itemCount) || 0
                            ),
                          1
                        );

                      const width =
                        Math.max(
                          (numericCount /
                            maxCount) *
                            100,
                          numericCount > 0
                            ? 3
                            : 0
                        );

                      return (
                        <div
                          className="algorithm-footprint-row"
                          key={name}
                        >

                          <div className="algorithm-footprint-label">
                            <span
                              className={`algorithm-dot dot-${index}`}
                            />
                            <span>
                              {name}
                            </span>
                          </div>

                          <div className="algorithm-footprint-track">

                            <div
                              className={`algorithm-footprint-bar bar-${index}`}
                              style={{
                                width:
                                  `${width}%`,
                              }}
                            />

                          </div>

                          <strong>
                            {numericCount}
                          </strong>

                        </div>
                      );
                    }
                  )
              ) : (
                <div className="no-data-message">
                  No cryptographic algorithms were detected.
                </div>
              )}

            </div>


            <div className="algorithm-footprint-footer">

              <div>
                <span className="legend-dot critical"></span>
                <span>
                  Risk classification remains available
                  in the asset inventory.
                </span>
              </div>

              <div>
                <strong>
                  {summary.crypto_assets || 0}
                </strong>
                <span>
                  total crypto assets
                </span>
              </div>

              <div>
                <strong>
                  {quantumExposure}%
                </strong>
                <span>
                  quantum exposure
                </span>
              </div>

            </div>

              </>
            ) : (
              <DependencyExplorer
                dependencies={dependencies}
                artifacts={artifacts}
                files={files}
                view={analysisView}
              />
            )}

          </section>

          {/* ==================================================
              INVENTORY
          ================================================== */}

          <section
            className="dashboard-card inventory-card"
            id="inventory"
          >

            <div className="inventory-header">

              <div>

                <span className="section-kicker">
                  CRYPTOGRAPHIC RESULTS
                </span>

                <h2>
                  Detected cryptographic artifacts
                </h2>

              </div>


              <div className="inventory-toolbar">

                <div className="inventory-search">

                  <Search size={14} />

                  <input
                    value={searchTerm}
                    onChange={(event) => {
                      setSearchTerm(
                        event.target.value
                      );
                      setAssetPage(1);
                    }}
                    placeholder="Search assets"
                  />

                </div>


                <div className="inventory-filter">

                  <Filter size={13} />

                  <select
                    value={
                      riskFilter
                    }
                    onChange={(event) => {
                      setRiskFilter(
                        event.target.value
                      );
                      setAssetPage(1);
                    }}
                  >

                    <option value="ALL">
                      Risk: All
                    </option>

                    <option value="CRITICAL">
                      Critical
                    </option>

                    <option value="HIGH">
                      High
                    </option>

                    <option value="MEDIUM">
                      Medium
                    </option>

                    <option value="LOW">
                      Low
                    </option>

                  </select>

                  <ChevronDown
                    size={12}
                  />

                </div>


                <div className="inventory-filter">

                  <select
                    value={
                      typeFilter
                    }
                    onChange={(event) => {
                      setTypeFilter(
                        event.target.value
                      );
                      setAssetPage(1);
                    }}
                  >

                    <option value="ALL">
                      Type: All
                    </option>

                    {categories.map(
                      (
                        category
                      ) => (
                        <option
                          key={
                            category
                          }
                          value={
                            category
                          }
                        >
                          {
                            category
                          }
                        </option>
                      )
                    )}

                  </select>

                  <ChevronDown
                    size={12}
                  />

                </div>


                <div className="inventory-filter">

                  <select
                    value={
                      quantumFilter
                    }
                    onChange={(event) => {
                      setQuantumFilter(
                        event.target.value
                      );
                      setAssetPage(1);
                    }}
                  >

                    <option value="ALL">
                      Quantum: All
                    </option>

                    <option value="VULNERABLE">
                      Vulnerable
                    </option>

                    <option value="LEGACY_WEAK">
                      Legacy / Weak
                    </option>

                    <option value="REVIEW">
                      Review
                    </option>

                    <option value="NOT_CURRENTLY_QUANTUM_VULNERABLE">
                      Protected
                    </option>

                  </select>

                  <ChevronDown
                    size={12}
                  />

                </div>

              </div>

            </div>


            <div className="inventory-table-wrapper">

              <table className="inventory-table">

                <thead>

                  <tr>

                    <th>
                      ASSET
                    </th>

                    <th>
                      KEY / MODE
                    </th>

                    <th>
                      QUANTUM
                    </th>

                    <th>
                      RISK
                    </th>

                    <th>
                      BUSINESS
                    </th>

                    <th>
                      LOCATION
                    </th>

                    <th></th>

                  </tr>

                </thead>


                <tbody>

                  {!filteredArtifacts.length ? (

                    <tr>

                      <td
                        colSpan="7"
                        className="empty-table"
                      >
                        No matching
                        cryptographic
                        artifacts.
                      </td>

                    </tr>

                  ) : (

                    paginatedArtifacts.map(
                      (
                        artifact
                      ) => {

                        /*
                         * We need the original artifact
                         * position because /assets/:index
                         * uses the original scan result.
                         */

                        const originalIndex =
                          artifacts.indexOf(
                            artifact
                          );

                        return (
                          <Fragment
                            key={artifactEntityId(
                              artifact,
                              originalIndex
                            )}
                          >
                          <tr
                            className={`inventory-row ${
                              expandedArtifactIndex ===
                              originalIndex
                                ? "expanded"
                                : ""
                            } ${
                              selectedContext?.entityId ===
                              artifactEntityId(
                                artifact,
                                originalIndex
                              )
                                ? "context-selected"
                                : ""
                            }`}
                            key={artifactEntityId(
                              artifact,
                              originalIndex
                            )}
                            onClick={() =>
                              setExpandedArtifactIndex(
                                (
                                  current
                                ) =>
                                  current ===
                                  originalIndex
                                    ? null
                                    : originalIndex
                              )
                            }
                          >

                            <td>

                              <div className="asset-cell">

                                <div className="asset-icon">
                                  <LockKeyhole
                                    size={15}
                                  />
                                </div>


                                <div>

                                  <strong>
                                    {
                                      artifact.algorithm ||
                                      "Unknown"
                                    }
                                  </strong>

                                  <span>
                                    {
                                      artifact.category ||
                                      "Cryptographic artifact"
                                    }
                                  </span>

                                </div>

                              </div>

                            </td>


                            <td>

                              <div className="key-mode-cell">

                                <span>
                                  {
                                    artifact.key_size ||
                                    "—"
                                  }
                                </span>

                                <small>
                                  {
                                    artifact.mode ||
                                    "N/A"
                                  }
                                </small>

                              </div>

                            </td>


                            <td>

                              <span
                                className={getQuantumClass(
                                  artifact.quantum_status
                                )}
                              >
                                {
                                  getQuantumLabel(
                                    artifact.quantum_status
                                  )
                                }
                              </span>

                            </td>


                            <td>

                              <span
                                className={getRiskClass(
                                  artifact.risk
                                )}
                              >
                                {
                                  artifact.risk ||
                                  "UNKNOWN"
                                }
                              </span>

                            </td>


                            <td>

                              <span
                                className={`business-badge ${String(
                                  artifact.business_criticality ||
                                    "MEDIUM"
                                ).toLowerCase()}`}
                              >
                                {
                                  artifact.business_criticality ||
                                  "MEDIUM"
                                }
                              </span>

                            </td>


                            <td>

                              <div className="location-cell">

                                <span>
                                  {
                                    artifact.file ||
                                    "Unknown file"
                                  }
                                </span>

                                <small>
                                  Line{" "}
                                  {
                                    artifact.line ??
                                    "n/a"
                                  }
                                </small>

                              </div>

                            </td>


                            <td>

                              <ChevronDown
                                size={15}
                                className={`row-arrow ${
                                  expandedArtifactIndex ===
                                  originalIndex
                                    ? "expanded-arrow"
                                    : ""
                                }`}
                              />

                            </td>

                          </tr>


                          {expandedArtifactIndex ===
                            originalIndex && (
                            <tr className="inventory-expanded-row">
                              <td
                                colSpan="7"
                                className="inventory-expanded-cell"
                              >

                                <div className="asset-dropdown">

                                  <div className="asset-dropdown-header">

                                    <div>

                                      <span className="section-kicker">
                                        INLINE ASSET INSPECTION
                                      </span>

                                      <h3>
                                        {
                                          artifact.algorithm ||
                                          "Cryptographic Asset"
                                        }
                                      </h3>

                                      <p>
                                        {
                                          artifact.file ||
                                          "Unknown file"
                                        }
                                        {" · "}
                                        Line{" "}
                                        {
                                          artifact.line ??
                                          "n/a"
                                        }
                                      </p>

                                    </div>


                                    <div className="asset-dropdown-status">

                                      <span
                                        className={getRiskClass(
                                          artifact.risk
                                        )}
                                      >
                                        {
                                          artifact.risk ||
                                          "UNKNOWN"
                                        }
                                      </span>

                                      <span
                                        className={getQuantumClass(
                                          artifact.quantum_status
                                        )}
                                      >
                                        {
                                          getQuantumLabel(
                                            artifact.quantum_status
                                          )
                                        }
                                      </span>

                                      <span
                                        className={`business-badge ${String(
                                          artifact.business_criticality ||
                                          "MEDIUM"
                                        ).toLowerCase()}`}
                                      >
                                        {
                                          artifact.business_criticality ||
                                          "MEDIUM"
                                        }
                                      </span>

                                    </div>

                                  </div>


                                  <div className="asset-dropdown-info-grid">

                                    <div className="asset-dropdown-info">
                                      <span>ALGORITHM</span>
                                      <strong>
                                        {
                                          artifact.algorithm ||
                                          "Unknown"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-info">
                                      <span>KEY SIZE</span>
                                      <strong>
                                        {
                                          artifact.key_size ||
                                          "—"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-info">
                                      <span>MODE</span>
                                      <strong>
                                        {
                                          artifact.mode ||
                                          "N/A"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-info">
                                      <span>FILE TYPE</span>
                                      <strong>
                                        {
                                          artifact.category ||
                                          "Cryptographic artifact"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-info">
                                      <span>LINE</span>
                                      <strong>
                                        {
                                          artifact.line ??
                                          "n/a"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-info">
                                      <span>QUANTUM STATUS</span>
                                      <strong>
                                        {
                                          getQuantumLabel(
                                            artifact.quantum_status
                                          )
                                        }
                                      </strong>
                                    </div>

                                  </div>


                                  <div className="asset-dropdown-columns">

                                    <div className="asset-dropdown-panel">

                                      <div className="asset-dropdown-panel-heading">

                                        <div>
                                          <span className="section-kicker">
                                            SOURCE EVIDENCE
                                          </span>

                                          <h4>
                                            Exact detection location
                                          </h4>
                                        </div>

                                        <Code2 size={16} />

                                      </div>


                                      <div className="asset-source-mini">

                                        <div className="asset-source-mini-header">

                                          <span>
                                            {
                                              artifact.file ||
                                              "Unknown file"
                                            }
                                          </span>

                                          <span>
                                            Line{" "}
                                            {
                                              artifact.line ??
                                              "n/a"
                                            }
                                          </span>

                                        </div>


                                        <div className="asset-source-mini-body">

                                          <div className="asset-source-mini-line-number">
                                            {
                                              artifact.line ??
                                              "—"
                                            }
                                          </div>

                                          <pre>
                                            {
                                              artifact.evidence ||
                                              artifact.source_excerpt ||
                                              artifact.match ||
                                              artifact.recommendation ||
                                              "Detected cryptographic usage. Source evidence was not returned by the current scanner response."
                                            }
                                          </pre>

                                        </div>

                                      </div>


                                      <div className="asset-evidence-type">

                                        AST / pattern match:
                                        {" "}
                                        <strong>
                                          {
                                            artifact.confidence ??
                                            artifact.match_confidence ??
                                            "Available"
                                          }
                                        </strong>

                                      </div>

                                    </div>


                                    <div className="asset-dropdown-panel">

                                      <div className="asset-dropdown-panel-heading">

                                        <div>
                                          <span className="section-kicker">
                                            RECOMMENDATION
                                          </span>

                                          <h4>
                                            Recommended migration action
                                          </h4>
                                        </div>

                                        <Lightbulb size={16} />

                                      </div>


                                      <div className="asset-recommendation-box">

                                        <strong>
                                          {
                                            artifact.recommendation ||
                                            "Review this cryptographic finding and select a supported migration target based on application requirements."
                                          }
                                        </strong>


                                        <div className="asset-recommendation-grid">

                                          <div>
                                            <span>RISK</span>
                                            <strong>
                                              {
                                                artifact.risk ||
                                                "UNKNOWN"
                                              }
                                            </strong>
                                          </div>

                                          <div>
                                            <span>BUSINESS</span>
                                            <strong>
                                              {
                                                artifact.business_criticality ||
                                                "MEDIUM"
                                              }
                                            </strong>
                                          </div>

                                          <div>
                                            <span>QUANTUM</span>
                                            <strong>
                                              {
                                                getQuantumLabel(
                                                  artifact.quantum_status
                                                )
                                              }
                                            </strong>
                                          </div>

                                        </div>


                                        {(
                                          artifact.migration_targets ||
                                          artifact
                                            .recommendation_detail
                                            ?.migration_targets ||
                                          []
                                        ).length > 0 && (

                                          <div className="asset-targets">

                                            <span className="asset-target-label">
                                              MIGRATION TARGETS
                                            </span>

                                            <div className="asset-target-list">

                                              {(
                                                artifact.migration_targets ||
                                                artifact
                                                  .recommendation_detail
                                                  ?.migration_targets ||
                                                []
                                              ).map(
                                                (
                                                  target
                                                ) => (
                                                  <span
                                                    key={
                                                      target
                                                    }
                                                  >
                                                    {target}
                                                  </span>
                                                )
                                              )}

                                            </div>

                                          </div>

                                        )}

                                      </div>

                                    </div>

                                  </div>


                                  <div className="asset-dropdown-context">

                                    <div className="asset-dropdown-context-item">
                                      <span>FILE</span>
                                      <strong>
                                        {
                                          artifact.file ||
                                          "Unknown"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-context-item">
                                      <span>CATEGORY</span>
                                      <strong>
                                        {
                                          artifact.category ||
                                          "Unknown"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-context-item">
                                      <span>DATA SENSITIVITY</span>
                                      <strong>
                                        {
                                          artifact.data_sensitivity ||
                                          "Not specified"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-context-item">
                                      <span>LIBRARY</span>
                                      <strong>
                                        {
                                          artifact.library ||
                                          "Not specified"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-context-item">
                                      <span>LIBRARY VERSION</span>
                                      <strong>
                                        {
                                          artifact.library_version ||
                                          "Not specified"
                                        }
                                      </strong>
                                    </div>

                                    <div className="asset-dropdown-context-item">
                                      <span>CONFIDENCE</span>
                                      <strong>
                                        {
                                          artifact.confidence ||
                                          artifact.match_confidence ||
                                          "Not specified"
                                        }
                                      </strong>
                                    </div>

                                  </div>


                                  <div className="asset-dropdown-footer">

                                    <span>
                                      Inline inspection preserves
                                      the current scan result and
                                      does not navigate away from
                                      the dashboard.
                                    </span>

                                    <button
                                      type="button"
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        setExpandedArtifactIndex(
                                          null
                                        );
                                      }}
                                    >
                                      <ChevronDown size={13} />
                                      Collapse
                                    </button>

                                  </div>

                                </div>

                              </td>
                            </tr>
                          )}

                          </Fragment>
                        );
                      }
                    )

                  )}

                </tbody>

              </table>

            </div>


            <div className="inventory-footer">

              Showing{" "}

              <strong>
                {filteredArtifacts.length
                  ? (effectiveAssetPage - 1) * PAGE_SIZE + 1
                  : 0}
                –
                {Math.min(
                  effectiveAssetPage * PAGE_SIZE,
                  filteredArtifacts.length
                )}
              </strong>

              {" "}of{" "}

              <strong>
                {filteredArtifacts.length}
              </strong>

              {" "}assets

              <PaginationControls
                currentPage={effectiveAssetPage}
                totalPages={assetTotalPages}
                onPageChange={setAssetPage}
              />

            </div>

          </section>


          {/* ==================================================
              RECOMMENDATIONS
          ================================================== */}

          <section
            className="dashboard-card recommendation-dashboard-card"
            id="recommendations"
          >

            <div className="dashboard-card-header">

              <div>

                <span className="section-kicker">
                  RECOMMENDATIONS
                </span>

                <h2>
                  {recommendationCount}{" "}
                  {recommendationCount === 1
                    ? "file requires"
                    : "files require"}{" "}
                  attention
                </h2>

              </div>

              <div className="recommendation-mark">
                <Lightbulb size={17} />
              </div>

            </div>

            {!recommendations.length ? (
              <div className="recommendation-empty">
                No actionable cryptographic recommendations were returned for this scan.
              </div>
            ) : (
              <div className="recommendation-list">
                {paginatedRecommendations.map(
                  ({
                    artifact,
                    index,
                    targets,
                    recommendation,
                  }) => {
                    const reason =
                      artifact.quantum_status === "VULNERABLE"
                        ? "Quantum vulnerable"
                        : artifact.quantum_status === "LEGACY_WEAK"
                          ? "Legacy / weak cryptography"
                          : `${artifact.risk || "Risk"} cryptographic finding`;
                    const location =
                      artifact.line !== undefined &&
                      artifact.line !== null &&
                      artifact.line !== ""
                        ? `${artifact.file || "Unknown file"}:${artifact.line}`
                        : `${artifact.file || "Unknown file"} · Line unavailable`;
                    const recommendedChange =
                      extractRecommendationTargets(
                        recommendation,
                        targets
                      );

                    return (
                      <article
                        className="recommendation-row"
                        key={artifactEntityId(artifact, index)}
                      >
                        <div className="recommendation-row-heading">
                          <div>
                            <strong className="recommendation-primary-name">
                              {artifact.algorithm || artifact.category || "Cryptographic artifact"}
                            </strong>
                            <span>{location}</span>
                          </div>

                          <span className={getRiskClass(artifact.risk)}>
                            {artifact.risk || "UNKNOWN"}
                          </span>
                        </div>

                        <div className="recommendation-row-details">
                          <div>
                            <span>CURRENT</span>
                            <strong className="recommendation-primary-name">
                              {artifact.algorithm || "Unknown algorithm"}
                            </strong>
                          </div>
                          <div>
                            <span>ISSUE</span>
                            <strong>{reason}</strong>
                          </div>
                          <div>
                            <span>RECOMMENDED</span>
                            <strong className="recommendation-primary-name">
                              {recommendedChange.length
                                ? recommendedChange.join(" · ")
                                : "Modern approved symmetric replacement"}
                            </strong>
                          </div>
                        </div>

                        <button
                          type="button"
                          className="recommendation-view-button"
                          onClick={() => {
                            selectContext({
                              entityType: "artifact",
                              entityId: artifactEntityId(artifact, index),
                              name: artifact.algorithm || artifact.category || "Cryptographic artifact",
                              file: artifact.file,
                              line: artifact.line,
                              algorithm: artifact.algorithm,
                              risk: artifact.risk,
                              quantumStatus: artifact.quantum_status,
                              category: artifact.category,
                              artifact,
                            });
                            setExpandedArtifactIndex(index);
                            scrollTo("inventory");
                          }}
                        >
                          <Code2 size={13} />
                          View File
                        </button>
                      </article>
                    );
                  }
                )}
              </div>
            )}

            <PaginationControls
              currentPage={effectiveRecommendationPage}
              totalPages={recommendationTotalPages}
              onPageChange={setRecommendationPage}
            />

          </section>


          {/* ==================================================
              HISTORY
          ================================================== */}

          <section
            className="dashboard-card history-card"
            id="history"
          >

            <div className="dashboard-card-header">

              <div>

                <span className="section-kicker">
                  SCAN HISTORY
                </span>

                <h2>
                  Previous complete reports
                </h2>

              </div>


              {history.length >
                0 && (

                <button
                  className="clear-history-button"
                  onClick={
                    clearHistory
                  }
                >
                  Clear history
                </button>

              )}

            </div>


            {!history.length ? (

              <div className="history-empty">

                <History size={20} />

                <div>

                  <strong>
                    No previous scans
                  </strong>

                  <span>
                    Complete scan results
                    will appear here.
                  </span>

                </div>

              </div>

            ) : (

              <div className="history-grid">

                {history
                  .slice(0, 10)
                  .map(
                    (entry) => {

                      const result =
                        entry.result ||
                        {};

                      const entrySummary =
                        result.summary ||
                        {};

                      const isCurrent =
                        result.input
                          ?.name ===
                        scanResult.input
                          ?.name;

                      return (
                        <button
                          className={`history-card ${
                            isCurrent
                              ? "current"
                              : ""
                          }`}
                          key={
                            entry.id ||
                            `${entry.name || "scan"}-${entry.timestamp || "unknown"}`
                          }
                          onClick={() =>
                            loadHistoryEntry(
                              entry
                            )
                          }
                        >

                          <div className="history-card-top">

                            <div className="history-card-icon">
                              <Archive size={16} />
                            </div>

                            <ArrowUpRight
                              size={14}
                            />

                          </div>


                          <strong>
                            {
                              entry.name
                            }
                          </strong>

                          <small className="history-source-type">
                            {{
                              folder: "Project",
                              files: "Files",
                              archive: "Archive",
                              file: "File",
                            }[result.input?.source_type] || "Scan"}
                          </small>

                          <span>
                            {
                              formatDate(
                                entry.timestamp
                              )
                            }
                          </span>


                          <div className="history-metrics">

                            <small>
                              {
                                entrySummary.files_scanned
                              }{" "}
                              files
                            </small>

                            <small>
                              {
                                entrySummary.crypto_assets
                              }{" "}
                              assets
                            </small>

                            <small className="history-critical">
                              {
                                entrySummary.critical
                              }{" "}
                              critical
                            </small>

                          </div>


                          {isCurrent && (

                            <div className="current-history-label">
                              Current
                            </div>

                          )}

                        </button>
                      );
                    }
                  )}

              </div>

            )}

          </section>


          {/* ==================================================
              FOOTER
          ================================================== */}

          <footer className="dashboard-status-footer">

            <div>

              <CheckCircle2 size={15} />

              <strong>
                Scan completed
              </strong>

              <span>
                {
                  scanResult.input?.name
                }
              </span>

            </div>


            <div>

              <span>
                {
                  summary.files_scanned
                }{" "}
                files
              </span>

              <span>
                {
                  summary.crypto_assets
                }{" "}
                assets
              </span>

              <span className="status-high">
                {
                  (summary.critical || 0) +
                  (summary.high || 0)
                }{" "}
                priority findings
              </span>

            </div>

          </footer>

        </div>

      </main>

    </div>
  );
}


/* ============================================================
   FLOW STEP
   ============================================================ */

function FlowStep({
  number,
  title,
  description,
  icon,
}) {
  return (
    <div className="analysis-flow-step active">

      <div className="analysis-flow-icon">
        {icon}
      </div>

      <div>

        <span>
          {number}
        </span>

        <strong>
          {title}
        </strong>

        <small>
          {description}
        </small>

      </div>

    </div>
  );
}


export default Dashboard;
