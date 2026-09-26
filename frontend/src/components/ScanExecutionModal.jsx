import { useMemo } from "react";
import {
  Check,
  CheckCircle2,
  Clock,
  Cpu,
  FileCode2,
  Layers,
  Loader2,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

export const SCAN_PIPELINE_STAGES = [
  {
    id: "scanning",
    label: "Scanning",
    title: "Scanning file architecture & source tree...",
    description: "Parsing project tree, cataloging source files, and extracting AST symbols",
    tag: "Source Tree",
    icon: FileCode2,
  },
  {
    id: "searching",
    label: "Searching",
    title: "Searching for cryptographic artifacts & keys...",
    description: "Locating cipher suites, private keys, certificates, keystores, and hashes",
    tag: "Artifact Discovery",
    icon: Search,
  },
  {
    id: "thinking",
    label: "Thinking",
    title: "Thinking & analyzing algorithm posture...",
    description: "Cross-referencing NIST PQC, FIPS 140-3 & CNSA 2.0 cryptographic standards",
    tag: "Posture Analysis",
    icon: Cpu,
  },
  {
    id: "vulnerabilities",
    label: "Searching for Vulnerabilities",
    title: "Searching for vulnerabilities & quantum exposure...",
    description: "Evaluating Shor's & Grover's algorithm exposure and deprecated cipher modes",
    tag: "Threat Model",
    icon: ShieldAlert,
  },
  {
    id: "cbom",
    label: "Synthesizing CBOM",
    title: "Finalizing CBOM & security intelligence...",
    description: "Compiling CycloneDX Cryptographic Bill of Materials and migration roadmap",
    tag: "Inventory Ready",
    icon: Layers,
  },
];

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  const kb = value / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

export default function ScanExecutionModal({
  isOpen,
  displayName = "Target",
  totalBytes = 0,
  elapsedSeconds = 0,
  approxEstimate = { text: "~7–9s", targetSec: 8.5, isLarge: false },
}) {
  if (!isOpen) return null;

  const targetSec = Math.max(7.0, approxEstimate?.targetSec || 8.5);

  const currentStepIndex = useMemo(() => {
    const ratio = Math.min(1, elapsedSeconds / targetSec);
    if (ratio < 0.22) return 0;
    if (ratio < 0.44) return 1;
    if (ratio < 0.68) return 2;
    if (ratio < 0.88) return 3;
    return 4;
  }, [targetSec, elapsedSeconds]);

  const scanPercent = useMemo(() => {
    const ratio = Math.min(0.98, (elapsedSeconds / targetSec) * 0.96);
    return Math.max(8, Math.round(ratio * 100));
  }, [targetSec, elapsedSeconds]);

  const activeStage = SCAN_PIPELINE_STAGES[currentStepIndex] || SCAN_PIPELINE_STAGES[0];
  const ActiveIcon = activeStage.icon;

  return (
    <div className="compact-scan-modal-backdrop" role="dialog" aria-modal="true">
      <div className="compact-scan-window executive-scan-window">
        {/* Topbar: Target Identity & Security Badge */}
        <div className="compact-scan-topbar">
          <div className="compact-scan-target-pill">
            <span className="compact-pulse-dot" />
            <span className="compact-target-name">{displayName || "Active Project"}</span>
          </div>

          <div className="compact-scan-topbar-meta">
            <span className="compact-file-size">
              {formatBytes(totalBytes)}
            </span>
            <span className="compact-audit-badge">
              DEEP AUDIT
            </span>
          </div>
        </div>

        {/* Hero Section: Dynamic Refined Loader & Active Step Title */}
        <div className="compact-scan-body">
          <div className="compact-scan-spinner-wrap">
            <div className="compact-spinner-ring outer" />
            <div className="compact-spinner-ring inner" />
            <div className="compact-spinner-core">
              <ActiveIcon size={20} className="compact-core-icon" />
            </div>
          </div>

          <div className="compact-scan-info">
            <div className="compact-phase-counter">
              STAGE {currentStepIndex + 1} OF {SCAN_PIPELINE_STAGES.length}
            </div>
            <div className="compact-scan-step-title animate-step" key={activeStage.title}>
              {activeStage.title}
            </div>
            <div className="compact-scan-sub">
              {activeStage.description}
            </div>
          </div>
        </div>

        {/* Multi-Stage Elements Checklist (Scanning, Searching, Thinking, Vulnerabilities, CBOM) */}
        <div className="scan-pipeline-card">
          <div className="scan-pipeline-header">
            <span>EXECUTION PIPELINE</span>
            <span className="scan-pipeline-active-badge">
              Active: {activeStage.label}
            </span>
          </div>

          <div className="scan-pipeline-list">
            {SCAN_PIPELINE_STAGES.map((stage, idx) => {
              const isCompleted = idx < currentStepIndex;
              const isCurrent = idx === currentStepIndex;
              const isPending = idx > currentStepIndex;
              const StageIcon = stage.icon;

              return (
                <div
                  key={stage.id}
                  className={`scan-pipeline-item ${
                    isCompleted ? "completed" : isCurrent ? "current" : "pending"
                  }`}
                >
                  <div className="pipeline-item-status">
                    {isCompleted ? (
                      <div className="pipeline-status-icon completed">
                        <Check size={12} strokeWidth={3} />
                      </div>
                    ) : isCurrent ? (
                      <div className="pipeline-status-icon current">
                        <Loader2 size={13} className="spin-loader" />
                      </div>
                    ) : (
                      <div className="pipeline-status-icon pending">
                        <span className="pending-dot" />
                      </div>
                    )}
                  </div>

                  <div className="pipeline-item-content">
                    <div className="pipeline-item-label-row">
                      <span className="pipeline-item-label">{stage.label}</span>
                      <span className="pipeline-item-tag">{stage.tag}</span>
                    </div>
                  </div>

                  <div className="pipeline-item-badge">
                    {isCompleted ? (
                      <span className="pipeline-state-badge done">DONE</span>
                    ) : isCurrent ? (
                      <span className="pipeline-state-badge active">IN PROGRESS</span>
                    ) : (
                      <span className="pipeline-state-badge queued">QUEUED</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Telemetry Row: Timing & Completion */}
        <div className="compact-scan-timing-section">
          <div className="compact-timing-pill approx">
            <Clock size={13} className="timer-spin" />
            <span className="timing-label">Estimated:</span>
            <span className="timing-value">{approxEstimate?.text || "~7–9s"}</span>
          </div>

          <div className="compact-timing-pill elapsed">
            <span className="timing-label">Elapsed:</span>
            <span className="timing-value">{elapsedSeconds.toFixed(1)}s</span>
          </div>

          <div className="compact-timing-pill percent">
            <span className="timing-label">Progress:</span>
            <span className="timing-value">{scanPercent}%</span>
          </div>
        </div>

        {/* Sleek Progress Bar with Non-Sci-Fi Slate/Silver Finish */}
        <div className="compact-progress-bar-wrap">
          <div
            className="compact-progress-bar-fill animated-shimmer"
            style={{ width: `${scanPercent}%` }}
          />
        </div>

        {/* Large File Advisory */}
        {(approxEstimate?.isLarge || elapsedSeconds > 12) && (
          <div className="compact-scan-advisory">
            <ShieldAlert size={15} className="advisory-icon" />
            <span>
              Large file/repository detected. Deep cryptographic analysis in progress (up to 2 mins max safety cutoff).
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
