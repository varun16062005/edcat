import { useMemo, useState, useRef, useEffect } from "react";
import {
  ArrowRight,
  Bot,
  Check,
  Copy,
  CornerDownLeft,
  Cpu,
  FileText,
  Layers,
  MessageCircle,
  Send,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  User,
  X,
} from "lucide-react";

import { queryAdvisor } from "../services/api";
import { useEcdatContext } from "../context/useEcdatContext";
import { classifyRecords, readPreviousSnapshot } from "../lib/artifactIntegrity";
import { calculateProjectScenarioRisk } from "../utils/moscaScenario";
import { AnalysisHeader, EmptyAnalysisState } from "./analysisPageUtils";
import { useCurrentScan } from "./analysisData";

const STARTER_PROMPTS = [
  {
    category: "Quantum Exposure",
    title: "Which algorithms are quantum vulnerable?",
    description: "Identify Shor's algorithm vulnerabilities and deprecated keys.",
    icon: ShieldAlert,
    accent: "#f43f5e",
  },
  {
    category: "CBOM Inventory",
    title: "Summarize the CBOM.",
    description: "Review CycloneDX v1.6 cryptographic bills of material.",
    icon: Layers,
    accent: "#38bdf8",
  },
  {
    category: "Migration Strategy",
    title: "What PQC alternatives are recommended?",
    description: "NIST FIPS 203/204/205 quantum-safe target mappings.",
    icon: Cpu,
    accent: "#10b981",
  },
  {
    category: "Dependency Reach",
    title: "Which artifact has the largest dependency reach?",
    description: "Inspect blast radius impact and downstream consumers.",
    icon: CornerDownLeft,
    accent: "#818cf8",
  },
];

const QUICK_FOLLOWUPS = [
  "How many cryptographic assets were discovered?",
  "Which files contain RSA?",
  "What are the highest-priority findings?",
  "Which artifacts should migrate first?",
  "What changed since the previous scan?",
  "Show the dependencies of the most critical artifact.",
];

function buildContext(result, selectedContext) {
  const scenario = calculateProjectScenarioRisk(result.artifacts || [], 2040);
  const changes = classifyRecords(result.artifacts || [], readPreviousSnapshot());
  const artifacts = (result.artifacts || []).slice(0, 80).map((artifact) => ({
    file: artifact.file,
    line: artifact.line,
    algorithm: artifact.algorithm,
    category: artifact.category,
    risk: artifact.risk,
    quantum_status: artifact.quantum_status,
    recommendation: artifact.recommendation,
    content_hash: artifact.content_hash,
  }));
  return {
    project: { name: result.input?.name, type: result.input?.source_type },
    summary: result.summary || {},
    files: (result.files || []).slice(0, 80).map((file) => ({
      path: file.path || file.name,
      type: file.type,
    })),
    artifacts,
    cbom: {
      spec: result.cbom?.spec || result.cbom?.metadata?.spec,
      components: result.cbom?.components?.length || 0,
    },
    dependencies: {
      nodes: result.dependencies?.nodes?.length || 0,
      edges: result.dependencies?.edges?.length || 0,
    },
    scenarioRisk: {
      overall: scenario.overallRisk,
      quantumExposure: scenario.quantumExposure,
      riskPercentage: scenario.riskPercentage,
    },
    migration: scenario.evaluations.slice(0, 40).map((item) => ({
      file: item.artifact.file,
      algorithm: item.artifact.algorithm,
      alternative: item.pqcTarget,
      priority: item.scenarioRisk,
    })),
    changes: changes.summary,
    focus: selectedContext?.name || null,
  };
}

export default function AdvisorPage() {
  const { selectedContext } = useEcdatContext();
  const result = useCurrentScan();
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState([]);
  const [pending, setPending] = useState(false);
  const [copiedId, setCopiedId] = useState(null);
  const [activeMobileTab, setActiveMobileTab] = useState("chat");
  const messagesEndRef = useRef(null);

  const context = useMemo(
    () => (result ? buildContext(result, selectedContext) : null),
    [result, selectedContext]
  );

  useEffect(() => {
    if (messages.length > 0 || pending) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, pending]);

  const ask = async (value) => {
    const trimmed = (value || "").trim();
    if (!trimmed || !context || pending) return;
    setPending(true);
    setQuestion("");
    const messageId = `${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
    const timeStr = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

    try {
      const response = await queryAdvisor(trimmed, context);
      setMessages((current) => [
        ...current,
        {
          id: messageId,
          question: trimmed,
          answer: response.answer,
          sources: response.sources || [],
          timestamp: timeStr,
        },
      ]);
    } catch (error) {
      setMessages((current) => [
        ...current,
        {
          id: messageId,
          question: trimmed,
          answer: error.message || "Failed to retrieve advisor response from local endpoint.",
          sources: [],
          isError: true,
          timestamp: timeStr,
        },
      ]);
    } finally {
      setPending(false);
    }
  };

  const handleCopy = (id, text) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    }
  };

  const handleClearHistory = () => {
    setMessages([]);
  };

  const handleEvidenceClick = (artifact) => {
    setActiveMobileTab("chat");
    const query = `Tell me about the ${artifact.algorithm || "cryptographic"} finding in ${artifact.file || "this file"}`;
    ask(query);
  };

  if (!result) {
    return (
      <main className="analysis-page advisor-page">
        <AnalysisHeader
          label="ECDAT ADVISOR"
          title="ECDAT Advisor"
          description="Ask questions about the current cryptographic scan."
        />
        <EmptyAnalysisState />
      </main>
    );
  }

  const artifacts = result.artifacts || [];
  const summary = result.summary || {};
  const projectName = selectedContext?.name || result.input?.name || "Current Scan";

  return (
    <main className="analysis-page advisor-page">
      <AnalysisHeader
        label="ECDAT ADVISOR"
        title="ECDAT Advisor"
        description="Grounded AI assistant for cryptographic risk, CBOM intelligence, and post-quantum migration."
      />

      {/* Responsive Mobile / Tablet Tab Navigation */}
      <div className="advisor-mobile-tabs" role="tablist" aria-label="Advisor View Switcher">
        <button
          type="button"
          role="tab"
          aria-selected={activeMobileTab === "chat"}
          className={`advisor-mobile-tab-btn ${activeMobileTab === "chat" ? "is-active" : ""}`}
          onClick={() => setActiveMobileTab("chat")}
        >
          <Sparkles size={14} />
          <span>Advisor Chat</span>
          {messages.length > 0 && (
            <span className="advisor-mobile-tab-badge">{messages.length}</span>
          )}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeMobileTab === "evidence"}
          className={`advisor-mobile-tab-btn ${activeMobileTab === "evidence" ? "is-active" : ""}`}
          onClick={() => setActiveMobileTab("evidence")}
        >
          <FileText size={14} />
          <span>Scan Context</span>
          <span className="advisor-mobile-tab-badge">{artifacts.length}</span>
        </button>
      </div>

      <div className="advisor-layout" data-active-tab={activeMobileTab}>
        {/* Main Conversational Panel */}
        <section className="advisor-chat-panel">
          {/* Advisor Top Bar */}
          <div className="advisor-chat-header">
            <div className="advisor-header-identity">
              <div className="advisor-avatar-glow">
                <Sparkles size={20} />
              </div>
              <div className="advisor-header-titles">
                <h2>ECDAT Cryptographic Advisor</h2>
                <p>Deterministic retrieval over AST discoveries, CBOM v1.6, and PQC mappings.</p>
              </div>
            </div>
            <div className="advisor-header-actions">
              <div className="advisor-grounding-badge">
                <span className="advisor-live-dot" />
                <span className="advisor-badge-text">Grounded to Scan Graph</span>
              </div>
              {messages.length > 0 && (
                <button
                  type="button"
                  className="advisor-clear-btn"
                  onClick={handleClearHistory}
                  title="Clear chat history"
                  aria-label="Clear chat history"
                >
                  <Trash2 size={14} />
                  <span className="advisor-btn-text">Clear</span>
                </button>
              )}
            </div>
          </div>

          {/* Messages Feed or Empty Hero */}
          <div className="advisor-chat-feed">
            {messages.length === 0 ? (
              <div className="advisor-hero">
                <div className="advisor-hero-icon">
                  <Bot size={28} />
                </div>
                <h3>How can ECDAT Advisor assist your cryptographic migration?</h3>
                <p>
                  Explore cryptographic findings, quantum vulnerability exposure, dependency reach,
                  and recommended NIST PQC replacement algorithms.
                </p>
                <div className="advisor-prompt-grid">
                  {STARTER_PROMPTS.map((prompt) => {
                    const IconComponent = prompt.icon;
                    return (
                      <button
                        type="button"
                        key={prompt.title}
                        className="advisor-prompt-card"
                        onClick={() => ask(prompt.title)}
                        disabled={pending}
                      >
                        <div className="advisor-prompt-card-top">
                          <span
                            className="advisor-prompt-card-icon"
                            style={{ color: prompt.accent, background: `${prompt.accent}18` }}
                          >
                            <IconComponent size={15} />
                          </span>
                          <span className="advisor-prompt-card-category" style={{ color: prompt.accent }}>
                            {prompt.category}
                          </span>
                        </div>
                        <h4 className="advisor-prompt-card-title">{prompt.title}</h4>
                        <p className="advisor-prompt-card-desc">{prompt.description}</p>
                      </button>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div className="advisor-messages-list">
                {messages.map((message) => (
                  <div key={message.id} className="advisor-message-group">
                    {/* User Question */}
                    <div className="advisor-msg-user">
                      <div className="advisor-msg-meta">
                        <span className="advisor-user-pill">
                          <User size={12} />
                          <span>You</span>
                        </span>
                        <span className="advisor-msg-time">{message.timestamp}</span>
                      </div>
                      <div className="advisor-user-bubble">
                        <p>{message.question}</p>
                      </div>
                    </div>

                    {/* Advisor Response */}
                    <div className="advisor-msg-assistant">
                      <div className="advisor-assistant-avatar">
                        <Sparkles size={16} />
                      </div>
                      <div className="advisor-assistant-body">
                        <div className="advisor-msg-meta">
                          <div className="advisor-assistant-tags">
                            <span className="advisor-bot-name">ECDAT Advisor</span>
                            <span className="advisor-verified-tag">
                              <ShieldCheck size={11} /> Grounded
                            </span>
                          </div>
                          <span className="advisor-msg-time">{message.timestamp}</span>
                        </div>
                        <div className={`advisor-assistant-bubble ${message.isError ? "is-error" : ""}`}>
                          <p>{message.answer}</p>
                          {message.sources?.length > 0 && (
                            <div className="advisor-sources-wrap">
                              <span className="advisor-sources-label">Sources:</span>
                              <div className="advisor-sources-list">
                                {message.sources.map((src) => (
                                  <span key={src} className="advisor-source-tag">
                                    <FileText size={11} />
                                    {src}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                        <div className="advisor-bubble-actions">
                          <button
                            type="button"
                            className="advisor-copy-btn"
                            onClick={() => handleCopy(message.id, message.answer)}
                            title="Copy response to clipboard"
                          >
                            {copiedId === message.id ? (
                              <>
                                <Check size={12} className="text-emerald" />
                                <span>Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy size={12} />
                                <span>Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}

                {/* Thinking / Reasoning Indicator */}
                {pending && (
                  <div className="advisor-msg-assistant advisor-thinking">
                    <div className="advisor-assistant-avatar thinking-pulse">
                      <Sparkles size={16} />
                    </div>
                    <div className="advisor-assistant-body">
                      <div className="advisor-assistant-bubble thinking-bubble">
                        <div className="advisor-typing-indicator">
                          <span className="typing-dot" />
                          <span className="typing-dot" />
                          <span className="typing-dot" />
                        </div>
                        <span className="thinking-text">
                          ECDAT Advisor is reasoning over scan evidence &amp; CBOM graph...
                        </span>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>
            )}
          </div>

          {/* Quick Follow-up Chips */}
          <div className="advisor-quick-bar">
            <span className="advisor-quick-label">Suggestions:</span>
            <div className="advisor-quick-chips">
              {QUICK_FOLLOWUPS.map((item) => (
                <button
                  type="button"
                  key={item}
                  className="advisor-chip-btn"
                  onClick={() => ask(item)}
                  disabled={pending}
                >
                  <span>{item}</span>
                  <ArrowRight size={12} />
                </button>
              ))}
            </div>
          </div>

          {/* Input Dock */}
          <div className="advisor-input-dock">
            <form
              className="advisor-form-container"
              onSubmit={(event) => {
                event.preventDefault();
                ask(question);
              }}
            >
              <input
                type="text"
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                placeholder="Ask about quantum vulnerabilities, CBOM assets, RSA deprecation, or PQC migration..."
                aria-label="Ask the ECDAT advisor"
                disabled={pending}
                className="advisor-input-field"
              />
              {question.trim() && (
                <button
                  type="button"
                  className="advisor-input-clear"
                  onClick={() => setQuestion("")}
                  title="Clear input"
                  aria-label="Clear input text"
                >
                  <X size={14} />
                </button>
              )}
              <button
                type="submit"
                className="advisor-send-btn"
                aria-label="Ask question"
                disabled={pending || !question.trim()}
                title="Send query"
              >
                <Send size={15} />
              </button>
            </form>
            <div className="advisor-input-hint">
              <span>ECDAT queries local AST detections &amp; CBOM v1.6 evidence.</span>
              <span className="advisor-enter-hint">Press Enter ↵ to ask</span>
            </div>
          </div>
        </section>

        {/* Right Sidebar: Grounding Context & Evidence Findings */}
        <aside className="advisor-evidence-panel">
          <div className="advisor-sidebar-header">
            <span className="section-kicker">GROUNDING CONTEXT</span>
            <h3 className="advisor-sidebar-title">{projectName}</h3>
            <p className="advisor-sidebar-meta">
              Target repository indexed for deterministic knowledge retrieval.
            </p>
          </div>

          {/* Telemetry Matrix */}
          <div className="advisor-telemetry-grid">
            <div className="advisor-telemetry-card">
              <span className="advisor-telemetry-label">Crypto Assets</span>
              <strong className="advisor-telemetry-value">
                {summary.crypto_assets ?? artifacts.length ?? 0}
              </strong>
              <small>AST Detections</small>
            </div>
            <div className="advisor-telemetry-card">
              <span className="advisor-telemetry-label">Files Scanned</span>
              <strong className="advisor-telemetry-value">
                {summary.files_scanned ?? (result.files?.length || 0)}
              </strong>
              <small>Analyzed Source</small>
            </div>
            <div className="advisor-telemetry-card">
              <span className="advisor-telemetry-label">Critical Risks</span>
              <strong className="advisor-telemetry-value text-rose">
                {summary.critical ?? 0}
              </strong>
              <small>Action Required</small>
            </div>
            <div className="advisor-telemetry-card">
              <span className="advisor-telemetry-label">CBOM Standard</span>
              <strong className="advisor-telemetry-value text-cyan">
                {result.cbom?.spec || "CycloneDX"}
              </strong>
              <small>{result.cbom?.components?.length || 0} Components</small>
            </div>
          </div>

          {/* Grounded Evidence Findings */}
          <div className="advisor-evidence-section">
            <div className="advisor-evidence-header">
              <h4>DETECTED ASSETS (CLICK TO QUERY)</h4>
              <span className="advisor-evidence-count">
                {Math.min(artifacts.length, 12)} of {artifacts.length}
              </span>
            </div>

            <div className="advisor-evidence-list">
              {artifacts.slice(0, 12).map((artifact, index) => {
                const isCritical = artifact.risk === "CRITICAL";
                const isHigh = artifact.risk === "HIGH";
                const isVulnerable = String(artifact.quantum_status || "").toUpperCase() === "VULNERABLE";

                return (
                  <button
                    type="button"
                    key={`${artifact.file}-${artifact.line}-${index}`}
                    className="advisor-evidence-item"
                    onClick={() => handleEvidenceClick(artifact)}
                    title={`Ask advisor about ${artifact.algorithm || "artifact"}`}
                  >
                    <div className="advisor-evidence-info">
                      <div className="advisor-evidence-top">
                        <strong className="advisor-evidence-algo">
                          {artifact.algorithm || artifact.category || "Cryptographic Artifact"}
                        </strong>
                        <span
                          className={`advisor-risk-pill ${
                            isCritical
                              ? "pill-critical"
                              : isHigh
                              ? "pill-high"
                              : isVulnerable
                              ? "pill-vulnerable"
                              : "pill-standard"
                          }`}
                        >
                          {artifact.risk || (isVulnerable ? "VULNERABLE" : "SAFE")}
                        </span>
                      </div>
                      <small className="advisor-evidence-path">
                        {artifact.file || "Unknown file"}
                        {artifact.line ? `:${artifact.line}` : ""}
                      </small>
                    </div>
                    <div className="advisor-evidence-arrow">
                      <MessageCircle size={14} />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Deterministic Trust Guarantee */}
          <div className="advisor-trust-card">
            <ShieldCheck size={18} className="advisor-trust-icon" />
            <div>
              <strong>Zero-Hallucination Grounding</strong>
              <p>
                Responses are synthesized exclusively from scan AST records and NIST SP 800-208 / PQC
                quantum safety standards.
              </p>
            </div>
          </div>
        </aside>
      </div>
    </main>
  );
}
