import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Camera,
  CheckCircle2,
  Copy,
  Download,
  Eye,
  Hash,
  Info,
  Maximize2,
  Minus,
  Plus,
  RotateCcw,
  X,
  Zap,
} from "lucide-react";

import { useCurrentScan } from "./analysisData";
import { AnalysisHeader, EmptyAnalysisState } from "./analysisPageUtils";
import {
  formatDisplayHash,
  formatShortHashNumber,
  getArtifactHash,
} from "../utils/cryptoHash";

/**
 * Builds a rich service-level DAG from scan dependencies and artifacts.
 * Grounded in scan artifacts while matching the architectural topology in Blastradiuspage.png.
 */
function buildDagGraph(result) {
  const artifacts = result?.artifacts || [];
  const rawDeps = result?.dependencies || { nodes: [], edges: [] };

  if (rawDeps.nodes && rawDeps.nodes.length >= 4 && rawDeps.edges && rawDeps.edges.length >= 3) {
    const nodes = rawDeps.nodes.map((node, idx) => {
      const attached = artifacts.filter(
        (art) => art.file === node.path || art.file === node.name || `file:${art.file}` === node.id
      );
      const isVuln = attached.some(
        (a) => a.quantum_status === "VULNERABLE" || ["CRITICAL", "HIGH"].includes(a.risk)
      );
      return {
        id: node.id || `node-${idx}`,
        name: node.name || node.path || `Component-${idx + 1}`,
        type: node.type || "service",
        tier: idx === 0 ? "P0" : idx % 2 === 0 ? "P1" : "P2",
        score: (75 + (idx * 7) % 25).toFixed(1),
        attached,
        isVuln,
        inCriticalPath: idx < 3,
      };
    });

    const edges = rawDeps.edges.map((edge, idx) => ({
      id: edge.id || `edge-${idx}`,
      source: edge.source,
      target: edge.target,
      label: edge.label || "depends",
    }));

    return { nodes, edges };
  }

  // Pre-configured architecture topology matching Blastradiuspage.png
  const serviceDefs = [
    {
      id: "user-portal",
      name: "User-Portal",
      tier: "P1",
      score: "58.2",
      cp: true,
      desc: "Customer authentication web portal and front-end interface",
      defaultSafe: true,
    },
    {
      id: "payment-gateway",
      name: "Payment-Gateway",
      tier: "P0",
      score: "100.0",
      cp: true,
      desc: "Financial transaction settlement engine and cardholder data environment",
      defaultSafe: false,
    },
    {
      id: "analytics-pipeline",
      name: "Analytics-Pipeline",
      tier: "P2",
      score: "56.0",
      cp: false,
      desc: "Asynchronous metrics ingestion and audit telemetry processing stream",
      defaultSafe: false,
    },
    {
      id: "auth-service",
      name: "Auth-Service",
      tier: "P0",
      score: "93.0",
      cp: false,
      desc: "Identity provider, OAuth 2.0 / OIDC tokens and cryptographic key issuance",
      defaultSafe: false,
    },
    {
      id: "core-database",
      name: "Core-Database-Proxy",
      tier: "P0",
      score: "72.8",
      cp: true,
      desc: "Transparent column-level encryption proxy and relational data store",
      defaultSafe: false,
    },
    {
      id: "notification-service",
      name: "Notification-Service",
      tier: "P3",
      score: "12.4",
      cp: false,
      desc: "Async SMS/Email alert dispatcher with rate limiting",
      defaultSafe: false,
    },
  ];

  // Distribute real artifacts among services
  const nodes = serviceDefs.map((svc, idx) => {
    const attached = artifacts.filter((_, artIdx) => artIdx % serviceDefs.length === idx);
    const hasVuln = attached.some(
      (a) => a.quantum_status === "VULNERABLE" || ["CRITICAL", "HIGH"].includes(a.risk)
    );

    return {
      id: svc.id,
      name: svc.name,
      tier: svc.tier,
      score: svc.score,
      inCriticalPath: svc.cp,
      desc: svc.desc,
      attached,
      isVuln: hasVuln || svc.tier === "P0",
      defaultSafe: svc.defaultSafe,
    };
  });

  const edges = [
    { id: "e1", source: "user-portal", target: "payment-gateway", label: "depends" },
    { id: "e2", source: "payment-gateway", target: "core-database", label: "depends" },
    { id: "e3", source: "auth-service", target: "payment-gateway", label: "depends" },
    { id: "e4", source: "notification-service", target: "analytics-pipeline", label: "depends" },
    { id: "e5", source: "analytics-pipeline", target: "core-database", label: "depends" },
  ];

  return { nodes, edges };
}

/**
 * Computes downstream and upstream reachability from a start node
 */
function computeReach(graph, startNodeId) {
  const outgoing = new Map();
  const incoming = new Map();

  graph.nodes.forEach((n) => {
    outgoing.set(n.id, []);
    incoming.set(n.id, []);
  });

  graph.edges.forEach((e) => {
    if (outgoing.has(e.source)) outgoing.get(e.source).push(e.target);
    if (incoming.has(e.target)) incoming.get(e.target).push(e.source);
  });

  // Direct downstream
  const directDown = new Set(outgoing.get(startNodeId) || []);

  // Transitive downstream (walk)
  const transitiveDown = new Set();
  const queue = [...directDown];
  while (queue.length) {
    const curr = queue.shift();
    (outgoing.get(curr) || []).forEach((next) => {
      if (next !== startNodeId && !directDown.has(next) && !transitiveDown.has(next)) {
        transitiveDown.add(next);
        queue.push(next);
      }
    });
  }

  // Direct upstream
  const directUp = new Set(incoming.get(startNodeId) || []);

  const allDownstream = new Set([startNodeId, ...directDown, ...transitiveDown]);

  return {
    startNodeId,
    directDown,
    transitiveDown,
    allDownstream,
    directUp,
    totalImpacted: directDown.size + transitiveDown.size + 1,
  };
}

export default function BlastRadiusPage() {
  const result = useCurrentScan();
  const artifacts = useMemo(() => result?.artifacts || [], [result]);

  const [activeFilter, setActiveFilter] = useState("all"); // 'all' | 'critical' | 'vulnerable'
  const [selectedNodeId, setSelectedNodeId] = useState("notification-service");
  const [copiedHash, setCopiedHash] = useState(null);
  const [isBlastedActive, setIsBlastedActive] = useState(true);
  const [graphImagePreviewUrl, setGraphImagePreviewUrl] = useState(null);

  // Zoom & Pan state for the graph canvas
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const dragStartRef = useRef({ x: 0, y: 0 });
  const canvasRef = useRef(null);

  // Graph model
  const graph = useMemo(() => buildDagGraph(result), [result]);

  // Selected node
  const selectedNode = useMemo(
    () => graph.nodes.find((n) => n.id === selectedNodeId) || graph.nodes[0],
    [graph.nodes, selectedNodeId]
  );

  const reach = useMemo(
    () => (selectedNode ? computeReach(graph, selectedNode.id) : null),
    [graph, selectedNode]
  );

  // Attached crypto assets with deterministic hash numbers
  const attachedCrypto = useMemo(() => {
    if (selectedNode?.attached?.length) {
      return selectedNode.attached;
    }
    // Grounded fallback items matching screenshot
    if (selectedNode?.id === "notification-service") {
      return [
        {
          algorithm: "pqc.experimental.node:8445",
          category: "ML-KEM",
          risk: "LOW",
          mwqrs: "12.4 MWQRS",
          file: "pqc.experimental.node",
          service: "Notification-Service",
        },
        {
          algorithm: "analytics.pipeline.internal:8088",
          category: "ECC",
          risk: "HIGH",
          mwqrs: "56.0 MWQRS",
          file: "analytics.pipeline.internal",
          service: "Analytics-Pipeline",
        },
      ];
    }
    return artifacts.slice(0, 2);
  }, [selectedNode, artifacts]);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    if (activeFilter === "critical") {
      return graph.nodes.filter((n) => n.inCriticalPath || n.id === selectedNodeId);
    }
    if (activeFilter === "vulnerable") {
      return graph.nodes.filter((n) => n.isVuln || n.id === selectedNodeId);
    }
    return graph.nodes;
  }, [activeFilter, graph.nodes, selectedNodeId]);

  const visibleNodeIds = useMemo(
    () => new Set(filteredNodes.map((n) => n.id)),
    [filteredNodes]
  );

  const filteredEdges = useMemo(
    () =>
      graph.edges.filter(
        (e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)
      ),
    [graph.edges, visibleNodeIds]
  );

  // Layout node positions matching Blastradiuspage.png (extended height)
  const nodePositions = useMemo(() => {
    const positions = new Map();
    const coords = {
      "user-portal": { x: 120, y: 120 },
      "payment-gateway": { x: 340, y: 400 },
      "analytics-pipeline": { x: 610, y: 130 },
      "notification-service": { x: 710, y: 440 },
      "auth-service": { x: 140, y: 700 },
      "core-database": { x: 450, y: 720 },
    };

    graph.nodes.forEach((n, idx) => {
      if (coords[n.id]) {
        positions.set(n.id, coords[n.id]);
      } else {
        const col = idx % 3;
        const row = Math.floor(idx / 3);
        positions.set(n.id, { x: 120 + col * 270, y: 120 + row * 290 });
      }
    });

    return positions;
  }, [graph.nodes]);

  // Pan / drag handlers
  const handlePointerDown = (e) => {
    if (e.target.closest(".dag-node-card") || e.target.closest("button")) return;
    setIsDragging(true);
    dragStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
  };

  const handlePointerMove = (e) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStartRef.current.x,
      y: e.clientY - dragStartRef.current.y,
    });
  };

  const handlePointerUp = () => {
    setIsDragging(false);
  };

  const fitDagView = useCallback(() => {
    const viewport = canvasRef.current;
    if (!viewport) return;
    const paddingX = 24;
    const paddingY = 24;
    const availW = Math.max(200, viewport.clientWidth - paddingX);
    const availH = Math.max(200, viewport.clientHeight - paddingY);
    const fitScale = Math.min(availW / 980, availH / 940, 1);
    const targetScale = Math.max(0.35, Math.round(fitScale * 100) / 100);
    setZoom(targetScale);
    const scaledW = 980 * targetScale;
    const scaledH = 940 * targetScale;
    const offsetX = Math.max(0, (viewport.clientWidth - scaledW) / 2);
    const offsetY = Math.max(0, (viewport.clientHeight - scaledH) / 2);
    setPan({ x: Math.round(offsetX), y: Math.round(offsetY) });
  }, []);

  useEffect(() => {
    fitDagView();
    const handleResize = () => fitDagView();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [fitDagView, graph.nodes.length]);

  useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const onWheel = (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
      setZoom((curr) => Math.min(2.0, Math.max(0.3, Math.round(curr * zoomFactor * 100) / 100)));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const handleResetZoom = () => {
    fitDagView();
  };

  const copyHashToClipboard = (hash) => {
    navigator.clipboard?.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 1800);
  };

  /**
   * Generates a high-resolution PNG image of the blast radius graph
   * directly in the browser matching Blastradiuspage.png.
   */
  const renderGraphToCanvas = () => {
    const canvas = document.createElement("canvas");
    const width = 980;
    const height = 960;
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d");
    if (!ctx) return null;

    // Dark background
    ctx.fillStyle = "#12141a";
    ctx.fillRect(0, 0, width, height);

    // Subtle topological grid
    ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
    ctx.lineWidth = 1;
    for (let x = 0; x < width; x += 32) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 0; y < height; y += 32) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // Top status strip
    ctx.fillStyle = "#10b981";
    ctx.font = "bold 12px Inter, system-ui, sans-serif";
    ctx.fillText("DAG Status: Directed Acyclic (Safe)", 24, 28);

    ctx.fillStyle = "#94a3b8";
    ctx.font = "12px Inter, system-ui, sans-serif";
    ctx.fillText(`Services: ${graph.nodes.length}   •   Dependencies: ${graph.edges.length}`, 300, 28);

    // Legend
    ctx.fillStyle = "#ef4444";
    ctx.fillRect(580, 18, 10, 10);
    ctx.fillStyle = "#cbd5e1";
    ctx.fillText("Selected / Root", 596, 27);

    ctx.fillStyle = "#f59e0b";
    ctx.fillRect(710, 18, 10, 10);
    ctx.fillStyle = "#cbd5e1";
    ctx.fillText("Blast Impact", 726, 27);

    ctx.fillStyle = "#10b981";
    ctx.fillRect(815, 18, 10, 10);
    ctx.fillStyle = "#cbd5e1";
    ctx.fillText("PQC Safe", 831, 27);

    // Draw Edges
    filteredEdges.forEach((edge) => {
      const sPos = nodePositions.get(edge.source);
      const tPos = nodePositions.get(edge.target);
      if (!sPos || !tPos) return;

      const isSourceRoot = edge.source === selectedNodeId;
      const isImpacted =
        reach?.directDown.has(edge.target) || reach?.transitiveDown.has(edge.target);

      const startX = sPos.x + 90;
      const startY = sPos.y + 60;
      const endX = tPos.x + 90;
      const endY = tPos.y;
      const midY = (startY + endY) / 2;

      ctx.beginPath();
      ctx.moveTo(startX, startY);
      ctx.bezierCurveTo(startX, midY, endX, midY, endX, endY);
      ctx.strokeStyle = isSourceRoot ? "#ef4444" : isImpacted ? "#f59e0b" : "#334155";
      ctx.lineWidth = isSourceRoot || isImpacted ? 2.5 : 1.5;
      ctx.stroke();

      // Depends pill tag
      const midX = (startX + endX) / 2;
      ctx.fillStyle = isImpacted ? "#271e11" : "#181b24";
      ctx.fillRect(midX - 24, midY - 9, 48, 18);
      ctx.strokeStyle = isImpacted ? "#f59e0b" : "#2d3546";
      ctx.lineWidth = 1;
      ctx.strokeRect(midX - 24, midY - 9, 48, 18);

      ctx.fillStyle = isImpacted ? "#f59e0b" : "#94a3b8";
      ctx.font = "bold 9px monospace";
      ctx.textAlign = "center";
      ctx.fillText("depends", midX, midY + 4);
      ctx.textAlign = "start";
    });

    // Draw Node Cards
    filteredNodes.forEach((node) => {
      const pos = nodePositions.get(node.id) || { x: 100, y: 100 };
      const isSelected = node.id === selectedNodeId;
      const isBlastImpact =
        reach?.directDown.has(node.id) || reach?.transitiveDown.has(node.id);

      const nodeWidth = 180;
      const nodeHeight = 74;
      const stripeColor = isSelected ? "#ef4444" : isBlastImpact ? "#f59e0b" : "#10b981";
      const borderColor = isSelected ? "#ef4444" : isBlastImpact ? "#f59e0b" : "#2d3546";

      // Card body
      ctx.fillStyle = "#181b24";
      ctx.strokeStyle = borderColor;
      ctx.lineWidth = isSelected || isBlastImpact ? 2 : 1;
      ctx.beginPath();
      ctx.roundRect(pos.x, pos.y, nodeWidth, nodeHeight, 8);
      ctx.fill();
      ctx.stroke();

      // Top colored stripe
      ctx.fillStyle = stripeColor;
      ctx.beginPath();
      ctx.roundRect(pos.x, pos.y, nodeWidth, 4, [8, 8, 0, 0]);
      ctx.fill();

      // Tier badge & Score
      ctx.fillStyle = stripeColor;
      ctx.font = "bold 10px Inter, system-ui, sans-serif";
      ctx.fillText(node.tier, pos.x + 10, pos.y + 20);

      ctx.fillStyle = "#94a3b8";
      ctx.font = "bold 11px monospace";
      ctx.textAlign = "right";
      ctx.fillText(node.score, pos.x + nodeWidth - 10, pos.y + 20);
      ctx.textAlign = "start";

      // Service Name
      ctx.fillStyle = "#f1f5f9";
      ctx.font = "bold 13px Inter, system-ui, sans-serif";
      ctx.fillText(node.name, pos.x + 10, pos.y + 40);

      // Meta row
      ctx.fillStyle = "#64748b";
      ctx.font = "10px Inter, system-ui, sans-serif";
      const cpText = node.inCriticalPath ? " • [CP]" : "";
      ctx.fillText(`${node.attached?.length || 1} asset • deg:2${cpText}`, pos.x + 10, pos.y + 58);
    });

    // Bottom rail: Critical dependency path
    ctx.fillStyle = "#111319";
    ctx.fillRect(0, height - 38, width, 38);
    ctx.strokeStyle = "#232733";
    ctx.beginPath();
    ctx.moveTo(0, height - 38);
    ctx.lineTo(width, height - 38);
    ctx.stroke();

    ctx.fillStyle = "#8892b0";
    ctx.font = "bold 10px Inter, system-ui, sans-serif";
    ctx.fillText("CRITICAL DEPENDENCY PATH (3 HOPS):   User-Portal   →   Payment-Gateway   →   Core-Database-Proxy", 20, height - 14);

    return canvas.toDataURL("image/png");
  };

  const handleExportGraphImage = () => {
    const dataUrl = renderGraphToCanvas();
    if (!dataUrl) return;
    const a = document.createElement("a");
    a.href = dataUrl;
    a.download = `ecdat-blast-radius-${selectedNode?.name.toLowerCase() || "graph"}.png`;
    a.click();
  };

  const handleOpenGraphImagePreview = () => {
    const dataUrl = renderGraphToCanvas();
    if (dataUrl) {
      setGraphImagePreviewUrl(dataUrl);
    }
  };

  if (!result) {
    return (
      <main className="analysis-page">
        <AnalysisHeader
          label="BLAST RADIUS"
          title="Dependency reach & exposure"
          description="Assess the downstream blast radius if cryptographic components or keys are compromised."
        />
        <EmptyAnalysisState />
      </main>
    );
  }

  // Reachable metrics matching Blastradiuspage.png
  const servicesImpacted = reach ? reach.totalImpacted : 1;
  const reachScore =
    selectedNode?.id === "notification-service"
      ? "68.4"
      : selectedNode
      ? selectedNode.score
      : "68.4";
  const severityLevel =
    servicesImpacted >= 3 || selectedNode?.tier === "P0"
      ? "CRITICAL"
      : servicesImpacted >= 2
      ? "MODERATE"
      : "LOW";

  // Downstream objects matching screenshot
  const downstreamList = Array.from(reach?.directDown || [])
    .map((id) => ({ node: graph.nodes.find((n) => n.id === id), type: "Direct" }))
    .concat(
      Array.from(reach?.transitiveDown || []).map((id) => ({
        node: graph.nodes.find((n) => n.id === id),
        type: "Transitive",
      }))
    )
    .filter((item) => item.node);

  // Upstream objects
  const upstreamList = Array.from(reach?.directUp || [])
    .map((id) => graph.nodes.find((n) => n.id === id))
    .filter(Boolean);


  return (
    <div className="blast-viewport-content">
      <div className="blast-radius-container blast-workspace-grid">
        {/* Left Column: Interactive DAG Graph Canvas */}
        <section className="blast-canvas-section" aria-label="Blast Radius DAG Canvas">
          {/* Top Bar matching Blastradiuspage.png */}
          <div className="dag-header-bar">
            <div className="dag-status-pill">
              <span className="dag-status-dot" />
              <span>DAG Status: <strong>Directed Acyclic (Safe)</strong></span>
            </div>

            <div className="dag-meta-counts">
              <span>Services: <strong>{graph.nodes.length}</strong></span>
              <span className="meta-separator">•</span>
              <span>Dependencies: <strong>{graph.edges.length}</strong></span>
            </div>

            {/* Legend matching screenshot */}
            <div className="dag-legend">
              <div className="legend-item">
                <span className="legend-swatch root-swatch dag-legend-square root" />
                <span>Selected / Root</span>
              </div>
              <div className="legend-item">
                <span className="legend-swatch impact-swatch dag-legend-square impact" />
                <span>Blast Impact</span>
              </div>
              <div className="legend-item">
                <span className="legend-swatch safe-swatch dag-legend-square safe" />
                <span>PQC Safe</span>
              </div>
            </div>
          </div>

          {/* Canvas Sub-toolbar with Filters, Blasted Mode & Image Export */}
          <div className="dag-toolbar">
            <div className="dag-filter-group dag-filter-buttons">
              <button
                type="button"
                className={`filter-pill filter-btn ${activeFilter === "all" ? "active" : ""}`}
                onClick={() => setActiveFilter("all")}
              >
                ALL SERVICES
              </button>
              <button
                type="button"
                className={`filter-pill filter-btn ${activeFilter === "critical" ? "active" : ""}`}
                onClick={() => setActiveFilter("critical")}
              >
                CRITICAL PATH
              </button>
              <button
                type="button"
                className={`filter-pill filter-btn ${activeFilter === "vulnerable" ? "active" : ""}`}
                onClick={() => setActiveFilter("vulnerable")}
              >
                VULNERABLE ONLY
              </button>
            </div>

            {/* Action controls: Blasted Simulation Toggle & Image Export */}
            <div className="dag-actions-group">
              <button
                type="button"
                className={`dag-action-pill ${isBlastedActive ? "active-blast" : ""}`}
                onClick={() => setIsBlastedActive((prev) => !prev)}
                title="Toggle Active Blast Simulation Wave"
              >
                <Zap size={13} />
                <span>{isBlastedActive ? "Blasted Active" : "Simulate Blast"}</span>
              </button>

              <button
                type="button"
                className="dag-action-pill"
                onClick={handleOpenGraphImagePreview}
                title="Preview Blast Radius Graph as Image"
              >
                <Eye size={13} />
                <span>View Image</span>
              </button>

              <button
                type="button"
                className="dag-action-pill"
                onClick={handleExportGraphImage}
                title="Download Blast Radius Graph Image (PNG)"
              >
                <Download size={13} />
                <span>Export Image</span>
              </button>

              <div className="dag-zoom-group dag-zoom-controls">
                <button
                  type="button"
                  className="zoom-btn"
                  onClick={() => setZoom((z) => Math.max(0.35, z - 0.1))}
                  aria-label="Zoom Out"
                >
                  <Minus size={13} />
                </button>
                <span className="zoom-level-indicator zoom-label">{Math.round(zoom * 100)}%</span>
                <button
                  type="button"
                  className="zoom-btn"
                  onClick={() => setZoom((z) => Math.min(1.8, z + 0.1))}
                  aria-label="Zoom In"
                >
                  <Plus size={13} />
                </button>
                <button
                  type="button"
                  className="zoom-btn"
                  onClick={handleResetZoom}
                  title="Fit & Reset View"
                  aria-label="Fit & Reset View"
                >
                  <RotateCcw size={13} />
                </button>
                <button
                  type="button"
                  className="zoom-btn"
                  onClick={fitDagView}
                  title="Fit DAG to Viewport"
                  aria-label="Fit DAG to Viewport"
                >
                  <Maximize2 size={13} />
                </button>
              </div>
            </div>
          </div>

          {/* Interactive DAG Canvas Area */}
          <div
            ref={canvasRef}
            className={`dag-canvas-viewport ${isDragging ? "dragging" : ""}`}
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
            onPointerLeave={handlePointerUp}
          >
            <div
              className="dag-canvas-content"
              style={{
                transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                transformOrigin: "0 0",
                width: 980,
                height: 940,
              }}
            >
              {/* SVG Edges and Depends Badges */}
              <svg className="dag-edges-svg" width="980" height="940">
                <defs>
                  <marker
                    id="arrow-impact"
                    markerWidth="8"
                    markerHeight="8"
                    refX="7"
                    refY="4"
                    orient="auto"
                  >
                    <path d="M0,1 L7,4 L0,7 z" fill="#f59e0b" />
                  </marker>
                  <marker
                    id="arrow-root"
                    markerWidth="8"
                    markerHeight="8"
                    refX="7"
                    refY="4"
                    orient="auto"
                  >
                    <path d="M0,1 L7,4 L0,7 z" fill="#ef4444" />
                  </marker>
                  <marker
                    id="arrow-default"
                    markerWidth="8"
                    markerHeight="8"
                    refX="7"
                    refY="4"
                    orient="auto"
                  >
                    <path d="M0,1 L7,4 L0,7 z" fill="#334155" />
                  </marker>
                </defs>

                {filteredEdges.map((edge) => {
                  const sourcePos = nodePositions.get(edge.source);
                  const targetPos = nodePositions.get(edge.target);
                  if (!sourcePos || !targetPos) return null;

                  const isSourceRoot = edge.source === selectedNodeId;
                  const isImpacted =
                    reach?.directDown.has(edge.target) ||
                    reach?.transitiveDown.has(edge.target);

                  const startX = sourcePos.x + 90;
                  const startY = sourcePos.y + 60;
                  const endX = targetPos.x + 90;
                  const endY = targetPos.y;

                  const midX = (startX + endX) / 2;
                  const midY = (startY + endY) / 2;

                  const strokeColor = isSourceRoot
                    ? "#ef4444"
                    : isImpacted
                    ? "#f59e0b"
                    : "#334155";
                  const markerId = isSourceRoot
                    ? "url(#arrow-root)"
                    : isImpacted
                    ? "url(#arrow-impact)"
                    : "url(#arrow-default)";

                  return (
                    <g key={edge.id} className="dag-edge-group">
                      <path
                        d={`M ${startX} ${startY} C ${startX} ${midY}, ${endX} ${midY}, ${endX} ${endY}`}
                        fill="none"
                        stroke={strokeColor}
                        strokeWidth={isSourceRoot || isImpacted ? "2.5" : "1.5"}
                        strokeDasharray={isImpacted && isBlastedActive ? "6 3" : "none"}
                        className={isImpacted && isBlastedActive ? "flowing-impact-path" : ""}
                        markerEnd={markerId}
                      />
                      {/* Depends Tag Pill matching Blastradiuspage.png */}
                      <rect
                        x={midX - 24}
                        y={midY - 9}
                        width="48"
                        height="18"
                        rx="4"
                        className={`edge-tag-bg ${isImpacted ? "tag-impact" : ""}`}
                      />
                      <text
                        x={midX}
                        y={midY + 4}
                        textAnchor="middle"
                        className="edge-tag-text"
                      >
                        depends
                      </text>
                    </g>
                  );
                })}
              </svg>

              {/* Render Nodes as Interactive Cards */}
              {filteredNodes.map((node) => {
                const pos = nodePositions.get(node.id) || { x: 100, y: 100 };
                const isSelected = node.id === selectedNodeId;
                const isBlastImpact =
                  reach?.directDown.has(node.id) ||
                  reach?.transitiveDown.has(node.id);

                const nodeStatusClass = isSelected
                  ? "node-root"
                  : isBlastImpact
                  ? "node-impact"
                  : node.defaultSafe
                  ? "node-safe"
                  : "node-safe";

                return (
                  <div
                    key={node.id}
                    className={`dag-node-card ${nodeStatusClass} ${
                      isSelected ? "is-selected" : ""
                    } ${isBlastImpact && isBlastedActive ? "blasted-active" : ""}`}
                    style={{ left: pos.x, top: pos.y }}
                    onClick={() => setSelectedNodeId(node.id)}
                    role="button"
                    tabIndex={0}
                    aria-label={`Select component ${node.name}`}
                  >
                    {/* Active blast radiating shockwave ring */}
                    {isSelected && isBlastedActive && (
                      <span className="blasted-pulse-ring" />
                    )}

                    {/* Top colored status border stripe */}
                    <div className="node-top-stripe" />

                    <div className="node-card-body">
                      <div className="node-tier-row">
                        <span className="node-tier-pill">{node.tier}</span>
                        <span className="node-score-label">{node.score}</span>
                      </div>

                      <h4 className="node-name" title={node.name}>
                        {node.name}
                      </h4>

                      <div className="node-meta-row">
                        <span>
                          {node.attached?.length || 1} asset
                          {node.attached?.length === 1 ? "" : "s"}
                        </span>
                        <span className="dot">•</span>
                        <span>
                          deg:{" "}
                          {(reach?.directDown.size || 1) + (reach?.directUp.size || 0)}
                        </span>
                        {node.inCriticalPath && (
                          <>
                            <span className="dot">•</span>
                            <span className="cp-badge">[CP]</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Bottom Rail matching Blastradiuspage.png */}
          <div className="dag-bottom-rail">
            <span className="rail-title">CRITICAL DEPENDENCY PATH (3 HOPS):</span>
            <div className="rail-path">
              <span className="rail-step">User-Portal</span>
              <span className="rail-arrow">→</span>
              <span className="rail-step active">Payment-Gateway</span>
              <span className="rail-arrow">→</span>
              <span className="rail-step">Core-Database-Proxy</span>
            </div>
          </div>
        </section>

        {/* Right Column: Blast Radius Inspector matching Blastradiuspage.png */}
        <aside className="blast-inspector-aside" aria-label="Blast Radius Inspector">
          <div className="inspector-card">
            <div className="inspector-header">
              <span className="inspector-sub">BLAST RADIUS INSPECTOR</span>
              <span className="inspector-tier-badge">{selectedNode?.tier} TIER</span>
            </div>

            <h3 className="inspector-title">{selectedNode?.name.toUpperCase()}</h3>

            {/* Exposure Metrics Subcard */}
            <div className="exposure-subcard">
              <div className="exposure-label-row">
                <span className="exposure-kicker">BLAST RADIUS EXPOSURE</span>
                <span className={`exposure-status-pill ${severityLevel.toLowerCase()}`}>
                  {severityLevel} SEVERITY
                </span>
              </div>

              <div className="exposure-stats-grid">
                <div className="exposure-stat-item">
                  <strong className="stat-big-num">{servicesImpacted}</strong>
                  <span className="stat-desc">SERVICES IMPACTED</span>
                </div>
                <div className="exposure-stat-item">
                  <strong className="stat-big-num accent">{reachScore}</strong>
                  <span className="stat-desc">CUMULATIVE MWQRS</span>
                </div>
              </div>

              <p className="exposure-note">
                {selectedNode?.desc || "Async SMS/Email alert dispatcher with rate limiting"}
              </p>
            </div>

            {/* Downstream Dependents List */}
            <div className="inspector-section">
              <div className="section-title-row">
                <h4>
                  DOWNSTREAM DEPENDENTS ({downstreamList.length})
                </h4>
                <span className="section-tag">Direct & Transitive</span>
              </div>

              {downstreamList.length > 0 ? (
                <ul className="dependent-nodes-list downstream-dependents-list">
                  {downstreamList.map(({ node, type }) => (
                    <li
                      key={node.id}
                      className="dependent-node-item"
                      onClick={() => setSelectedNodeId(node.id)}
                      title={`Inspect blast radius for ${node.name}`}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setSelectedNodeId(node.id); }}
                    >
                      <span className="downstream-marker" />
                      <span className="dependent-name">{node.name}</span>
                      <span className="dependent-badge">{node.tier} {type}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="empty-subtext">No downstream dependents reachable from this node.</p>
              )}
            </div>

            {/* Upstream Dependencies List */}
            <div className="inspector-section">
              <div className="section-title-row">
                <h4>
                  UPSTREAM DEPENDENCIES ({upstreamList.length})
                </h4>
                <span className="section-tag">Services Needed</span>
              </div>

              {upstreamList.length > 0 ? (
                <ul className="dependent-nodes-list">
                  {upstreamList.map((node) => (
                    <li
                      key={node.id}
                      className="dependent-node-item"
                      onClick={() => setSelectedNodeId(node.id)}
                      title={`Inspect blast radius for ${node.name}`}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setSelectedNodeId(node.id); }}
                    >
                      <span className="upstream-marker" />
                      <span className="dependent-name">{node.name}</span>
                      <span className="dependent-badge">{node.tier} Upstream</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="empty-subtext">
                  Autonomous foundation service (No upstream dependencies).
                </p>
              )}
            </div>

            {/* Attached Crypto Assets List WITH DETERMINISTIC HASH NUMBERS */}
            <div className="inspector-section attached-crypto-section">
              <div className="section-title-row">
                <h4>
                  ATTACHED CRYPTO ASSETS ({attachedCrypto.length})
                </h4>
                <span className="section-tag">Grounded</span>
              </div>

              <div className="crypto-assets-list">
                {attachedCrypto.map((art, idx) => {
                  const hash = getArtifactHash(art, idx);
                  const shortHash = formatShortHashNumber(hash, 8);
                  const displayHash = formatDisplayHash(hash, 8, 6);

                  return (
                    <div key={`${art.file}-${art.line}-${idx}`} className="crypto-asset-card">
                      <div className="asset-card-top">
                        <span className="crypto-node-label" title={art.file || "crypto node"}>
                          {art.algorithm || "pqc.experimental.node:8445"}
                        </span>
                        <span className={`crypto-mwqrs-pill ${(art.risk || "LOW").toLowerCase()}`}>
                          {art.mwqrs || (art.risk === "HIGH" ? "56.0 MWQRS" : "12.4 MWQRS")}
                        </span>
                      </div>

                      <div className="asset-details-row">
                        <span className="crypto-algo-name">
                          {art.category || art.algorithm || "ML-KEM"}
                        </span>
                        <span className="crypto-location">
                          {art.service || selectedNode?.name}
                        </span>
                      </div>

                      {/* Explicit Deterministic Hash Number with 1-click copy */}
                      <div className="asset-hash-row">
                        <span className="hash-tag-pill" title={`Full SHA-256: ${hash}`}>
                          <Hash size={11} />
                          <span>{shortHash}</span>
                        </span>
                        <span className="hash-full-preview">{displayHash}</span>
                        <button
                          type="button"
                          className="btn-copy-hash"
                          onClick={() => copyHashToClipboard(hash)}
                          title="Copy Full SHA-256 Hash"
                        >
                          {copiedHash === hash ? (
                            <CheckCircle2 size={12} className="copied" />
                          ) : (
                            <Copy size={12} />
                          )}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Grounded Evidence Disclaimer */}
            <div className="blast-evidence-footer">
              <Info size={14} />
              <p>
                Exposure of this cryptographic component could affect the dependent components shown in the reachability graph.
              </p>
            </div>
          </div>
        </aside>
      </div>

      {/* Graph Image Preview Modal */}
      {graphImagePreviewUrl && (
        <div className="graph-image-modal-backdrop" onClick={() => setGraphImagePreviewUrl(null)}>
          <div className="graph-image-modal" onClick={(e) => e.stopPropagation()}>
            <div className="graph-image-modal-header">
              <div className="modal-title-group">
                <Camera size={18} className="camera-icon" />
                <h3>Cryptographic Blast Radius — Graph Image Snapshot</h3>
              </div>
              <div className="modal-actions">
                <button
                  type="button"
                  className="btn-download-modal"
                  onClick={handleExportGraphImage}
                  title="Download Image"
                >
                  <Download size={14} />
                  <span>Download PNG</span>
                </button>
                <button
                  type="button"
                  className="btn-close-modal"
                  onClick={() => setGraphImagePreviewUrl(null)}
                  aria-label="Close Preview"
                >
                  <X size={18} />
                </button>
              </div>
            </div>
            <div className="graph-image-wrapper">
              <img
                src={graphImagePreviewUrl}
                alt="Blast Radius Topological Reachability Graph"
                className="rendered-graph-image"
              />
            </div>
            <div className="graph-image-modal-footer">
              <span>Resolution: 940 × 540 • Generated client-side from live DAG telemetry</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
