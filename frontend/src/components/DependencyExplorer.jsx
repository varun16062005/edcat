import { Maximize2, Minus, Plus, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useEcdatContext } from "../context/useEcdatContext";
import { artifactEntityId, fileEntityId, makeEntityId } from "../context/entityIds";

const NODE_COLORS = {
  project: "#b13f9b",
  file: "#4659d2",
  external: "#4659d2",
  artifact: "#b13f9b",
};

const NODE_LABELS = {
  project: "Project",
  file: "File",
  external: "External package",
  artifact: "Crypto artifact",
};

function shortLabel(value, max = 28) {
  const text = String(value || "");
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function DependencyNode({ node, selected, dimmed, onSelect }) {
  const progress = node.type === "project"
    ? 100
    : node.type === "artifact"
      ? node.risk === "CRITICAL" ? 92 : node.risk === "HIGH" ? 76 : 58
      : node.type === "external" ? 68 : 46;

  return (
    <button
      type="button"
      className={`dependency-graph-node ${selected ? "selected" : ""} ${dimmed ? "dimmed" : ""}`}
      style={{ borderColor: NODE_COLORS[node.type] || "#526174" }}
      onClick={() => onSelect(node)}
      title={`${NODE_LABELS[node.type] || "Dependency"}: ${node.name}`}
    >
      <span
        className="dependency-node-dot"
        style={{ background: NODE_COLORS[node.type] || "#526174" }}
      />
      <span className="dependency-node-type">
        {NODE_LABELS[node.type] || node.type}
      </span>
      <strong>{shortLabel(node.name || node.path)}</strong>
      {node.path && node.path !== node.name ? (
        <small>{shortLabel(node.path, 34)}</small>
      ) : null}
      <span className="dependency-node-progress" aria-hidden="true">
        <i style={{ width: `${progress}%` }} />
      </span>
    </button>
  );
}

function DependencyTree({ nodes, edges, selectedNodeId, onSelect }) {
  const [collapsedNodes, setCollapsedNodes] = useState(new Set());
  const [scale, setScale] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const viewportRef = useRef(null);
  const dragStart = useRef(null);

  const toggleNode = (nodeId) => {
    setCollapsedNodes((current) => {
      const next = new Set(current);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  };

  const treeModel = useMemo(() => {
    const nodeMap = new Map(nodes.map((node) => [node.id, node]));
    const children = new Map(nodes.map((node) => [node.id, []]));
    edges.forEach((edge) => {
      if (children.has(edge.source) && nodeMap.has(edge.target)) {
        children.get(edge.source).push(edge.target);
      }
    });

    const roots = nodes.filter((node) => node.type === "project");
    const positions = new Map();
    const depths = new Map();
    const visited = new Set();
    let leafIndex = 0;
    let maxDepth = 0;
    const horizontalGap = 190;
    const verticalGap = 112;
    const leftPadding = 92;
    const topPadding = 34;

    const placeNode = (nodeId, depth) => {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      depths.set(nodeId, depth);
      maxDepth = Math.max(maxDepth, depth);
      const childIds = collapsedNodes.has(nodeId) ? [] : (children.get(nodeId) || []);
      const validChildren = childIds.filter((childId) => !visited.has(childId));

      if (!validChildren.length) {
        positions.set(nodeId, { x: leftPadding + leafIndex * horizontalGap, y: topPadding + depth * verticalGap });
        leafIndex += 1;
        return positions.get(nodeId).x;
      }

      const childXs = validChildren.map((childId) => placeNode(childId, depth + 1));
      const x = (childXs[0] + childXs[childXs.length - 1]) / 2;
      positions.set(nodeId, { x, y: topPadding + depth * verticalGap });
      return x;
    };

    roots.forEach((root) => placeNode(root.id, 0));
    nodes.forEach((node) => {
      if (!visited.has(node.id)) placeNode(node.id, 0);
    });

    const visibleNodes = nodes.filter((node) => positions.has(node.id));
    const visibleIds = new Set(visibleNodes.map((node) => node.id));
    const visibleEdges = edges.filter((edge) => (
      visibleIds.has(edge.source)
      && visibleIds.has(edge.target)
      && !collapsedNodes.has(edge.source)
    ));
    return {
      nodes: visibleNodes,
      edges: visibleEdges,
      positions,
      width: Math.max(480, leftPadding * 2 + Math.max(leafIndex - 1, 0) * horizontalGap),
      height: Math.max(260, topPadding * 2 + maxDepth * verticalGap + 74),
    };
  }, [collapsedNodes, edges, nodes]);

  const connectedIds = useMemo(() => {
    if (!selectedNodeId) return new Set(treeModel.nodes.map((node) => node.id));
    const connected = new Set([selectedNodeId]);
    treeModel.edges.forEach((edge) => {
      if (edge.source === selectedNodeId) connected.add(edge.target);
      if (edge.target === selectedNodeId) connected.add(edge.source);
    });
    return connected;
  }, [selectedNodeId, treeModel.edges, treeModel.nodes]);

  const fitView = useCallback(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    const horizontalPadding = 40;
    const verticalPadding = 36;
    const nextScale = Math.min(
      1,
      (viewport.clientWidth - horizontalPadding) / treeModel.width,
      (viewport.clientHeight - verticalPadding) / treeModel.height,
    );
    setScale(Math.max(0.45, nextScale));
    setPan({ x: 0, y: 0 });
  }, [treeModel.height, treeModel.width]);

  useEffect(() => {
    fitView();
  }, [fitView]);

  const resetView = () => {
    setScale(1);
    setPan({ x: 0, y: 0 });
  };

  const onPointerDown = (event) => {
    if (event.target.closest("button")) return;
    setDragging(true);
    dragStart.current = { x: event.clientX - pan.x, y: event.clientY - pan.y };
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };

  const onPointerMove = (event) => {
    if (!dragging || !dragStart.current) return;
    setPan({
      x: event.clientX - dragStart.current.x,
      y: event.clientY - dragStart.current.y,
    });
  };

  return (
    <div className="dependency-tree-view">
      <div className="dependency-tree-controls">
        <button type="button" onClick={() => setScale((value) => Math.max(0.45, value - 0.1))} aria-label="Zoom out dependency tree"><Minus size={13} /></button>
        <span>{Math.round(scale * 100)}%</span>
        <button type="button" onClick={() => setScale((value) => Math.min(2, value + 0.1))} aria-label="Zoom in dependency tree"><Plus size={13} /></button>
        <button type="button" onClick={resetView} aria-label="Reset dependency tree"><RotateCcw size={13} /></button>
        <button type="button" onClick={fitView} aria-label="Fit dependency tree"><Maximize2 size={13} /><span>Fit tree</span></button>
      </div>
      <div
        ref={viewportRef}
        className={`dependency-tree-viewport ${dragging ? "dragging" : ""}`}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={() => { setDragging(false); dragStart.current = null; }}
        onPointerCancel={() => { setDragging(false); dragStart.current = null; }}
      >
        <div
          className="dependency-tree-canvas"
          style={{
            width: `${treeModel.width}px`,
            height: `${treeModel.height}px`,
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${scale})`,
          }}
        >
          <svg className="dependency-tree-svg" viewBox={`0 0 ${treeModel.width} ${treeModel.height}`} role="img" aria-label="Hierarchical cryptographic dependency flowchart">
            <defs>
              <marker id="dependency-tree-arrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
                <path d="M0,0 L9,4.5 L0,9 z" fill="#7e94b7" />
              </marker>
            </defs>
            {treeModel.edges.map((edge) => {
              const source = treeModel.positions.get(edge.source);
              const target = treeModel.positions.get(edge.target);
              if (!source || !target) return null;
              const startY = source.y + 34;
              const endY = target.y;
              const curve = Math.max(26, (endY - startY) * 0.42);
              const active = connectedIds.has(edge.source) && connectedIds.has(edge.target);
              return (
                <g className={`dependency-tree-edge ${active ? "" : "dimmed"} ${selectedNodeId && active ? "selected" : ""}`} key={edge.id}>
                  <path d={`M ${source.x} ${startY} C ${source.x} ${startY + curve}, ${target.x} ${endY - curve}, ${target.x} ${endY}`} markerEnd="url(#dependency-tree-arrow)" />
                  <text x={(source.x + target.x) / 2 + 8} y={(source.y + target.y) / 2}>{String(edge.label || edge.type || "relation")}</text>
                </g>
              );
            })}
          </svg>
          {treeModel.nodes.map((node) => {
            const point = treeModel.positions.get(node.id);
            const hasChildren = edges.some((edge) => edge.source === node.id);
            const collapsed = collapsedNodes.has(node.id);
            const connected = connectedIds.has(node.id);
            return (
              <div className={`dependency-tree-node-layer ${connected ? "" : "dimmed"}`} style={{ left: `${point.x - 78}px`, top: `${point.y}px` }} key={node.id}>
                {hasChildren ? (
                  <button type="button" className="dependency-tree-toggle" onClick={() => toggleNode(node.id)} aria-label={`${collapsed ? "Expand" : "Collapse"} ${String(node.name || node.path || "dependency")}`} aria-expanded={!collapsed}>
                    {collapsed ? "+" : "−"}
                  </button>
                ) : <span className="dependency-tree-toggle-spacer" />}
                <DependencyNode node={node} selected={selectedNodeId === node.id} dimmed={!connected} onSelect={onSelect} />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default function DependencyExplorer({
  dependencies,
  artifacts,
  files,
  view = "graph",
  highlightIds = [],
  selectedId = "",
}) {
  const { selectContext } = useEcdatContext();
  const [internalSelectedId, setInternalSelectedId] = useState("");
  const selectedNodeId = selectedId || internalSelectedId;
  const [scale, setScale] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef(null);
  const graphViewportRef = useRef(null);

  const model = dependencies || { nodes: [], edges: [], meta: {} };
  const nodes = useMemo(() => {
    const priority = {
      project: 0,
      file: 1,
      artifact: 2,
      external: 3,
    };
    return [...(model.nodes || [])]
      .sort((a, b) => (priority[a.type] ?? 4) - (priority[b.type] ?? 4))
      .slice(0, 60);
  }, [model.nodes]);
  const visibleNodeIds = useMemo(
    () => new Set(nodes.map((node) => node.id)),
    [nodes]
  );
  const edges = useMemo(
    () => (model.edges || [])
      .filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target))
      .slice(0, 160),
    [model.edges, visibleNodeIds]
  );
  const displayCapped = (model.nodes || []).length > nodes.length || (model.edges || []).length > edges.length;
  const nodeMap = useMemo(
    () => new Map(nodes.map((node) => [node.id, node])),
    [nodes]
  );
  const fileMap = useMemo(
    () => new Map(files.map((file, index) => [file.path || file.name || index, file])),
    [files]
  );

  const layout = useMemo(() => {
    const groups = ["project", "file", "external", "artifact"];
    const grouped = new Map(groups.map((type) => [type, []]));
    nodes.forEach((node) => {
      if (!grouped.has(node.type)) grouped.set(node.type, []);
      grouped.get(node.type).push(node);
    });
    const positions = new Map();
    const maxRows = 6;
    const rowHeight = 84;
    const columnWidth = 190;
    const layerGap = 110;
    const height = 560;
    let cursorX = 70;

    groups.forEach((type) => {
      const group = grouped.get(type) || [];
      const columnCount = Math.max(1, Math.ceil(group.length / maxRows));
      group.forEach((node, index) => {
        const column = Math.floor(index / maxRows);
        const row = index % maxRows;
        positions.set(node.id, {
          x: cursorX + column * columnWidth,
          y: 42 + row * rowHeight,
        });
      });
      cursorX += columnCount * columnWidth + layerGap;
    });
    return { positions, width: Math.max(1100, cursorX), height };
  }, [nodes]);

  const selectNode = (node) => {
    setInternalSelectedId(node.id);
    if (node.type === "artifact") {
      const artifact = artifacts[node.artifactIndex];
      if (!artifact) return;
      selectContext({
        entityType: "artifact",
        entityId: artifactEntityId(artifact, node.artifactIndex),
        name: artifact.algorithm || artifact.category || "Cryptographic artifact",
        file: artifact.file,
        line: artifact.line,
        algorithm: artifact.algorithm,
        risk: artifact.risk,
        quantumStatus: artifact.quantum_status,
        category: artifact.category,
        artifact,
        source: "dependency",
      });
      return;
    }

    if (node.type === "file") {
      const file = fileMap.get(node.path) || { path: node.path, name: node.name };
      const index = files.indexOf(file);
      selectContext({
        entityType: "file",
        entityId: fileEntityId(file, index < 0 ? 0 : index),
        name: file.name || node.name,
        path: file.path || node.path,
        type: file.type || node.fileType || "binary/unknown",
        file: file.path || file.name || node.path || node.name,
        fileRecord: file,
        source: "dependency",
      });
      return;
    }

    if (node.type === "external") {
      selectContext({
        entityType: "dependency",
        entityId: makeEntityId("dependency", node.name),
        name: node.name,
        dependencyType: "external",
        source: "dependency",
      });
      return;
    }

    selectContext({
      entityType: "scan",
      entityId: makeEntityId("scan", node.name),
      name: node.name,
      source: "dependency",
    });
  };

  const fitGraphView = useCallback(() => {
    const viewport = graphViewportRef.current;
    if (!viewport) return;
    const paddingX = 40;
    const paddingY = 40;
    const availW = Math.max(200, viewport.clientWidth - paddingX);
    const availH = Math.max(200, viewport.clientHeight - paddingY);
    const fitScale = Math.min(1, availW / layout.width, availH / layout.height);
    const targetScale = Math.max(0.35, fitScale);
    setScale(targetScale);
    const scaledW = layout.width * targetScale;
    const scaledH = layout.height * targetScale;
    const offsetX = Math.max(0, (viewport.clientWidth - scaledW) / 2);
    const offsetY = Math.max(0, (viewport.clientHeight - scaledH) / 2);
    setPan({ x: Math.round(offsetX), y: Math.round(offsetY) });
  }, [layout.height, layout.width]);

  useEffect(() => {
    if (view === "graph") {
      fitGraphView();
      const onResize = () => fitGraphView();
      window.addEventListener("resize", onResize);
      return () => window.removeEventListener("resize", onResize);
    }
  }, [fitGraphView, view]);

  useEffect(() => {
    const el = graphViewportRef.current;
    if (!el || view !== "graph") return;
    const onWheel = (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
      setScale((curr) => Math.min(2.0, Math.max(0.3, Math.round(curr * zoomFactor * 100) / 100)));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [view]);

  const resetView = () => {
    fitGraphView();
  };

  const onPointerDown = (event) => {
    if (event.target.closest("button")) return;
    setDragging(true);
    dragStart.current = { x: event.clientX - pan.x, y: event.clientY - pan.y };
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };

  const onPointerMove = (event) => {
    if (!dragging || !dragStart.current) return;
    setPan({
      x: event.clientX - dragStart.current.x,
      y: event.clientY - dragStart.current.y,
    });
  };

  const selectedNode = nodeMap.get(selectedNodeId);
  const connectedIds = useMemo(() => {
    if (highlightIds.length) return new Set(highlightIds);
    if (!selectedNodeId) return new Set();
    const connected = new Set([selectedNodeId]);
    edges.forEach((edge) => {
      if (edge.source === selectedNodeId) connected.add(edge.target);
      if (edge.target === selectedNodeId) connected.add(edge.source);
    });
    return connected;
  }, [edges, highlightIds, selectedNodeId]);

  const edgeTypes = [...new Set(edges.map((edge) => edge.label || edge.type))];
  const nodeTypes = [...new Set(nodes.map((node) => node.type))];
  const empty = !nodes.length || !edges.length;

  return (
    <div className="dependency-explorer">
      <div className="dependency-explorer-toolbar">
        <div>
          <span className="section-kicker">STATIC RELATIONSHIP MODEL</span>
          <p>Showing the cryptographically relevant dependency subset.</p>
        </div>
        {view === "graph" && !empty ? (
          <div className="dependency-zoom-controls">
            <button type="button" onClick={() => setScale((value) => Math.max(0.35, value - 0.1))} aria-label="Zoom out"><Minus size={13} /></button>
            <span>{Math.round(scale * 100)}%</span>
            <button type="button" onClick={() => setScale((value) => Math.min(1.8, value + 0.1))} aria-label="Zoom in"><Plus size={13} /></button>
            <button type="button" onClick={resetView} aria-label="Reset dependency view"><RotateCcw size={13} /></button>
            <button type="button" className="dependency-fit-button" onClick={fitGraphView} aria-label="Fit dependency view"><Maximize2 size={13} /><span>Fit graph</span></button>
          </div>
        ) : null}
      </div>

      {empty ? (
        <div className="dependency-empty-state">
          No dependency relationships were established from the current scan.
        </div>
      ) : view === "tree" ? (
        <DependencyTree
          nodes={nodes}
          edges={edges}
          selectedNodeId={selectedNodeId}
          onSelect={selectNode}
        />
      ) : (
        <div
          ref={graphViewportRef}
          className={`dependency-graph-canvas ${dragging ? "dragging" : ""}`}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={() => { setDragging(false); dragStart.current = null; }}
          onPointerCancel={() => { setDragging(false); dragStart.current = null; }}
        >
          <svg
            className="dependency-graph-svg"
            viewBox={`0 0 ${layout.width} ${layout.height}`}
            preserveAspectRatio="xMidYMid meet"
            role="img"
            aria-label="Cryptographic dependency graph"
            style={{
              transform: `translate(${pan.x}px, ${pan.y}px) scale(${scale})`,
              transformOrigin: "0 0",
            }}
          >
            <defs>
              <marker id="dependency-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                <path d="M0,0 L8,4 L0,8 z" fill="#536174" />
              </marker>
            </defs>
            {edges.map((edge) => {
              const source = layout.positions.get(edge.source);
              const target = layout.positions.get(edge.target);
              if (!source || !target) return null;
              const focusing = Boolean(selectedNodeId || highlightIds.length);
              const isConnected = !focusing || (connectedIds.has(edge.source) && connectedIds.has(edge.target));
              const midpointX = (source.x + target.x) / 2;
              const midpointY = (source.y + target.y) / 2;
              return (
                <g key={edge.id} className={`dependency-graph-edge ${isConnected ? "" : "dimmed"}`}>
                  <line x1={source.x + 78} y1={source.y + 25} x2={target.x - 78} y2={target.y + 25} markerEnd="url(#dependency-arrow)" />
                  <text x={midpointX} y={midpointY - 5}>{edge.label}</text>
                </g>
              );
            })}
            {nodes.map((node) => {
              const point = layout.positions.get(node.id);
              if (!point) return null;
              const focusing = Boolean(selectedNodeId || highlightIds.length);
              const isConnected = !focusing || connectedIds.has(node.id);
              return (
                <foreignObject key={node.id} x={point.x - 78} y={point.y} width="156" height="66" className={isConnected ? "" : "dimmed"}>
                  <DependencyNode
                    node={node}
                    selected={selectedNodeId === node.id}
                    dimmed={!isConnected}
                    onSelect={selectNode}
                  />
                </foreignObject>
              );
            })}
          </svg>
        </div>
      )}

      <div className="dependency-legend">
        {nodeTypes.map((type) => (
          <span key={type}><i style={{ background: NODE_COLORS[type] || "#526174" }} />{NODE_LABELS[type] || type}</span>
        ))}
        {edgeTypes.map((type) => (
          <span key={type} className="dependency-legend-edge"><i />{type}</span>
        ))}
      </div>

      {selectedNode ? (
        <div className="dependency-selection-note">
          Selected: <strong>{selectedNode.name}</strong>. Connected relationships are highlighted.
        </div>
      ) : null}
      {model.meta?.capped || displayCapped ? (
        <div className="dependency-cap-note">Showing the cryptographically relevant dependency subset; the full static relationship model exceeded the display limit.</div>
      ) : null}
    </div>
  );
}
