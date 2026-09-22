"""Conservative, static dependency extraction for scan results.

This module intentionally only reads text and never imports, executes, or
resolves packages through a runtime. The output is designed for the dashboard
dependency views, not as a replacement for a language-native build graph.
"""

from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


MAX_DEPENDENCY_NODES = 180
MAX_DEPENDENCY_EDGES = 320

SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".cs", ".go", ".h", ".hpp",
    ".java", ".js", ".jsx", ".kt", ".kts", ".m", ".mm", ".php",
    ".py", ".rb", ".rs", ".scala", ".swift", ".ts", ".tsx",
}

IMPORT_PATTERNS = (
    re.compile(r"^\s*import\s+([A-Za-z_][\w.]*)(?:\s|$)", re.MULTILINE),
    re.compile(r"^\s*from\s+([.A-Za-z_][\w.]*)\s+import\s+", re.MULTILINE),
    re.compile(r"\bimport\s+(?:[^\"']+?\s+from\s+)?[\"']([^\"']+)[\"']"),
    re.compile(r"\brequire\s*\(\s*[\"']([^\"']+)[\"']\s*\)"),
    re.compile(r"^\s*#include\s*[<\"]([^>\"]+)[>\"]", re.MULTILINE),
    re.compile(r"^\s*using\s+([A-Za-z_][\w.]*)\s*;", re.MULTILINE),
    re.compile(r"^\s*use\s+([A-Za-z_][\w:]*)", re.MULTILINE),
    re.compile(r"^\s*(?:require|require_relative|include)\s*[\(\s]*[\"']([^\"']+)[\"']", re.MULTILINE),
    re.compile(r"^\s*(?:import|use)\s+([A-Za-z_][\w\\.]*)", re.MULTILINE),
)


def read_text(file_path: Path) -> Optional[str]:
    try:
        if file_path.stat().st_size > 10 * 1024 * 1024:
            return None
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeError):
        return None


def _dedupe(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def extract_references(relative_path: str, content: str) -> List[str]:
    """Return import/reference strings using language-neutral patterns."""

    suffix = Path(relative_path).suffix.lower()
    if suffix not in SOURCE_EXTENSIONS and Path(relative_path).name.lower() not in {
        "dockerfile",
        "containerfile",
    }:
        return []

    references: List[str] = []
    for pattern in IMPORT_PATTERNS:
        references.extend(pattern.findall(content))

    if suffix == ".go":
        for block in re.findall(r"\bimport\s*\((.*?)\)", content, re.DOTALL):
            references.extend(re.findall(r"[\"']([^\"']+)[\"']", block))

    # A Python ``import a, b`` statement is captured as one value by the
    # simple pattern above. Split only comma-separated module names.
    expanded: List[str] = []
    for reference in references:
        expanded.extend(part.strip() for part in reference.split(","))

    return _dedupe(expanded)


def _candidate_paths(source_path: str, reference: str) -> List[str]:
    source = Path(source_path)
    raw = reference.replace("\\", "/").strip()
    candidates: List[str] = []

    if raw.startswith(".") or raw.startswith("/"):
        base = (source.parent / raw).as_posix() if raw.startswith(".") else raw.lstrip("/")
        candidates.append(base)
    else:
        module_path = raw.replace(".", "/").replace("\\", "/")
        candidates.append(module_path)

    suffix = source.suffix.lower()
    extensions = [suffix, ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".cs", ".php", ".rb", ".swift"]
    for candidate in list(candidates):
        path = Path(candidate)
        if path.suffix:
            continue
        for extension in extensions:
            candidates.append(f"{candidate}{extension}")
        for extension in extensions:
            candidates.append(f"{candidate}/index{extension}")
            candidates.append(f"{candidate}/__init__{extension}")

    return _dedupe(candidates)


def resolve_local_reference(
    source_path: str,
    reference: str,
    known_paths: Set[str],
) -> Optional[str]:
    candidates = _candidate_paths(source_path, reference)
    normalized_known = {path.replace("\\", "/") for path in known_paths}

    if reference.startswith(("crate::", "self::", "super::")):
        rust_path = reference.split("::", 1)[1].replace("::", "/")
        candidates.extend(_candidate_paths(source_path, f"./{rust_path}"))

    for candidate in candidates:
        normalized = Path(candidate).as_posix().lstrip("./")
        if normalized in normalized_known:
            return normalized

    # Java/Kotlin and package-style imports may have a project prefix. Match
    # only an exact suffix to avoid claiming arbitrary external packages.
    if not reference.startswith((".", "/")):
        module_path = reference.replace(".", "/").replace("\\", "/")
        suffix_matches = sorted(
            path for path in normalized_known
            if path == module_path or path.endswith(f"/{module_path}")
            or path.startswith(f"{module_path}.")
        )
        if suffix_matches:
            return suffix_matches[0]

    return None


def _external_name(reference: str) -> str:
    value = reference.strip().replace("\\", "/")
    if value.startswith((".", "/")):
        return value
    if value.startswith("@"):
        parts = value.split("/")
        return "/".join(parts[:2]) if len(parts) > 1 else value
    return value.split("/")[0].split(".")[0]


def build_dependency_graph(
    root_directory: Path,
    files: List[Dict[str, Any]],
    artifacts: List[Dict[str, Any]],
    project_name: str = "",
) -> Dict[str, Any]:
    scanned_files = [
        item for item in files
        if item.get("scan_status") == "scanned"
    ]
    known_paths = {str(item.get("path") or "") for item in scanned_files}
    contents: Dict[str, str] = {}
    references: Dict[str, List[str]] = {}

    for item in scanned_files:
        relative_path = str(item.get("path") or "")
        if not relative_path:
            continue
        content = read_text(root_directory / relative_path)
        if content is None:
            continue
        contents[relative_path] = content
        references[relative_path] = extract_references(relative_path, content)

    local_edges: List[Tuple[str, str]] = []
    external_edges: List[Tuple[str, str]] = []
    for source_path, refs in references.items():
        for reference in refs:
            local_target = resolve_local_reference(source_path, reference, known_paths)
            if local_target and local_target != source_path:
                local_edges.append((source_path, local_target))
            elif not reference.startswith((".", "/", "crate::", "self::", "super::")):
                external_edges.append((source_path, _external_name(reference)))

    crypto_files = {
        str(artifact.get("file") or "")
        for artifact in artifacts
        if artifact.get("file")
    }
    focused_files = set(path for path in crypto_files if path in known_paths)

    # Include direct local dependencies of crypto-bearing files and the files
    # that directly import them. This keeps the graph useful without showing a
    # full project graph for large repositories.
    for source_path, target_path in local_edges:
        if source_path in crypto_files or target_path in crypto_files:
            focused_files.update((source_path, target_path))

    changed = True
    while changed:
        changed = False
        for source_path, target_path in local_edges:
            if target_path in focused_files and source_path not in focused_files:
                focused_files.add(source_path)
                changed = True

    if not focused_files:
        return {
            "nodes": [],
            "edges": [],
            "meta": {
                "capped": False,
                "total_nodes": 0,
                "total_edges": 0,
                "message": "No dependency relationships were established from the current scan.",
            },
        }

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    node_ids: Set[str] = set()
    edge_keys: Set[Tuple[str, str, str]] = set()

    def add_node(node: Dict[str, Any]) -> None:
        if node["id"] not in node_ids:
            node_ids.add(node["id"])
            nodes.append(node)

    def add_edge(source: str, target: str, edge_type: str, label: str) -> None:
        key = (source, target, edge_type)
        if key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({
            "id": f"{source}->{target}:{edge_type}",
            "source": source,
            "target": target,
            "type": edge_type,
            "label": label,
        })

    project_id = "project:root"
    add_node({
        "id": project_id,
        "type": "project",
        "name": project_name or root_directory.name or "Scanned project",
    })

    for relative_path in sorted(focused_files):
        item = next((file for file in scanned_files if file.get("path") == relative_path), {})
        file_id = f"file:{relative_path}"
        add_node({
            "id": file_id,
            "type": "file",
            "name": item.get("name") or Path(relative_path).name,
            "path": relative_path,
            "fileType": item.get("type") or "source/code",
        })
        add_edge(project_id, file_id, "contains", "contains")

    for source_path, target_path in local_edges:
        if source_path in focused_files and target_path in focused_files:
            add_edge(
                f"file:{source_path}",
                f"file:{target_path}",
                "imports",
                "imports",
            )

    crypto_file_set = set(crypto_files)
    for source_path, external_name in external_edges:
        if source_path not in crypto_file_set or not external_name:
            continue
        external_id = f"external:{external_name}"
        add_node({
            "id": external_id,
            "type": "external",
            "name": external_name,
            "dependencyType": "external",
        })
        add_edge(
            f"file:{source_path}",
            external_id,
            "imports",
            "uses package",
        )

    for index, artifact in enumerate(artifacts):
        relative_path = str(artifact.get("file") or "")
        if relative_path not in focused_files:
            continue
        artifact_id = f"artifact:{index}"
        add_node({
            "id": artifact_id,
            "type": "artifact",
            "name": artifact.get("algorithm") or artifact.get("category") or f"Artifact {index + 1}",
            "path": relative_path,
            "artifactIndex": index,
            "risk": artifact.get("risk"),
            "quantumStatus": artifact.get("quantum_status"),
        })
        add_edge(
            f"file:{relative_path}",
            artifact_id,
            "uses",
            "uses crypto",
        )

    total_nodes = len(nodes)
    total_edges = len(edges)
    capped = total_nodes > MAX_DEPENDENCY_NODES or total_edges > MAX_DEPENDENCY_EDGES
    if capped:
        allowed_ids = {node["id"] for node in nodes[:MAX_DEPENDENCY_NODES]}
        nodes = nodes[:MAX_DEPENDENCY_NODES]
        edges = [
            edge for edge in edges[:MAX_DEPENDENCY_EDGES]
            if edge["source"] in allowed_ids and edge["target"] in allowed_ids
        ]

    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "capped": capped,
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "message": "Showing the cryptographically relevant dependency subset.",
        },
    }
