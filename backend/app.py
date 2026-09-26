import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional
from zipfile import BadZipFile, ZipFile, is_zipfile
import tarfile

from pydantic import BaseModel, Field

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware

from scanner.file_detector import detect_file_type
from scanner.scanner import scan_directory


BASE_DIR = Path(__file__).resolve().parent

UPLOADS_DIR = BASE_DIR / "uploads"
REPORTS_DIR = BASE_DIR / "reports"
MAX_TOTAL_UPLOAD_SIZE = 500 * 1024 * 1024
ALLOWED_ORIGINS = [
    "https://ecdat1.netlify.app",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    *[
        origin.strip().rstrip("/")
        for origin in os.getenv("FRONTEND_ORIGINS", "").split(",")
        if origin.strip()
    ],
]

UPLOADS_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

REPORTS_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


app = FastAPI(
    title="ECDAT API",
    version="0.2.0",
    description=(
        "Cryptographic Discovery, "
        "CBOM Analysis and Quantum Risk Assessment API"
    ),
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def ensure_api_cors_headers(request: Request, call_next):
    origin = request.headers.get("origin", "").rstrip("/")
    is_allowed = (
        origin in ALLOWED_ORIGINS
        or origin.startswith("http://localhost")
        or origin.startswith("http://127.0.0.1")
        or origin.endswith(".netlify.app")
    )

    if request.method == "OPTIONS":
        from fastapi.responses import Response
        resp = Response(status_code=204)
        if is_allowed and origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD"
            resp.headers["Access-Control-Allow-Headers"] = "*"
        return resp

    response = await call_next(request)

    if is_allowed and origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD"
        response.headers["Access-Control-Allow-Headers"] = "*"

    if request.url.path == "/scan":
        response.headers["Cache-Control"] = "no-store"

    return response


def safe_zip_extract(
    archive_path: Path,
    destination: Path,
) -> None:
    with ZipFile(
        archive_path,
        "r",
    ) as archive:
        destination_root = destination.resolve()
        extracted_size = 0

        for member in archive.infolist():
            extracted_size += member.file_size
            if extracted_size > MAX_TOTAL_UPLOAD_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail="Archive contents exceed the ECDAT project size limit of 500 MB.",
                )
            target = (
                destination
                / member.filename
            ).resolve()

            if target != destination_root and destination_root not in target.parents:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Unsafe archive path detected."
                    ),
                )

        archive.extractall(
            destination
        )


def safe_tar_extract(
    archive_path: Path,
    destination: Path,
) -> None:
    destination_root = destination.resolve()
    extracted_size = 0

    with tarfile.open(
        archive_path,
        "r:*",
    ) as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk():
                raise HTTPException(
                    status_code=400,
                    detail="Symbolic links are not allowed in uploaded archives.",
                )
            extracted_size += member.size
            if extracted_size > MAX_TOTAL_UPLOAD_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail="Archive contents exceed the ECDAT project size limit of 500 MB.",
                )
            target = (
                destination
                / member.name
            ).resolve()

            if target != destination_root and destination_root not in target.parents:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Unsafe archive path detected."
                    ),
                )

        archive.extractall(
            destination
        )


async def save_upload_file(
    upload: UploadFile,
    destination: Path,
) -> int:
    total_size = 0

    with destination.open(
        "wb"
    ) as output:
        while True:
            chunk = await upload.read(
                1024 * 1024
            )

            if not chunk:
                break

            total_size += len(chunk)
            output.write(chunk)

    return total_size


def safe_relative_path(
    root: Path,
    relative_path: str,
) -> Path:
    normalized = Path(str(relative_path or "").replace("\\", "/"))
    root_resolved = root.resolve()
    target = (root / normalized).resolve()

    if target != root_resolved and root_resolved not in target.parents:
        raise HTTPException(
            status_code=400,
            detail="Unsafe relative upload path detected.",
        )

    return target


def parse_manifest(value: str) -> List[Dict[str, Any]]:
    try:
        parsed = json.loads(value or "[]")
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "name": "ECDAT API",
        "status": "running",
        "version": "0.2.0",
    }


@app.get("/cors-test")
def cors_test() -> Dict[str, str]:
    return {
        "status": "ok",
    }


@app.get("/health")
def health() -> Dict[str, str]:
    return {
        "status": "healthy",
    }


@app.post("/scan")
async def scan_file(
    files: Optional[List[UploadFile]] = File(default=None),
    file: Optional[UploadFile] = File(default=None),
    relative_paths: Optional[List[str]] = Form(default=None),
    source_type: str = Form(default="file"),
    project_name: str = Form(default=""),
    manifest: str = Form(default="[]"),
) -> Dict[str, Any]:
    uploads = list(files or [])
    if file is not None:
        uploads.append(file)

    manifest_items = parse_manifest(manifest)

    if not uploads and source_type != "folder":
        raise HTTPException(
            status_code=400,
            detail="No files were provided.",
        )

    first_name = Path(
        uploads[0].filename if uploads else project_name or "project"
    ).name

    with TemporaryDirectory(
        prefix="ecdat_scan_"
    ) as temporary_directory:
        temp_root = Path(
            temporary_directory
        )

        scan_root = temp_root / "scan"

        scan_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        total_size = 0
        input_type = "project" if source_type == "folder" else "binary/unknown"

        if len(uploads) == 1 and source_type != "folder":
            uploaded_file = temp_root / first_name
            total_size = await save_upload_file(uploads[0], uploaded_file)

            if total_size > MAX_TOTAL_UPLOAD_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail="Upload exceeds the ECDAT project size limit of 500 MB.",
                )

            if total_size == 0:
                raise HTTPException(
                    status_code=400,
                    detail="The uploaded file is empty.",
                )

            input_type = detect_file_type(uploaded_file)

            try:
                if is_zipfile(uploaded_file):
                    safe_zip_extract(uploaded_file, scan_root)
                    input_type = "archive"
                elif tarfile.is_tarfile(uploaded_file):
                    safe_tar_extract(uploaded_file, scan_root)
                    input_type = "archive"
                else:
                    relative_path = (relative_paths or [first_name])[0]
                    target = safe_relative_path(scan_root, relative_path or first_name)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(uploaded_file.read_bytes())
            except BadZipFile:
                raise HTTPException(
                    status_code=400,
                    detail="The uploaded ZIP file is invalid.",
                )
            except tarfile.TarError:
                raise HTTPException(
                    status_code=400,
                    detail="The uploaded TAR archive is invalid.",
                )
        else:
            for index, upload in enumerate(uploads):
                upload_name = Path(upload.filename or f"file-{index + 1}").name
                paths = relative_paths or []
                relative_path = paths[index] if index < len(paths) else upload_name
                target = safe_relative_path(scan_root, relative_path or upload_name)
                target.parent.mkdir(parents=True, exist_ok=True)
                uploaded_size = await save_upload_file(upload, target)
                total_size += uploaded_size
                if total_size > MAX_TOTAL_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Upload exceeds the ECDAT project size limit of 500 MB.",
                    )

        result = scan_directory(
            scan_root,
            project_name=project_name or first_name,
        )

        existing_paths = {
            item.get("path")
            for item in result.get("files", [])
        }

        for item in manifest_items:
            path = str(item.get("path") or item.get("name") or "")
            if source_type == "archive" and len(uploads) == 1:
                continue
            if not path or path in existing_paths:
                continue

            result["files"].append({
                "name": Path(path).name,
                "path": path,
                "type": "binary/unknown",
                "size": item.get("size", 0),
                "scan_status": "skipped",
                "skip_reason": item.get("client_skip_reason") or "Unsupported or skipped",
            })

        result["summary"]["files_discovered"] = len(result.get("files", []))
        result["summary"]["files_scanned"] = sum(
            1
            for item in result.get("files", [])
            if item.get("scan_status") == "scanned"
        )
        result["summary"]["files_skipped"] = sum(
            1
            for item in result.get("files", [])
            if item.get("scan_status") == "skipped"
        )

        result["input"] = {
            "name": project_name or first_name,
            "type": "project" if source_type in {"folder", "files"} else input_type,
            "source_type": source_type,
            "size": total_size,
            "file_count": len(result.get("files", [])),
        }
        if input_type == "archive":
            result["input"]["scan_status"] = "scanned_archive"

        return result


@app.post("/scan/artifact")
async def scan_artifact(
    file: UploadFile = File(...),
    relative_path: str = Form(default=""),
    project_name: str = Form(default="artifact"),
) -> Dict[str, Any]:
    """Run the normal scanner against one uploaded artifact file."""
    with TemporaryDirectory(prefix="ecdat_artifact_scan_") as temporary_directory:
        scan_root = Path(temporary_directory) / "scan"
        scan_root.mkdir(parents=True, exist_ok=True)
        safe_path = safe_relative_path(
            scan_root,
            relative_path or Path(file.filename or "artifact").name,
        )
        safe_path.parent.mkdir(parents=True, exist_ok=True)
        await save_upload_file(file, safe_path)
        result = scan_directory(scan_root, project_name=project_name)
        return {
            "artifacts": result.get("artifacts", []),
            "files": result.get("files", []),
            "summary": result.get("summary", {}),
            "input": result.get("input", {}),
        }


class AssistantQuery(BaseModel):
    question: str = ""
    context: Dict[str, Any] = Field(default_factory=dict)


def _sanitize_advisor_context(context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    source = context if isinstance(context, dict) else {}
    artifacts = []
    for artifact in source.get("artifacts") or []:
        if not isinstance(artifact, dict):
            continue
        artifacts.append({
            "file": artifact.get("file"),
            "line": artifact.get("line"),
            "algorithm": artifact.get("algorithm"),
            "category": artifact.get("category"),
            "risk": artifact.get("risk"),
            "quantum_status": artifact.get("quantum_status"),
            "recommendation": artifact.get("recommendation"),
            "content_hash": artifact.get("content_hash"),
        })
    return {
        "project": source.get("project") or {},
        "summary": source.get("summary") or {},
        "files": source.get("files") or [],
        "artifacts": artifacts[:120],
        "cbom": source.get("cbom") or {},
        "dependencies": source.get("dependencies") or {},
        "scenarioRisk": source.get("scenarioRisk") or {},
        "migration": source.get("migration") or [],
        "changes": source.get("changes") or {},
    }


def answer_advisor_question(question: str, context: Dict[str, Any]) -> Dict[str, Any]:
    topic = (question or "").lower()
    artifacts = context.get("artifacts") or []
    summary = context.get("summary") or {}
    files = context.get("files") or []
    changes = context.get("changes") or {}
    migration = context.get("migration") or []
    dependencies = context.get("dependencies") or {}
    cbom = context.get("cbom") or {}

    if "how many" in topic and ("asset" in topic or "discover" in topic):
        count = summary.get("crypto_assets") or len(artifacts)
        return {
            "answer": f"The current scan contains {count} cryptographic assets.",
            "sources": ["summary.crypto_assets"],
        }

    if "quantum" in topic and "vulnerable" in topic:
        vulnerable = [
            item for item in artifacts
            if str(item.get("quantum_status") or "").upper() == "VULNERABLE"
        ]
        algorithms = sorted({item.get("algorithm") or "Unknown" for item in vulnerable})
        if not vulnerable:
            return {
                "answer": "No artifacts in this scan are marked quantum_status=VULNERABLE.",
                "sources": ["artifacts.quantum_status"],
            }
        return {
            "answer": (
                f"{len(vulnerable)} artifacts are quantum vulnerable. "
                f"Algorithms: {', '.join(algorithms)}."
            ),
            "sources": ["artifacts.quantum_status"],
        }

    if "rsa" in topic:
        rsa = [
            item for item in artifacts
            if "RSA" in str(item.get("algorithm") or "").upper()
        ]
        files_with_rsa = sorted({item.get("file") or "Unknown file" for item in rsa})
        if not rsa:
            return {
                "answer": "This scan does not contain RSA findings.",
                "sources": ["artifacts.algorithm"],
            }
        return {
            "answer": f"{len(rsa)} RSA findings appear in: {', '.join(files_with_rsa[:12])}.",
            "sources": ["artifacts.algorithm"],
        }

    if "highest" in topic or "priority" in topic or "migrate first" in topic:
        ranked = sorted(
            artifacts,
            key=lambda item: (
                0 if item.get("risk") == "CRITICAL" else
                1 if item.get("risk") == "HIGH" else 2
            ),
        )
        if not ranked:
            return {
                "answer": "No artifacts are available to prioritize.",
                "sources": ["artifacts.risk"],
            }
        first = ranked[0]
        line = f":{first['line']}" if first.get("line") else ""
        return {
            "answer": (
                f"Highest-priority finding: {first.get('algorithm') or 'artifact'} in "
                f"{first.get('file') or 'unknown file'}{line} "
                f"with risk {first.get('risk') or 'unspecified'}."
            ),
            "sources": ["artifacts.risk"],
        }

    if "pqc" in topic or "alternative" in topic:
        if not migration:
            return {
                "answer": "PQC alternatives are unavailable in the current scan context.",
                "sources": ["migration"],
            }
        preview = "; ".join(
            f"{item.get('algorithm') or 'artifact'} → {item.get('alternative') or 'not specified'}"
            for item in migration[:8]
            if isinstance(item, dict)
        )
        return {
            "answer": f"Recommended replacements from scan evidence: {preview}.",
            "sources": ["migration"],
        }

    if "cbom" in topic:
        return {
            "answer": (
                f"CBOM summary: {cbom.get('components') or 0} components"
                f"{' using ' + str(cbom.get('spec')) if cbom.get('spec') else ''}."
            ),
            "sources": ["cbom"],
        }

    if "changed" in topic or "previous scan" in topic:
        if not changes:
            return {
                "answer": "Change detection data is unavailable for this scan.",
                "sources": ["changes"],
            }
        return {
            "answer": (
                "Since the previous local scan: "
                f"{changes.get('unchanged', 0)} unchanged, "
                f"{changes.get('changed', 0)} changed, "
                f"{changes.get('new', 0)} new, "
                f"{changes.get('removed', 0)} removed."
            ),
            "sources": ["changes"],
        }

    if "reach" in topic or "blast" in topic or "dependenc" in topic:
        return {
            "answer": (
                "Dependency evidence contains "
                f"{dependencies.get('nodes') or 0} nodes and "
                f"{dependencies.get('edges') or 0} edges. "
                "Open Blast Radius to compute reach for a selected artifact. "
                "Largest individual reach is not precomputed in this context."
            ),
            "sources": ["dependencies"],
        }

    count = summary.get("crypto_assets") or len(artifacts)
    file_count = summary.get("files_scanned") or len(files)
    return {
        "answer": (
            f"The current scan covers {file_count} files and {count} cryptographic assets. "
            "That fact is available. Ask about RSA files, quantum-vulnerable algorithms, "
            "CBOM, migration, or change detection for a more specific grounded answer."
        ),
        "sources": ["summary"],
    }


@app.post("/assistant/query")
async def assistant_query(payload: AssistantQuery) -> Dict[str, Any]:
    question = payload.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="A question is required.")
    context = _sanitize_advisor_context(payload.context)
    return answer_advisor_question(question, context)
