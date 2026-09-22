import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional
from zipfile import BadZipFile, ZipFile, is_zipfile
import tarfile

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware

from scanner.file_detector import detect_file_type
from scanner.scanner import scan_directory


BASE_DIR = Path(__file__).resolve().parent

UPLOADS_DIR = BASE_DIR / "uploads"
REPORTS_DIR = BASE_DIR / "reports"
MAX_TOTAL_UPLOAD_SIZE = 500 * 1024 * 1024

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
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        *[
            origin.strip()
            for origin in os.getenv("FRONTEND_ORIGINS", "").split(",")
            if origin.strip()
        ],
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
