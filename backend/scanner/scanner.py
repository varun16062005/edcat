import json
import hashlib
import ssl
from pathlib import Path
from typing import Any, Dict, List, Optional

from .crypto_rules import CRYPTO_RULES
from .dependencies import build_dependency_graph
from .file_detector import detect_file_type


MAX_TEXT_FILE_SIZE = 50 * 1024 * 1024  # 50 MB per individual text file

IGNORED_DIRECTORIES = {
    "node_modules",
}

SCANNABLE_FILE_TYPES = {
    "source/code",
    "configuration",
    "certificate/key",
    "container",
}

NON_TEXT_FILE_TYPES = {
    "archive",
    "library",
    "binary/unknown",
}


def read_text_safely(
    file_path: Path,
) -> Optional[str]:
    try:
        if file_path.stat().st_size > MAX_TEXT_FILE_SIZE:
            return None

        return file_path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except (OSError, UnicodeError):
        return None


def is_probably_text_file(
    file_path: Path,
) -> bool:
    try:
        sample = file_path.read_bytes()[:64 * 1024]
    except OSError:
        return False

    if b"\x00" in sample:
        return False

    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def is_scannable_file(
    file_path: Path,
    file_type: str,
) -> bool:
    if file_type in SCANNABLE_FILE_TYPES:
        return True

    return is_probably_text_file(file_path)


def detect_pem_type(
    content: str,
) -> Optional[str]:
    labels = [
        "BEGIN CERTIFICATE",
        "BEGIN PRIVATE KEY",
        "BEGIN ENCRYPTED PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN DSA PRIVATE KEY",
        "BEGIN PUBLIC KEY",
        "BEGIN RSA PUBLIC KEY",
        "BEGIN OPENSSH PRIVATE KEY",
    ]

    for label in labels:
        if label in content:
            return label

    return None


def inspect_real_crypto_file(
    file_path: Path,
    relative_path: str,
    file_type: str,
) -> List[Dict[str, Any]]:
    """
    Inspect actual certificate/key files without
    exposing private-key contents.
    """

    artifacts = []

    if file_type != "certificate/key":
        return artifacts

    try:
        raw = file_path.read_bytes()

        sample = raw[:2 * 1024 * 1024].decode(
            "latin-1",
            errors="ignore",
        )

    except OSError:
        return artifacts

    pem_type = detect_pem_type(sample)

    if pem_type == "BEGIN CERTIFICATE":
        metadata = {}

        try:
            metadata = ssl._ssl._test_decode_cert(
                str(file_path)
            )
        except Exception:
            metadata = {}

        subject = metadata.get(
            "subject",
            "Unknown subject",
        )

        issuer = metadata.get(
            "issuer",
            "Unknown issuer",
        )

        not_after = metadata.get(
            "notAfter",
            "Unknown expiry",
        )

        usage = (
            "X.509 certificate"
            f" | Subject: {subject}"
            f" | Issuer: {issuer}"
            f" | Expiry: {not_after}"
        )

        artifacts.append(
            {
                "file": relative_path,
                "line": 1,
                "code": "Certificate body hidden",
                "algorithm": "X.509 Certificate",
                "algorithm_family": "PKI",
                "category": "Certificate",
                "usage": usage,
                "quantum_status": "REVIEW",
                "risk": "MEDIUM",
                "recommendation": (
                    "Inventory the certificate's public-key "
                    "algorithm and plan PQC or hybrid "
                    "certificate migration where required."
                ),
            }
        )

        return artifacts

    if pem_type in {
        "BEGIN RSA PRIVATE KEY",
        "BEGIN ENCRYPTED PRIVATE KEY",
    }:
        artifacts.append(
            {
                "file": relative_path,
                "line": 1,
                "code": "Private key material detected; content hidden",
                "algorithm": "RSA Private Key",
                "algorithm_family": "RSA",
                "category": "Private Key",
                "usage": "Private-key material",
                "quantum_status": "VULNERABLE",
                "risk": "CRITICAL",
                "recommendation": (
                    "Protect the key material and plan "
                    "migration to a PQC or hybrid signature "
                    "and key-establishment architecture."
                ),
            }
        )

        return artifacts

    if pem_type == "BEGIN EC PRIVATE KEY":
        artifacts.append(
            {
                "file": relative_path,
                "line": 1,
                "code": "Private key material detected; content hidden",
                "algorithm": "EC Private Key",
                "algorithm_family": "Elliptic Curve",
                "category": "Private Key",
                "usage": "Elliptic-curve private-key material",
                "quantum_status": "VULNERABLE",
                "risk": "CRITICAL",
                "recommendation": (
                    "Plan migration to ML-DSA or a hybrid "
                    "signature architecture."
                ),
            }
        )

        return artifacts

    if pem_type == "BEGIN DSA PRIVATE KEY":
        artifacts.append(
            {
                "file": relative_path,
                "line": 1,
                "code": "Private key material detected; content hidden",
                "algorithm": "DSA Private Key",
                "algorithm_family": "DSA",
                "category": "Private Key",
                "usage": "DSA private-key material",
                "quantum_status": "VULNERABLE",
                "risk": "CRITICAL",
                "recommendation": (
                    "Plan migration toward ML-DSA."
                ),
            }
        )

        return artifacts

    if pem_type == "BEGIN OPENSSH PRIVATE KEY":
        artifacts.append(
            {
                "file": relative_path,
                "line": 1,
                "code": "OpenSSH private-key material detected; content hidden",
                "algorithm": "OpenSSH Private Key",
                "algorithm_family": "SSH",
                "category": "Private Key",
                "usage": "SSH private-key material",
                "quantum_status": "REVIEW",
                "risk": "HIGH",
                "recommendation": (
                    "Identify the underlying SSH public-key "
                    "algorithm and plan an appropriate PQC "
                    "or hybrid migration."
                ),
            }
        )

        return artifacts

    if pem_type in {
        "BEGIN PUBLIC KEY",
        "BEGIN RSA PUBLIC KEY",
    }:
        artifacts.append(
            {
                "file": relative_path,
                "line": 1,
                "code": "Public key detected",
                "algorithm": "Public Key",
                "algorithm_family": "PKI",
                "category": "Public Key",
                "usage": "Public-key material",
                "quantum_status": "REVIEW",
                "risk": "MEDIUM",
                "recommendation": (
                    "Identify the public-key algorithm and "
                    "evaluate PQC or hybrid migration."
                ),
            }
        )

    return artifacts


def find_crypto_artifacts(
    file_path: Path,
    relative_path: str,
) -> List[Dict[str, Any]]:
    artifacts = []

    file_type = detect_file_type(
        file_path
    )

    real_crypto_artifacts = (
        inspect_real_crypto_file(
            file_path=file_path,
            relative_path=relative_path,
            file_type=file_type,
        )
    )

    artifacts.extend(
        real_crypto_artifacts
    )

    if file_type == "archive":
        return artifacts

    content = read_text_safely(
        file_path
    )

    if content is None:
        return artifacts

    lines = content.splitlines()

    for rule in CRYPTO_RULES:
        matched_lines = set()

        for line_number, line in enumerate(
            lines,
            start=1,
        ):
            lower_line = line.lower()

            for pattern in rule[
                "patterns"
            ]:
                if pattern.lower() in lower_line:
                    matched_lines.add(
                        line_number
                    )
                    break

        for line_number in sorted(
            matched_lines
        ):
            source_line = (
                lines[line_number - 1]
                .strip()
            )

            artifact = {
                "file": relative_path,
                "line": line_number,
                "code": source_line[:500],
                "algorithm": rule[
                    "algorithm"
                ],
                "algorithm_family": rule[
                    "family"
                ],
                "category": rule[
                    "category"
                ],
                "usage": rule[
                    "usage"
                ],
                "quantum_status": rule[
                    "quantum_status"
                ],
                "risk": rule[
                    "risk"
                ],
                "recommendation": rule[
                    "recommendation"
                ],
                "content_hash": hashlib.sha256(
                    source_line.encode("utf-8")
                ).hexdigest(),
            }

            duplicate = any(
                existing["file"]
                == artifact["file"]
                and existing["line"]
                == artifact["line"]
                and existing["algorithm"]
                == artifact[
                    "algorithm"
                ]
                for existing in artifacts
            )

            if not duplicate:
                artifacts.append(
                    artifact
                )

    return artifacts


def attach_content_hashes(artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for artifact in artifacts:
        payload = {
            "file": artifact.get("file"),
            "line": artifact.get("line"),
            "algorithm": artifact.get("algorithm"),
            "category": artifact.get("category"),
            "usage": artifact.get("usage"),
            "risk": artifact.get("risk"),
            "quantum_status": artifact.get("quantum_status"),
            "key_size": artifact.get("key_size"),
            "mode": artifact.get("mode"),
            "code": artifact.get("code"),
        }
        artifact["content_hash"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
    return artifacts


def create_summary(
    files: List[Dict[str, Any]],
    artifacts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    critical = sum(
        1
        for item in artifacts
        if item.get("risk")
        == "CRITICAL"
    )

    high = sum(
        1
        for item in artifacts
        if item.get("risk")
        == "HIGH"
    )

    medium = sum(
        1
        for item in artifacts
        if item.get("risk")
        == "MEDIUM"
    )

    low = sum(
        1
        for item in artifacts
        if item.get("risk")
        == "LOW"
    )

    quantum_vulnerable = sum(
        1
        for item in artifacts
        if item.get(
            "quantum_status"
        )
        == "VULNERABLE"
    )

    legacy_weak = sum(
        1
        for item in artifacts
        if item.get(
            "quantum_status"
        )
        == "LEGACY_WEAK"
    )

    if critical > 0:
        posture = {
            "key": "CRITICAL",
            "label": "Highly Critical",
            "description": (
                "Immediate remediation is recommended. "
                "Critical cryptographic findings are present."
            ),
        }
    elif (
        high > 0
        or quantum_vulnerable > 0
    ):
        posture = {
            "key": "HIGH",
            "label": "High Risk",
            "description": (
                "Quantum-vulnerable or high-risk "
                "cryptographic assets require migration planning."
            ),
        }
    elif (
        medium > 0
        or legacy_weak > 0
    ):
        posture = {
            "key": "ELEVATED",
            "label": "Elevated",
            "description": (
                "Weak or legacy cryptography was identified "
                "and should be reviewed."
            ),
        }
    else:
        posture = {
            "key": "NORMAL",
            "label": "Normal",
            "description": (
                "No critical or high-risk cryptographic "
                "findings were identified by the scanner."
            ),
        }

    files_scanned = sum(
        1
        for item in files
        if item.get("scan_status") == "scanned"
    )

    files_skipped = sum(
        1
        for item in files
        if item.get("scan_status") == "skipped"
    )

    return {
        "files_discovered": len(files),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "crypto_assets": len(artifacts),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "quantum_vulnerable": quantum_vulnerable,
        "legacy_weak": legacy_weak,
        "security_posture": posture,
    }


def scan_directory(
    root_directory: Path,
    project_name: str = "",
) -> Dict[str, Any]:
    files = []
    artifacts = []

    for file_path in sorted(root_directory.rglob("*")):
        if not file_path.is_file():
            continue

        try:
            relative_path = file_path.relative_to(root_directory).as_posix()
        except ValueError:
            continue

        if any(
            directory in IGNORED_DIRECTORIES
            for directory in Path(relative_path).parts[:-1]
        ):
            continue

        try:
            file_type = detect_file_type(
                file_path
            )

            size = file_path.stat().st_size

        except OSError:
            continue

        file_record = {
            "name": file_path.name,
            "path": relative_path,
            "type": file_type,
            "size": size,
            "scan_status": "scanned",
            "status": "scanned_text",
        }

        if file_type in NON_TEXT_FILE_TYPES and not is_probably_text_file(file_path):
            file_record["scan_status"] = "skipped"
            file_record["status"] = "binary_file"
            file_record["skip_reason"] = "Binary or non-text file preserved without source analysis"
            files.append(file_record)
            continue

        if size > MAX_TEXT_FILE_SIZE and file_type in {
            "source/code",
            "configuration",
            "container",
            "binary/unknown",
        }:
            file_record["scan_status"] = "skipped"
            file_record["status"] = "unreadable_file"
            file_record["skip_reason"] = "File too large"
            files.append(file_record)
            continue

        if not is_scannable_file(file_path, file_type):
            file_record["scan_status"] = "skipped"
            file_record["status"] = "unreadable_file"
            file_record["skip_reason"] = "File could not be decoded as readable text"
            files.append(file_record)
            continue

        files.append(file_record)

        detected = find_crypto_artifacts(
            file_path=file_path,
            relative_path=relative_path,
        )

        artifacts.extend(
            detected
        )

    attach_content_hashes(artifacts)

    return {
        "summary": create_summary(
            files,
            artifacts,
        ),
        "files": files,
        "artifacts": artifacts,
        "dependencies": build_dependency_graph(
            root_directory=root_directory,
            files=files,
            artifacts=artifacts,
            project_name=project_name,
        ),
    }
