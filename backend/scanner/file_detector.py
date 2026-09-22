from pathlib import Path


SOURCE_EXTENSIONS = {
    ".java",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".swift",
    ".kt",
    ".kts",
    ".scala",
    ".cs",
    ".m",
    ".mm",
    ".sh",
    ".bash",
    ".zsh",
    ".sql",
    ".dart",
    ".ex",
    ".exs",
    ".erl",
    ".fs",
    ".fsx",
    ".html",
    ".css",
    ".md",
}

CONFIG_EXTENSIONS = {
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".xml",
    ".env",
    ".cnf",
    ".env",
}

CERTIFICATE_KEY_EXTENSIONS = {
    ".pem",
    ".crt",
    ".cer",
    ".der",
    ".key",
    ".csr",
    ".p12",
    ".pfx",
    ".jks",
    ".p7b",
    ".p7c",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
}

LIBRARY_EXTENSIONS = {
    ".jar",
    ".war",
    ".ear",
    ".aar",
    ".whl",
    ".egg",
}

BINARY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".elf",
    ".app",
    ".out",
    ".o",
    ".a",
}

CONTAINER_NAMES = {
    "dockerfile",
    "containerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
}


def detect_file_type(file_path: Path) -> str:
    """
    Classify a file without assuming that it is
    source code.

    Returns one of:
        source/code
        configuration
        certificate/key
        archive
        container
        library
        binary/unknown
    """

    name = file_path.name.lower()
    suffix = file_path.suffix.lower()

    if name in CONTAINER_NAMES:
        return "container"

    if (
        name.startswith("dockerfile")
        or name.startswith("containerfile")
    ):
        return "container"

    if suffix in SOURCE_EXTENSIONS:
        return "source/code"

    if suffix in CONFIG_EXTENSIONS:
        return "configuration"

    if suffix in CERTIFICATE_KEY_EXTENSIONS:
        return "certificate/key"

    if suffix in ARCHIVE_EXTENSIONS:
        return "archive"

    if suffix in LIBRARY_EXTENSIONS:
        return "library"

    if suffix in BINARY_EXTENSIONS:
        return "binary/unknown"

    return "binary/unknown"
