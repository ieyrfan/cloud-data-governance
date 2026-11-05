"""Create a source-only review archive without local credentials or user documents."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "open-source" / "datasentinel-source-review.zip"
DIRECTORIES = ("src", "frontend", "tests")
EXPLICIT_FILES = (
    ".gitignore",
    "LICENSE",
    "README.md",
    "pyproject.toml",
    "requirements-dev.txt",
    "cloudformation/learner-lab.yml",
    "deployment/lambda-requirements.txt",
    "deployment/LEARNER_LAB.md",
    "docs/DATASENTINEL_DIRECT_MODE_BRIEF_BM_EN.md",
    "scripts/deploy_learner_lab.ps1",
    "scripts/verify_learner_lab.ps1",
    "scripts/generate_release_manifest.py",
    "scripts/backfill_query_indexes.py",
    "scripts/configure_custom_domain.ps1",
    "scripts/export_open_source.py",
)
SOURCE_SUFFIXES = {".py", ".js", ".cjs", ".html", ".css", ".svg", ".json", ".md", ".txt", ".ttf"}
PRIVATE_PARTS = {"__pycache__", ".git", ".venv", "node_modules", ".pytest_cache", ".ruff_cache"}
SECRET_MARKERS = (
    re.compile(rb"AKIA(?!IOSFODNN7EXAMPLE)[A-Z0-9]{16}"),
    re.compile(rb"ASIA[A-Z0-9]{16}"),
    re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(rb"(?im)^\s*(?:aws_secret_access_key|aws_session_token)\s*=\s*(?!\.\.\.\s*$)[^\s#]+"),
)


def source_files() -> list[Path]:
    files = {ROOT / name for name in EXPLICIT_FILES}
    for dirname in DIRECTORIES:
        files.update(
            path for path in (ROOT / dirname).rglob("*")
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
            and not any(part in PRIVATE_PARTS for part in path.relative_to(ROOT).parts)
        )
    for path in files:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError(f"Unsafe or missing source path: {path.relative_to(ROOT)}")
        data = path.read_bytes()
        if any(pattern.search(data) for pattern in SECRET_MARKERS):
            raise ValueError(f"Potential secret in source path: {path.relative_to(ROOT)}")
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def main() -> None:
    files = source_files()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, path.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(OUTPUT) as archive:
        if archive.testzip() is not None:
            raise ValueError("Source archive integrity check failed")
    print(f"Source-only review archive: {OUTPUT}")
    print(f"Files included: {len(files)}")


if __name__ == "__main__":
    main()
