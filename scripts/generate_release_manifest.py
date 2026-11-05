"""Create a secret-safe, reproducible release identity for DataSentinel."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INCLUDED_PATHS = (
    "cloudformation",
    "deployment",
    "frontend",
    "scripts",
    "sdk",
    "src",
    "tests",
    ".github/workflows",
    "README.md",
    "LICENSE",
    "requirements-dev.txt",
    "pyproject.toml",
)
EXCLUDED_NAMES = {
    ".git",
    ".gstack",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    ".venv",
    "__pycache__",
    "aws",
    "aws.env",
    ".learner-lab-token",
    ".learner-lab-admin-token",
    ".learner-lab-login",
    ".datasentinel-integration-client",
}


def _release_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for relative in INCLUDED_PATHS:
        target = root / relative
        if target.is_file():
            files.append(target)
            continue
        if not target.is_dir():
            continue
        files.extend(
            path
            for path in target.rglob("*")
            if path.is_file() and not any(part in EXCLUDED_NAMES for part in path.parts)
        )
    return sorted(set(files), key=lambda path: path.relative_to(root).as_posix())


def _tree_identity(root: Path) -> tuple[str, list[dict[str, object]]]:
    tree = hashlib.sha256()
    entries: list[dict[str, object]] = []
    for path in _release_files(root):
        relative = path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        size = path.stat().st_size
        entries.append({"path": relative, "sha256": digest, "bytes": size})
        tree.update(relative.encode("utf-8"))
        tree.update(b"\0")
        tree.update(digest.encode("ascii"))
        tree.update(b"\n")
    return tree.hexdigest(), entries


def _git_commit(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        check=False,
        text=True,
    )
    value = result.stdout.strip()
    return value if result.returncode == 0 and len(value) == 40 else None


def build_manifest(root: Path, release: str) -> dict[str, object]:
    tree_sha256, files = _tree_identity(root)
    return {
        "product": "DataSentinel",
        "release": release,
        "generated_at": datetime.now(UTC).isoformat(),
        "source_tree_sha256": tree_sha256,
        "git_commit": _git_commit(root),
        "git_metadata_available": (root / ".git").exists(),
        "file_count": len(files),
        "files": files,
        "security_note": "Credential, token, virtual-environment, cache, and state files are excluded.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", default="datasentinel-booth-2026.10")
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "release-manifest.json",
    )
    args = parser.parse_args()
    manifest = build_manifest(PROJECT_ROOT, args.release)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Release manifest written: {args.output}")
    print(f"Source tree SHA-256: {manifest['source_tree_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
