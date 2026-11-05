from pathlib import Path

from scripts.generate_release_manifest import build_manifest


def test_release_manifest_is_stable_and_excludes_secrets(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('safe')\n", encoding="utf-8")
    (tmp_path / "aws.env").write_text("aws_secret_access_key=never-include\n", encoding="utf-8")
    (tmp_path / ".learner-lab-login").write_text("admin=never-include\n", encoding="utf-8")

    first = build_manifest(tmp_path, "test-release")
    second = build_manifest(tmp_path, "test-release")

    assert first["source_tree_sha256"] == second["source_tree_sha256"]
    assert first["file_count"] == 1
    assert [item["path"] for item in first["files"]] == ["src/app.py"]
    assert "never-include" not in str(first)
    assert first["git_metadata_available"] is False
