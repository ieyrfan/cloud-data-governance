import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_cli(*arguments):
    return subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "cgctl.py"), "--demo", *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_summary_and_posture_scan():
    summary = run_cli("summary")
    assert summary.returncode == 0
    assert "Files: 8" in summary.stdout
    scan = run_cli("scan")
    assert scan.returncode == 0
    assert "PASS: 6/6 checks passed" in scan.stdout


def test_cli_verifies_demo_ledger():
    result = run_cli("audit", "--verify")
    assert result.returncode == 0, result.stderr + result.stdout
    assert "PASS: Verified 3 chained event(s)" in result.stdout
