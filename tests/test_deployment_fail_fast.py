"""Regression coverage for Learner Lab deployment preflight failures."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_learner_lab_deployment_fails_before_build_when_session_is_denied():
    script = (PROJECT_ROOT / "scripts" / "deploy_learner_lab.ps1").read_text(encoding="utf-8")

    access_probe = script.index("aws cloudformation list-stacks")
    package_build = script.index("Building Lambda package")
    assert access_probe < package_build
    assert "deployment access is denied" in script


def test_deployment_checks_every_artifact_bucket_mutation():
    script = (PROJECT_ROOT / "scripts" / "deploy_learner_lab.ps1").read_text(encoding="utf-8")

    assert "artifact bucket could not be created" in script
    assert "public-access block could not be applied" in script
    assert "bucket encryption could not be applied" in script
    assert "deployment artifact could not be uploaded" in script
