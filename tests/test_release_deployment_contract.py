from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_lambda_runtime_and_release_identity_are_consistent():
    template = (ROOT / "cloudformation" / "learner-lab.yml").read_text(encoding="utf-8")

    assert template.count("Runtime: python3.12") == 3
    assert "ReleaseId:" in template
    assert template.count("RELEASE_ID: !Ref ReleaseId") == 3
    assert "Value: !Ref ReleaseId" in template


def test_deploy_scripts_build_linux_312_and_write_credentials_after_success():
    powershell = (ROOT / "scripts" / "deploy_learner_lab.ps1").read_text(encoding="utf-8")
    bash = (ROOT / "scripts" / "deploy_learner_lab.sh").read_text(encoding="utf-8")

    for source in (powershell, bash):
        assert "manylinux_2_28_x86_64" in source
        assert "manylinux2014_x86_64" in source
        assert "3.12" in source
        assert "ReleaseId" in source
        assert "backfill_query_indexes.py" in source
        assert "update-event-source-mapping" in source
        assert "get-event-source-mapping" in source

    assert powershell.index("aws cloudformation deploy") < powershell.index(
        "Write-AtomicSecretFile"
    )
    assert bash.index("aws cloudformation deploy") < bash.index("write_atomic()")
    assert ".learner-lab-login" in bash


def test_release_verifier_covers_core_pdf_and_integration_paths():
    source = (ROOT / "scripts" / "verify_release.ps1").read_text(encoding="utf-8")

    assert "verify_learner_lab.ps1" in source
    assert "live_pdf_acceptance.py" in source
    assert "verify_integration_api.py" in source
    assert "passed all three gates" in source


def test_customer_integration_example_is_secret_safe_and_explainable():
    script = Path("scripts/customer_example.py").read_text(encoding="utf-8")
    doc = Path("docs/CUSTOMER_INTEGRATION_EXAMPLE.md").read_text(encoding="utf-8")
    assert "X-API-Key" in doc
    assert "Idempotency-Key" in doc
    assert "never prints the API key" in doc
    assert "900101-14-5678" in script
    assert "print(api_key" not in script
