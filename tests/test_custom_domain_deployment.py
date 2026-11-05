from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_custom_domain_script_enforces_safe_idempotent_contract():
    script = (PROJECT_ROOT / "scripts" / "configure_custom_domain.ps1").read_text(encoding="utf-8")

    assert "Certificate.Status -ne 'ISSUED'" in script
    assert "Certificate does not cover $DomainName" in script
    assert "get-api-mappings" in script
    assert "update-api-mapping" in script
    assert "'UPSERT'" in script
    assert "resource-record-sets-changed" in script
    assert '--resolve "$DomainName`:443`:$TargetIp"' in script
    assert "--fail" in script
    assert "-SkipCertificateCheck" not in script
    assert "--insecure" not in script


def test_deploy_requires_complete_custom_domain_configuration():
    script = (PROJECT_ROOT / "scripts" / "deploy_learner_lab.ps1").read_text(encoding="utf-8")

    assert "$ConfiguredCustomDomainValues.Count -gt 0" in script
    assert "$ConfiguredCustomDomainValues.Count -ne 3" in script
    assert "configure_custom_domain.ps1" in script
    assert "-DomainName $CustomDomainName" in script
    assert "-HostedZoneId $HostedZoneId" in script
    assert "-CertificateArn $CertificateArn" in script
