from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_raw_bucket_allows_api_and_custom_dashboard_origins():
    template = (PROJECT_ROOT / "cloudformation" / "learner-lab.yml").read_text(
        encoding="utf-8"
    )

    assert "DashboardCustomOrigin:" in template
    assert 'Default: "https://datasentinel.ifhx.my"' in template
    assert "HasDashboardCustomOrigin:" in template
    assert "!If [HasDashboardCustomOrigin, !Ref DashboardCustomOrigin" in template
    assert 'https://${GovernanceApi}.execute-api.${AWS::Region}.${AWS::URLSuffix}' in template


def test_deploy_passes_and_validates_custom_dashboard_origin():
    script = (PROJECT_ROOT / "scripts" / "deploy_learner_lab.ps1").read_text(
        encoding="utf-8"
    )

    assert "$DashboardCustomOrigin = 'https://datasentinel.ifhx.my'" in script
    assert "DashboardCustomOrigin must be an HTTPS origin" in script
    assert '"DashboardCustomOrigin=$DashboardCustomOrigin"' in script


def test_upload_ui_replaces_opaque_fetch_failure():
    script = (PROJECT_ROOT / "frontend" / "static" / "app.js").read_text(
        encoding="utf-8"
    )

    assert "The secure storage connection was blocked." in script
    assert "error instanceof TypeError" in script


def test_api_lambda_receives_live_pipeline_resource_names():
    template = (PROJECT_ROOT / "cloudformation" / "learner-lab.yml").read_text(
        encoding="utf-8"
    )

    assert "CLASSIFIER_FUNCTION_NAME: !Ref ClassifierFunction" in template
    assert "CLASSIFICATION_RULE_NAME: !Ref ClassificationRule" in template
    assert "CLASSIFICATION_DLQ_URL: !Ref ClassificationDeadLetterQueue" in template


def test_cloudformation_monitors_api_classifier_and_dead_letter_failures():
    template = (PROJECT_ROOT / "cloudformation" / "learner-lab.yml").read_text(
        encoding="utf-8"
    )

    assert "ApiErrorsAlarm:" in template
    assert "ApiThrottlesAlarm:" in template
    assert "ApiSlowProcessingAlarm:" in template
    assert "ClassifierErrorsAlarm:" in template
    assert "ClassificationDeadLetterAlarm:" in template
    assert "MetricName: ApproximateNumberOfMessagesVisible" in template
    assert template.count("AlarmActions: [!Ref AlertTopic]") == 7
