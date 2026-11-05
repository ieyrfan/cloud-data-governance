from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _cloudformation(path: Path) -> dict:
    class CfnLoader(yaml.SafeLoader):
        pass

    def construct_unknown(loader, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    CfnLoader.add_multi_constructor("!", lambda loader, suffix, node: construct_unknown(loader, node))
    return yaml.load(path.read_text(encoding="utf-8"), Loader=CfnLoader)


def test_learner_lab_api_has_bounded_throttling_and_detailed_metrics():
    template = _cloudformation(ROOT / "cloudformation" / "learner-lab.yml")
    settings = template["Resources"]["ApiStage"]["Properties"]["DefaultRouteSettings"]

    assert settings == {
        "DetailedMetricsEnabled": True,
        "ThrottlingBurstLimit": 20,
        "ThrottlingRateLimit": 10,
    }


def test_production_edge_template_has_managed_and_rate_based_protection():
    template = _cloudformation(ROOT / "cloudformation" / "production-edge.yml")
    resources = template["Resources"]
    rules = resources["DataSentinelWebAcl"]["Properties"]["Rules"]

    assert resources["DataSentinelWebAcl"]["Type"] == "AWS::WAFv2::WebACL"
    assert resources["DataSentinelWebAcl"]["Properties"]["Scope"] == "CLOUDFRONT"
    assert resources["EdgeDistribution"]["Type"] == "AWS::CloudFront::Distribution"
    distribution = resources["EdgeDistribution"]["Properties"]["DistributionConfig"]
    assert distribution["WebACLId"] == "DataSentinelWebAcl.Arn"
    assert distribution["DefaultCacheBehavior"]["ViewerProtocolPolicy"] == "redirect-to-https"
    assert resources["NoCachePolicy"]["Properties"]["CachePolicyConfig"]["MaxTTL"] == 0
    assert "ApiWebAclAssociation" not in resources
    assert any("ManagedRuleGroupStatement" in rule["Statement"] for rule in rules)
    assert any("RateBasedStatement" in rule["Statement"] for rule in rules)


def test_readiness_matrix_names_external_controls_without_claiming_they_are_active():
    matrix = (ROOT / "docs" / "PLATFORM_READINESS_MATRIX.md").read_text(encoding="utf-8")

    assert "**Integration-ready**" in matrix
    assert "**Production artifact**" in matrix
    assert "external_anchor_active=false" in matrix
    assert "It is not deployed in Learner Lab" in matrix
    assert "burst of 20" in matrix


def test_disaster_recovery_and_sdk_artifacts_exist():
    assert (ROOT / "deployment" / "DISASTER_RECOVERY_RUNBOOK.md").is_file()
    assert (ROOT / "sdk" / "python" / "datasentinel_client.py").is_file()
    assert (ROOT / "sdk" / "python" / "README.md").is_file()
