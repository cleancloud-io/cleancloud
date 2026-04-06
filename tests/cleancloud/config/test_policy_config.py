import pytest

from cleancloud.config.schema import (
    CleanCloudConfig,
    load_config,
)


def test_empty_config_has_defaults():
    cfg = CleanCloudConfig.empty()
    assert cfg.rules == {}
    assert cfg.exceptions == []
    assert cfg.thresholds is None
    assert cfg.tag_filtering is None


def test_rules_enabled_false():
    cfg = load_config({"version": 1, "rules": {"aws.rds.instance.idle": {"enabled": False}}})
    assert cfg.rules["aws.rds.instance.idle"].enabled is False


def test_rules_enabled_true_is_default():
    cfg = load_config({"version": 1, "rules": {"aws.ebs.unattached": {"enabled": True}}})
    assert cfg.rules["aws.ebs.unattached"].enabled is True


def test_rules_min_cost():
    cfg = load_config(
        {"version": 1, "rules": {"aws.rds.instance.idle": {"enabled": True, "min_cost": 100}}}
    )
    assert cfg.rules["aws.rds.instance.idle"].min_cost == 100.0


def test_rules_min_cost_as_int():
    cfg = load_config(
        {"version": 1, "rules": {"aws.ec2.ami.old": {"enabled": True, "min_cost": 5}}}
    )
    assert cfg.rules["aws.ec2.ami.old"].min_cost == 5.0


def test_rules_invalid_min_cost_raises():
    with pytest.raises(ValueError, match="must be a number"):
        load_config({"version": 1, "rules": {"aws.ebs.unattached": {"min_cost": "notanumber"}}})


def test_rules_not_a_mapping_raises():
    with pytest.raises(ValueError):
        load_config({"version": 1, "rules": ["aws.ebs.unattached"]})


def test_exceptions_basic():
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [
                {
                    "rule_id": "aws.ec2.instance.stopped",
                    "resource_id": "i-0abc123",
                    "reason": "bastion",
                }
            ],
        }
    )
    assert len(cfg.exceptions) == 1
    ex = cfg.exceptions[0]
    assert ex.rule_id == "aws.ec2.instance.stopped"
    assert ex.resource_id == "i-0abc123"
    assert ex.reason == "bastion"


def test_exceptions_reason_optional():
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [{"rule_id": "aws.rds.instance.idle", "resource_id": "db-prod"}],
        }
    )
    assert cfg.exceptions[0].reason is None


def test_exceptions_missing_rule_id_raises():
    with pytest.raises(ValueError, match="rule_id"):
        load_config({"version": 1, "exceptions": [{"resource_id": "i-123"}]})


def test_exceptions_missing_resource_id_raises():
    with pytest.raises(ValueError, match="resource_id"):
        load_config({"version": 1, "exceptions": [{"rule_id": "aws.rds.instance.idle"}]})


def test_exceptions_not_a_list_raises():
    with pytest.raises(ValueError):
        load_config(
            {"version": 1, "exceptions": {"rule_id": "aws.rds.instance.idle", "resource_id": "x"}}
        )


def test_thresholds_fail_on_confidence():
    cfg = load_config({"version": 1, "thresholds": {"fail_on_confidence": "HIGH"}})
    assert cfg.thresholds.fail_on_confidence == "HIGH"


def test_thresholds_fail_on_confidence_normalised_to_upper():
    cfg = load_config({"version": 1, "thresholds": {"fail_on_confidence": "high"}})
    assert cfg.thresholds.fail_on_confidence == "HIGH"


def test_thresholds_fail_on_cost():
    cfg = load_config({"version": 1, "thresholds": {"fail_on_cost": 500}})
    assert cfg.thresholds.fail_on_cost == 500.0


def test_thresholds_fail_on_findings_default_false():
    cfg = load_config({"version": 1, "thresholds": {"fail_on_confidence": "HIGH"}})
    assert cfg.thresholds.fail_on_findings is False


def test_thresholds_fail_on_findings_true():
    cfg = load_config({"version": 1, "thresholds": {"fail_on_findings": True}})
    assert cfg.thresholds.fail_on_findings is True


def test_thresholds_invalid_confidence_raises():
    with pytest.raises(ValueError, match="low, medium, or high"):
        load_config({"version": 1, "thresholds": {"fail_on_confidence": "CRITICAL"}})


def test_thresholds_invalid_cost_raises():
    with pytest.raises(ValueError, match="must be a number"):
        load_config({"version": 1, "thresholds": {"fail_on_cost": "lots"}})


def test_all_sections_together():
    cfg = load_config(
        {
            "version": 1,
            "tag_filtering": {"enabled": True, "ignore": [{"key": "env", "value": "prod"}]},
            "rules": {"aws.ec2.ami.old": {"enabled": False}},
            "exceptions": [
                {"rule_id": "aws.rds.instance.idle", "resource_id": "db-prod", "reason": "ok"}
            ],
            "thresholds": {"fail_on_confidence": "MEDIUM", "fail_on_cost": 200},
        }
    )
    assert cfg.tag_filtering.enabled is True
    assert cfg.rules["aws.ec2.ami.old"].enabled is False
    assert cfg.exceptions[0].resource_id == "db-prod"
    assert cfg.thresholds.fail_on_confidence == "MEDIUM"
    assert cfg.thresholds.fail_on_cost == 200.0


def test_unknown_top_level_key_raises():
    with pytest.raises(ValueError, match="Unknown config fields"):
        load_config({"version": 1, "unknown_key": True})
