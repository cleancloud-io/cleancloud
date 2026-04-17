import functools
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from cleancloud.config.schema import CleanCloudConfig, load_config
from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.filtering.rules import (
    apply_exceptions,
    apply_policy_filters,
    apply_rule_config,
)

_EVIDENCE = Evidence(signals_used=["test"], signals_not_checked=[])


def _make_rule(name="rule_fn"):
    fn = MagicMock()
    fn.__name__ = name
    return fn


def _make_finding(
    rule_id="aws.rds.instance.idle",
    resource_id="db-prod",
    cost=None,
    confidence=ConfidenceLevel.MEDIUM,
):
    return Finding(
        provider="aws",
        rule_id=rule_id,
        resource_type="rds-instance",
        resource_id=resource_id,
        region="us-east-1",
        title="Test finding",
        summary="Test summary",
        reason="Test reason",
        risk=RiskLevel.LOW,
        confidence=confidence,
        detected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        details={},
        evidence=_EVIDENCE,
        estimated_monthly_cost_usd=cost,
    )


# ── apply_rule_config ────────────────────────────────────────────────────────


def test_all_rules_active_when_no_config():
    r1, r2 = _make_rule(), _make_rule()
    rule_map = {"aws.ebs.unattached": r1, "aws.rds.instance.idle": r2}
    cfg = CleanCloudConfig.empty()
    active, skipped = apply_rule_config([r1, r2], rule_map, cfg)
    assert active == [r1, r2]
    assert skipped == []


def test_disabled_rule_removed():
    r1, r2 = _make_rule(), _make_rule()
    rule_map = {"aws.ebs.unattached": r1, "aws.rds.instance.idle": r2}
    cfg = load_config({"version": 1, "rules": {"aws.rds.instance.idle": {"enabled": False}}})
    active, skipped = apply_rule_config([r1, r2], rule_map, cfg)
    assert active == [r1]
    assert "aws.rds.instance.idle" in skipped


def test_skip_flag_removes_rule():
    r1, r2 = _make_rule(), _make_rule()
    rule_map = {"aws.ebs.unattached": r1, "aws.rds.instance.idle": r2}
    cfg = CleanCloudConfig.empty()
    active, skipped = apply_rule_config([r1, r2], rule_map, cfg, skip_ids=["aws.ebs.unattached"])
    assert active == [r2]
    assert "aws.ebs.unattached" in skipped


def test_skip_flag_takes_precedence_over_enabled_true():
    r1 = _make_rule()
    rule_map = {"aws.ebs.unattached": r1}
    cfg = load_config({"version": 1, "rules": {"aws.ebs.unattached": {"enabled": True}}})
    active, skipped = apply_rule_config([r1], rule_map, cfg, skip_ids=["aws.ebs.unattached"])
    assert active == []
    assert "aws.ebs.unattached" in skipped


def test_rule_not_in_map_always_included():
    r1 = _make_rule()
    rule_map = {}  # not registered
    cfg = load_config({"version": 1, "rules": {}})
    active, skipped = apply_rule_config([r1], rule_map, cfg)
    assert active == [r1]
    assert skipped == []


def test_multiple_rules_skipped():
    r1, r2, r3 = _make_rule(), _make_rule(), _make_rule()
    rule_map = {"rule.a": r1, "rule.b": r2, "rule.c": r3}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"rule.a": {"enabled": False}, "rule.c": {"enabled": False}},
        }
    )
    active, skipped = apply_rule_config([r1, r2, r3], rule_map, cfg)
    assert active == [r2]
    assert set(skipped) == {"rule.a", "rule.c"}


# ── apply_exceptions ─────────────────────────────────────────────────────────


def test_no_exceptions_returns_all_findings():
    f1, f2 = _make_finding(), _make_finding(resource_id="db-staging")
    cfg = CleanCloudConfig.empty()
    kept, suppressed_list, expired_events = apply_exceptions([f1, f2], cfg)
    assert kept == [f1, f2]
    assert len(suppressed_list) == 0


def test_exception_suppresses_matching_finding():
    f1 = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-prod")
    f2 = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-staging")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [{"rule_id": "aws.rds.instance.idle", "resource_id": "db-prod"}],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f1, f2], cfg)
    assert kept == [f2]
    assert len(suppressed_list) == 1


def test_exception_requires_both_rule_id_and_resource_id_match():
    f1 = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-prod")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [{"rule_id": "aws.ec2.instance.stopped", "resource_id": "db-prod"}],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f1], cfg)
    assert kept == [f1]
    assert len(suppressed_list) == 0


def test_min_cost_suppresses_below_threshold():
    f_cheap = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-dev", cost=40.0)
    f_expensive = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-prod", cost=400.0)
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"enabled": True, "min_cost": 100}},
        }
    )
    kept, suppressed_list = apply_policy_filters([f_cheap, f_expensive], cfg)
    assert kept == [f_expensive]
    assert len(suppressed_list) == 1


def test_min_cost_finding_with_no_cost_not_suppressed():
    f = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-dev", cost=None)
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"enabled": True, "min_cost": 100}},
        }
    )
    kept, suppressed_list = apply_policy_filters([f], cfg)
    assert kept == [f]
    assert len(suppressed_list) == 0


def test_multiple_exceptions_all_suppressed():
    findings = [
        _make_finding(rule_id="aws.ec2.instance.stopped", resource_id="i-bastion"),
        _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-reporting"),
        _make_finding(rule_id="aws.ebs.unattached", resource_id="vol-999"),
    ]
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [
                {"rule_id": "aws.ec2.instance.stopped", "resource_id": "i-bastion"},
                {"rule_id": "aws.rds.instance.idle", "resource_id": "db-reporting"},
            ],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions(findings, cfg)
    assert len(kept) == 1
    assert kept[0].resource_id == "vol-999"
    assert len(suppressed_list) == 2


# ── params / functools.partial ────────────────────────────────────────────────


def test_params_bound_to_rule_via_partial():
    r1 = _make_rule()
    rule_map = {"aws.rds.instance.idle": r1}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"params": {"idle_days": 21}}},
        }
    )
    active, skipped = apply_rule_config([r1], rule_map, cfg)
    assert len(active) == 1
    assert skipped == []
    # Active rule should be a partial with idle_days=21 bound
    assert isinstance(active[0], functools.partial)
    assert active[0].keywords == {"idle_days": 21}
    assert active[0].func is r1


def test_no_params_returns_original_function():
    r1 = _make_rule()
    rule_map = {"aws.rds.instance.idle": r1}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"enabled": True}},
        }
    )
    active, skipped = apply_rule_config([r1], rule_map, cfg)
    assert active == [r1]  # not wrapped in partial


# ── confidence filter ─────────────────────────────────────────────────────────


def test_confidence_filter_suppresses_low_finding_when_medium_required():
    f = _make_finding(confidence=ConfidenceLevel.LOW)
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"confidence": "MEDIUM"}},
        }
    )
    kept, suppressed_list = apply_policy_filters([f], cfg)
    assert kept == []
    assert len(suppressed_list) == 1


def test_confidence_filter_keeps_medium_when_medium_required():
    f = _make_finding(confidence=ConfidenceLevel.MEDIUM)
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"confidence": "MEDIUM"}},
        }
    )
    kept, suppressed_list = apply_policy_filters([f], cfg)
    assert kept == [f]
    assert len(suppressed_list) == 0


def test_confidence_filter_keeps_high_when_medium_required():
    f = _make_finding(confidence=ConfidenceLevel.HIGH)
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"confidence": "MEDIUM"}},
        }
    )
    kept, suppressed_list = apply_policy_filters([f], cfg)
    assert kept == [f]
    assert len(suppressed_list) == 0


# ── override_risk_level ───────────────────────────────────────────────────────


def test_override_risk_level_changes_risk_on_finding():
    f = _make_finding()
    assert f.risk == RiskLevel.LOW
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"override_risk_level": "HIGH"}},
        }
    )
    kept, suppressed_list = apply_policy_filters([f], cfg)
    assert len(kept) == 1
    assert len(suppressed_list) == 0
    # override_risk_level uses dataclasses.replace() — original is unchanged, kept has new risk
    assert f.risk == RiskLevel.LOW  # original untouched
    assert kept[0].risk == RiskLevel.HIGH  # override applied to the returned copy


# ── defaults merging ──────────────────────────────────────────────────────────


def test_defaults_min_cost_applied_when_no_per_rule_config():
    f_cheap = _make_finding(rule_id="aws.ebs.unattached", resource_id="vol-1", cost=5.0)
    f_expensive = _make_finding(rule_id="aws.ebs.unattached", resource_id="vol-2", cost=50.0)
    cfg = load_config(
        {
            "version": 1,
            "defaults": {"min_cost": 10},
        }
    )
    kept, suppressed_list = apply_policy_filters([f_cheap, f_expensive], cfg)
    assert kept == [f_expensive]
    assert len(suppressed_list) == 1


def test_per_rule_min_cost_overrides_defaults():
    f = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-dev", cost=50.0)
    cfg = load_config(
        {
            "version": 1,
            "defaults": {"min_cost": 10},
            "rules": {"aws.rds.instance.idle": {"min_cost": 100}},
        }
    )
    kept, suppressed_list = apply_policy_filters([f], cfg)
    # 50 < 100 (per-rule wins over default 10)
    assert kept == []
    assert len(suppressed_list) == 1


def test_defaults_confidence_applied_globally():
    f_low = _make_finding(rule_id="aws.ebs.unattached", confidence=ConfidenceLevel.LOW)
    f_med = _make_finding(rule_id="aws.ebs.unattached", confidence=ConfidenceLevel.MEDIUM)
    cfg = load_config(
        {
            "version": 1,
            "defaults": {"confidence": "MEDIUM"},
        }
    )
    kept, suppressed_list = apply_policy_filters([f_low, f_med], cfg)
    assert kept == [f_med]
    assert len(suppressed_list) == 1


def test_per_rule_confidence_overrides_defaults():
    # Rule sets LOW — should include LOW findings even if default is MEDIUM
    f_low = _make_finding(rule_id="aws.rds.instance.idle", confidence=ConfidenceLevel.LOW)
    cfg = load_config(
        {
            "version": 1,
            "defaults": {"confidence": "MEDIUM"},
            "rules": {"aws.rds.instance.idle": {"confidence": "LOW"}},
        }
    )
    kept, suppressed_list = apply_policy_filters([f_low], cfg)
    assert kept == [f_low]
    assert len(suppressed_list) == 0


# ── params validation ─────────────────────────────────────────────────────────


def _make_real_rule():
    """A real function with typed signature so _get_configurable_params can introspect it."""

    def find_idle(*, session, region_filter=None, idle_days: int = 14):
        pass

    return find_idle


def test_unknown_param_raises_with_helpful_message():
    rule = _make_real_rule()
    rule_map = {"aws.rds.instance.idle": rule}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"params": {"idel_days": 21}}},  # typo
        }
    )
    with pytest.raises(ValueError, match="idel_days"):
        apply_rule_config([rule], rule_map, cfg)


def test_unknown_param_suggests_correction():
    rule = _make_real_rule()
    rule_map = {"aws.rds.instance.idle": rule}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"params": {"idel_days": 21}}},
        }
    )
    with pytest.raises(ValueError, match="idle_days"):
        apply_rule_config([rule], rule_map, cfg)


def test_wrong_type_param_raises():
    rule = _make_real_rule()
    rule_map = {"aws.rds.instance.idle": rule}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"params": {"idle_days": "three-weeks"}}},
        }
    )
    with pytest.raises(ValueError, match="expected int"):
        apply_rule_config([rule], rule_map, cfg)


def test_valid_params_do_not_raise():
    rule = _make_real_rule()
    rule_map = {"aws.rds.instance.idle": rule}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"params": {"idle_days": 21}}},
        }
    )
    active, _ = apply_rule_config([rule], rule_map, cfg)
    assert len(active) == 1


def test_mock_rule_skips_param_validation():
    # MagicMock can't be introspected — validation is silently skipped, no crash
    r1 = _make_rule()
    rule_map = {"aws.rds.instance.idle": r1}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instance.idle": {"params": {"completely_unknown_key": 99}}},
        }
    )
    active, _ = apply_rule_config([r1], rule_map, cfg)
    assert len(active) == 1  # no crash — mock introspection falls back gracefully


# ── tag filtering mode ────────────────────────────────────────────────────────


def test_tag_filtering_mode_defaults_to_exclude():
    cfg = load_config(
        {
            "version": 1,
            "tag_filtering": {"enabled": True, "ignore": [{"key": "env"}]},
        }
    )
    assert cfg.tag_filtering.mode == "exclude"


def test_tag_filtering_mode_explicit_exclude():
    cfg = load_config(
        {
            "version": 1,
            "tag_filtering": {"enabled": True, "mode": "exclude", "ignore": []},
        }
    )
    assert cfg.tag_filtering.mode == "exclude"


def test_tag_filtering_unsupported_mode_raises():
    with pytest.raises(ValueError, match="not supported"):
        load_config(
            {
                "version": 1,
                "tag_filtering": {"enabled": True, "mode": "include", "ignore": []},
            }
        )


# ── rule ID validation ────────────────────────────────────────────────────────


def test_unknown_rule_id_for_current_provider_raises():
    r1 = _make_rule()
    rule_map = {"aws.rds.instance.idle": r1, "aws.ebs.unattached": r1}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instnace.idle": {"enabled": False}},  # typo
        }
    )
    with pytest.raises(ValueError, match="aws.rds.instnace.idle"):
        apply_rule_config([r1], rule_map, cfg)


def test_unknown_rule_id_suggests_close_match():
    r1 = _make_rule()
    rule_map = {"aws.rds.instance.idle": r1}
    cfg = load_config(
        {
            "version": 1,
            "rules": {"aws.rds.instnace.idle": {"enabled": False}},
        }
    )
    with pytest.raises(ValueError, match="aws.rds.instance.idle"):
        apply_rule_config([r1], rule_map, cfg)


def test_cross_provider_rule_id_ignored():
    # azure.* rule in an AWS scan — not a typo, just a different provider
    r1 = _make_rule()
    rule_map = {"aws.rds.instance.idle": r1}
    cfg = load_config(
        {
            "version": 1,
            "rules": {
                "aws.rds.instance.idle": {"enabled": True},
                "azure.compute.disk.unattached": {"enabled": False},  # valid for azure scan
            },
        }
    )
    active, _ = apply_rule_config([r1], rule_map, cfg)
    assert active == [r1]  # no error — azure rule silently ignored in aws scan


# ── exception glob matching ───────────────────────────────────────────────────


def test_exception_exact_match_still_works():
    f = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-prod")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [{"rule_id": "aws.rds.instance.idle", "resource_id": "db-prod"}],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f], cfg)
    assert kept == []
    assert len(suppressed_list) == 1


def test_exception_glob_star_matches_prefix():
    f1 = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-test-001")
    f2 = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-prod")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [{"rule_id": "aws.rds.instance.idle", "resource_id": "db-test-*"}],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f1, f2], cfg)
    assert len(kept) == 1
    assert kept[0].resource_id == "db-prod"
    assert len(suppressed_list) == 1


def test_exception_glob_star_matches_suffix():
    f1 = _make_finding(rule_id="aws.ec2.instance.stopped", resource_id="i-0abc1234staging")
    f2 = _make_finding(rule_id="aws.ec2.instance.stopped", resource_id="i-0abc1234prod")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [{"rule_id": "aws.ec2.instance.stopped", "resource_id": "*staging"}],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f1, f2], cfg)
    assert len(kept) == 1
    assert kept[0].resource_id == "i-0abc1234prod"


def test_exception_glob_no_match_keeps_finding():
    f = _make_finding(rule_id="aws.rds.instance.idle", resource_id="db-prod")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [{"rule_id": "aws.rds.instance.idle", "resource_id": "db-test-*"}],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f], cfg)
    assert kept == [f]
    assert len(suppressed_list) == 0


# ── exception account_id + region scoping ────────────────────────────────────


def _make_finding_full(rule_id, resource_id, account_id=None, region=None):
    f = _make_finding(rule_id=rule_id, resource_id=resource_id)
    f.account_id = account_id
    f.region = region
    return f


def test_exception_account_id_matches_correct_account():
    f = _make_finding_full("aws.ebs.unattached", "vol-123", account_id="111111111111")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [
                {
                    "rule_id": "aws.ebs.unattached",
                    "resource_id": "vol-*",
                    "account_id": "111111111111",
                }
            ],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f], cfg)
    assert kept == []
    assert len(suppressed_list) == 1


def test_exception_account_id_skips_different_account():
    f = _make_finding_full("aws.ebs.unattached", "vol-123", account_id="999999999999")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [
                {
                    "rule_id": "aws.ebs.unattached",
                    "resource_id": "vol-*",
                    "account_id": "111111111111",
                }
            ],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f], cfg)
    assert kept == [f]
    assert len(suppressed_list) == 0


def test_exception_region_matches_correct_region():
    f = _make_finding_full("aws.ebs.unattached", "vol-123", region="us-east-1")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [
                {
                    "rule_id": "aws.ebs.unattached",
                    "resource_id": "vol-*",
                    "region": "us-east-1",
                }
            ],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f], cfg)
    assert kept == []
    assert len(suppressed_list) == 1


def test_exception_region_skips_different_region():
    f = _make_finding_full("aws.ebs.unattached", "vol-123", region="eu-west-1")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [
                {
                    "rule_id": "aws.ebs.unattached",
                    "resource_id": "vol-*",
                    "region": "us-east-1",
                }
            ],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f], cfg)
    assert kept == [f]
    assert len(suppressed_list) == 0


def test_exception_omit_account_matches_any_account():
    f = _make_finding_full("aws.ebs.unattached", "vol-123", account_id="any-account")
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [
                {"rule_id": "aws.ebs.unattached", "resource_id": "vol-*"}
            ],  # no account_id
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f], cfg)
    assert kept == []
    assert len(suppressed_list) == 1


def test_exception_all_three_must_match():
    f = _make_finding_full(
        "aws.ebs.unattached", "vol-123", account_id="111111111111", region="us-east-1"
    )
    # resource_id matches, account_id matches, region DOES NOT match
    cfg = load_config(
        {
            "version": 1,
            "exceptions": [
                {
                    "rule_id": "aws.ebs.unattached",
                    "resource_id": "vol-*",
                    "account_id": "111111111111",
                    "region": "eu-west-1",
                }
            ],
        }
    )
    kept, suppressed_list, expired_events = apply_exceptions([f], cfg)
    assert kept == [f]
    assert len(suppressed_list) == 0
