"""
Tests for skipped_rules handling in build_summary and _print_summary.
"""

from datetime import datetime, timezone

import click
from click.testing import CliRunner

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.output.summary import _print_summary, build_summary


def _make_finding():
    return Finding(
        provider="aws",
        rule_id="aws.ebs.volume.unattached",
        resource_type="aws.ebs.volume",
        resource_id="vol-1",
        region="us-east-1",
        title="Unattached EBS Volume",
        summary="Volume unattached",
        reason="Volume unattached for 30 days",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={},
        evidence=Evidence(signals_used=["state=available"], signals_not_checked=[]),
    )


_SKIPPED = [
    {
        "rule": "find_idle_rds_instances",
        "missing_permissions": "Missing required IAM permissions: rds:DescribeDBInstances, cloudwatch:GetMetricStatistics",
    },
    {
        "rule": "find_idle_nat_gateways",
        "missing_permissions": "Missing required IAM permissions: ec2:DescribeNatGateways",
    },
]


# --- build_summary ---


def test_build_summary_includes_skipped_rules():
    summary = build_summary([_make_finding()], skipped_rules=_SKIPPED)
    assert "skipped_rules" in summary
    assert len(summary["skipped_rules"]) == 2


def test_build_summary_skipped_rules_absent_when_empty():
    summary = build_summary([_make_finding()], skipped_rules=[])
    assert "skipped_rules" not in summary


def test_build_summary_skipped_rules_absent_when_not_provided():
    summary = build_summary([_make_finding()])
    assert "skipped_rules" not in summary


def test_build_summary_skipped_rules_preserves_fields():
    summary = build_summary([], skipped_rules=_SKIPPED)
    first = summary["skipped_rules"][0]
    assert first["rule"] == "find_idle_rds_instances"
    assert "rds:DescribeDBInstances" in first["missing_permissions"]


# --- _print_summary ---


def _run_print_summary(summary):
    runner = CliRunner()

    @click.command()
    def _cmd():
        _print_summary(summary)

    return runner.invoke(_cmd, catch_exceptions=False).output


def _base_summary(skipped_rules=None):
    s = {
        "total_findings": 1,
        "by_risk": {},
        "by_confidence": {},
        "regions_scanned": ["us-east-1"],
        "provider": "aws",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
    if skipped_rules:
        s["skipped_rules"] = skipped_rules
    return s


def test_print_summary_shows_rules_executed_count():
    summary = _base_summary(skipped_rules=_SKIPPED)
    output = _run_print_summary(summary)
    assert "Rules executed:" in output
    assert "8/10" in output
    assert "Rules skipped:  2" in output


def test_print_summary_shows_skipped_rule_names():
    summary = _base_summary(skipped_rules=_SKIPPED)
    output = _run_print_summary(summary)
    # find_ prefix stripped in display
    assert "idle_rds_instances" in output
    assert "idle_nat_gateways" in output


def test_print_summary_shows_missing_permissions():
    summary = _base_summary(skipped_rules=_SKIPPED)
    output = _run_print_summary(summary)
    assert "rds:DescribeDBInstances" in output
    assert "ec2:DescribeNatGateways" in output


def test_print_summary_strips_verbose_prefix_from_permissions():
    summary = _base_summary(skipped_rules=_SKIPPED)
    output = _run_print_summary(summary)
    # The "Missing required IAM permissions: " prefix should be stripped
    assert "Missing required IAM permissions:" not in output


def test_print_summary_shows_doctor_hint_when_skipped():
    summary = _base_summary(skipped_rules=_SKIPPED)
    output = _run_print_summary(summary)
    assert "cleancloud doctor" in output


def test_print_summary_no_skipped_section_when_none():
    summary = _base_summary()
    output = _run_print_summary(summary)
    assert "Rules skipped" not in output
    assert "Rules executed" not in output
    assert "cleancloud doctor" not in output
