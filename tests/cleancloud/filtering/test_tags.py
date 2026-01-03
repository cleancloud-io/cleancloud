from datetime import datetime, timezone

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.filtering.tags import (
    IgnoreTagRule,
    filter_findings_by_tags,
)


def _finding(resource_id: str, tags: dict):
    return Finding(
        provider="aws",
        rule_id="test-rule",
        resource_type="ebs-volume",
        resource_id=resource_id,
        region="us-east-1",
        title="Test",
        summary="Test",
        reason="Test",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.LOW,
        detected_at=datetime.now(timezone.utc),
        details={"tags": tags},
        evidence=Evidence(
            signals_used=["signal-a"],
            signals_not_checked=[],
        ),
    )


def test_ignore_by_key_only():
    findings = [
        _finding("vol-1", {"env": "prod"}),
        _finding("vol-2", {"team": "platform"}),
    ]

    rules = [IgnoreTagRule(key="env")]

    result = filter_findings_by_tags(findings, rules)

    assert len(result.ignored) == 1
    assert result.ignored[0].resource_id == "vol-1"
    assert len(result.kept) == 1


def test_ignore_by_key_and_value():
    findings = [
        _finding("vol-1", {"env": "production"}),
        _finding("vol-2", {"env": "staging"}),
    ]

    rules = [IgnoreTagRule(key="env", value="production")]

    result = filter_findings_by_tags(findings, rules)

    assert len(result.ignored) == 1
    assert result.ignored[0].resource_id == "vol-1"
    assert result.kept[0].resource_id == "vol-2"


def test_multiple_rules_any_match_ignores():
    findings = [
        _finding("vol-1", {"env": "prod"}),
        _finding("vol-2", {"team": "platform"}),
        _finding("vol-3", {"service": "billing"}),
    ]

    rules = [
        IgnoreTagRule(key="env"),
        IgnoreTagRule(key="team", value="platform"),
    ]

    result = filter_findings_by_tags(findings, rules)

    ignored_ids = {f.resource_id for f in result.ignored}

    assert ignored_ids == {"vol-1", "vol-2"}
    assert result.kept[0].resource_id == "vol-3"


def test_no_ignore_rules_returns_all_kept():
    findings = [
        _finding("vol-1", {"env": "prod"}),
    ]

    result = filter_findings_by_tags(findings, [])

    assert result.kept == findings
    assert result.ignored == []


def test_missing_tags_safe():
    findings = [
        _finding("vol-1", {}),
        _finding("vol-2", None),
    ]

    rules = [IgnoreTagRule(key="env")]

    result = filter_findings_by_tags(findings, rules)

    assert len(result.kept) == 2
    assert len(result.ignored) == 0
