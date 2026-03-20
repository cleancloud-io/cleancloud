"""
Tests for account_id / account_name fields on Finding.
Verifies backwards compatibility — single-account findings are unaffected.
"""

from datetime import datetime, timezone

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel


def _make_finding(**kwargs):
    defaults = dict(
        provider="aws",
        rule_id="aws.ebs.volume.unattached",
        resource_type="aws.ebs.volume",
        resource_id="vol-1",
        region="us-east-1",
        title="Unattached EBS Volume",
        summary="Volume has been unattached",
        reason="Volume unattached for 30 days",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={},
        evidence=Evidence(signals_used=["state=available"], signals_not_checked=[]),
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_account_fields_default_to_none():
    f = _make_finding()

    assert f.account_id is None
    assert f.account_name is None


def test_account_fields_not_in_to_dict_when_none():
    f = _make_finding()
    d = f.to_dict()

    assert "account_id" not in d
    assert "account_name" not in d


def test_account_fields_in_to_dict_when_set():
    f = _make_finding(account_id="111111111111", account_name="prod")
    d = f.to_dict()

    assert d["account_id"] == "111111111111"
    assert d["account_name"] == "prod"


def test_account_id_can_be_set_after_creation():
    f = _make_finding()
    f.account_id = "111111111111"
    f.account_name = "prod"

    assert f.account_id == "111111111111"
    assert f.account_name == "prod"


def test_existing_fields_unaffected_by_account_fields():
    f = _make_finding(account_id="111111111111", account_name="prod")
    d = f.to_dict()

    assert d["provider"] == "aws"
    assert d["rule_id"] == "aws.ebs.volume.unattached"
    assert d["region"] == "us-east-1"
    assert d["risk"] == "low"
    assert d["confidence"] == "high"
