"""
Tests for _print_summary with multi-account results.
Verifies per-account breakdown, failed/timed-out account reporting.
"""

from datetime import datetime, timezone
from unittest.mock import patch

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.output.summary import _print_summary
from cleancloud.providers.aws.multi_account import AccountScanResult


def _make_finding(account_id="111111111111", account_name="prod", cost=None):
    return Finding(
        provider="aws",
        rule_id="aws.ebs.volume.unattached",
        resource_type="aws.ebs.volume",
        resource_id="vol-1",
        region="us-east-1",
        title="Unattached EBS Volume",
        summary="Volume has been unattached",
        reason="Volume unattached",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={},
        evidence=Evidence(signals_used=[], signals_not_checked=[]),
        estimated_monthly_cost_usd=cost,
        account_id=account_id,
        account_name=account_name,
    )


def _base_summary(findings):
    return {
        "total_findings": len(findings),
        "by_risk": {},
        "by_confidence": {},
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "regions_scanned": ["us-east-1"],
        "provider": "aws",
    }


def _capture_summary(summary, region_selection_mode=None, multi_account_results=None):
    output = []
    with patch(
        "cleancloud.output.summary.click.echo",
        side_effect=lambda msg="", **kw: output.append(str(msg)),
    ):
        _print_summary(summary, region_selection_mode, multi_account_results)
    return "\n".join(output)


def test_summary_shows_accounts_scanned_count():
    results = [
        AccountScanResult(
            account_id="111111111111",
            account_name="prod",
            status="success",
            findings=[_make_finding()],
        ),
        AccountScanResult(
            account_id="222222222222", account_name="dev", status="success", findings=[]
        ),
    ]
    summary = _base_summary([_make_finding()])
    output = _capture_summary(summary, multi_account_results=results)

    assert "2" in output
    assert "Accounts scanned" in output


def test_summary_shows_failed_accounts():
    results = [
        AccountScanResult(
            account_id="111111111111",
            account_name="prod",
            status="success",
            findings=[_make_finding()],
        ),
        AccountScanResult(
            account_id="222222222222",
            account_name="legacy",
            status="failed",
            error="AccessDenied: role not found",
        ),
    ]
    summary = _base_summary([_make_finding()])
    output = _capture_summary(summary, multi_account_results=results)

    assert "[failed]" in output
    assert "legacy" in output
    assert "AccessDenied" in output


def test_summary_shows_timed_out_accounts():
    results = [
        AccountScanResult(
            account_id="111111111111",
            account_name="prod",
            status="timeout",
            error="Exceeded 300s timeout",
        ),
    ]
    summary = _base_summary([])
    output = _capture_summary(summary, multi_account_results=results)

    assert "[timeout]" in output
    assert "prod" in output


def test_summary_shows_per_account_breakdown():
    finding = _make_finding(account_id="111111111111", account_name="prod", cost=500.0)
    results = [
        AccountScanResult(
            account_id="111111111111",
            account_name="prod",
            status="success",
            findings=[finding],
        ),
    ]
    summary = _base_summary([finding])
    output = _capture_summary(summary, multi_account_results=results)

    assert "prod" in output
    assert "1 findings" in output


def test_summary_without_multi_account_results_unchanged():
    """Single-account scans must not show any multi-account section."""
    summary = _base_summary([])
    output = _capture_summary(summary, multi_account_results=None)

    assert "[failed]" not in output
    assert "[timeout]" not in output
    assert "Accounts scanned" not in output
