"""Tests for the markdown output formatter."""

from datetime import datetime, timezone

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.output.markdown import write_markdown


def _make_finding(
    title="Unattached EBS Volume",
    cost=None,
    rule_id="aws.ebs.unattached",
    provider="aws",
):
    return Finding(
        provider=provider,
        rule_id=rule_id,
        resource_type="aws.ebs.volume",
        resource_id="vol-123",
        region="us-east-1",
        title=title,
        summary="Volume unattached",
        reason="Volume has been unattached for 30 days",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={},
        evidence=Evidence(signals_used=["Signal"], signals_not_checked=[]),
        estimated_monthly_cost_usd=cost,
    )


def _make_summary(findings, provider="aws", regions=None, waste=None):
    summary = {
        "provider": provider,
        "scanned_at": "2026-03-07T10:00:00+00:00",
        "regions_scanned": regions or ["us-east-1"],
        "total_findings": len(findings),
        "by_confidence": {ConfidenceLevel.HIGH: len(findings)},
    }
    if waste is not None:
        summary["minimum_estimated_monthly_waste_usd"] = waste
    return summary


def test_no_findings_output():
    summary = _make_summary([])
    summary["total_findings"] = 0
    output = write_markdown([], summary)
    assert "No hygiene issues detected" in output


def test_findings_table_present():
    findings = [_make_finding(cost=40.0)]
    summary = _make_summary(findings, waste=40.0)
    output = write_markdown(findings, summary)

    assert "| Finding |" in output
    assert "Unattached EBS Volume" in output
    assert "~$40" in output


def test_findings_without_cost_show_dash():
    findings = [_make_finding(cost=None)]
    summary = _make_summary(findings)
    output = write_markdown(findings, summary)

    assert "—" in output


def test_grouped_by_title():
    findings = [
        _make_finding(title="Unattached EBS Volume", cost=40.0),
        _make_finding(title="Unattached EBS Volume", cost=40.0),
        _make_finding(title="Idle NAT Gateway", cost=32.0),
    ]
    summary = _make_summary(findings, waste=112.0)
    output = write_markdown(findings, summary)

    lines = output.split("\n")
    table_lines = [row for row in lines if "Unattached EBS Volume" in row]
    assert len(table_lines) == 1  # grouped, not 2 separate rows

    ebs_line = table_lines[0]
    assert "| 2 |" in ebs_line
    assert "~$80" in ebs_line


def test_sorted_by_cost_descending():
    findings = [
        _make_finding(title="Cheap finding", cost=10.0),
        _make_finding(title="Expensive finding", cost=100.0),
    ]
    summary = _make_summary(findings, waste=110.0)
    output = write_markdown(findings, summary)

    expensive_pos = output.index("Expensive finding")
    cheap_pos = output.index("Cheap finding")
    assert expensive_pos < cheap_pos


def test_waste_shown_when_positive():
    findings = [_make_finding(cost=147.0)]
    summary = _make_summary(findings, waste=147.0)
    output = write_markdown(findings, summary)

    assert "Estimated monthly waste" in output
    assert "~$147" in output


def test_waste_not_shown_when_zero():
    findings = [_make_finding(cost=None)]
    summary = _make_summary(findings)
    output = write_markdown(findings, summary)

    assert "Estimated monthly waste" not in output


def test_provider_shown():
    findings = [_make_finding(provider="aws")]
    summary = _make_summary(findings, provider="aws")
    output = write_markdown(findings, summary)

    assert "**Provider:** AWS" in output


def test_azure_subscriptions_shown():
    findings = [_make_finding(provider="azure")]
    summary = _make_summary(findings, provider="azure")
    summary["subscriptions_scanned"] = ["sub-abc", "sub-def"]
    output = write_markdown(findings, summary)

    assert "**Subscriptions:**" in output
    assert "sub-abc" in output
    assert "sub-def" in output


def test_confidence_breakdown_shown():
    findings = [_make_finding()]
    summary = _make_summary(findings)
    output = write_markdown(findings, summary)

    assert "**Confidence:**" in output
    assert "high:" in output or "high" in output


def test_footer_present():
    output = write_markdown([], _make_summary([]))
    assert "CleanCloud" in output
    assert "github.com" in output


def test_writes_to_file(tmp_path):
    findings = [_make_finding(cost=40.0)]
    summary = _make_summary(findings, waste=40.0)
    out_file = tmp_path / "results.md"

    result = write_markdown(findings, summary, output_path=out_file)

    assert result is None
    content = out_file.read_text()
    assert "Unattached EBS Volume" in content


def test_returns_string_when_no_file():
    findings = [_make_finding(cost=40.0)]
    summary = _make_summary(findings, waste=40.0)

    result = write_markdown(findings, summary, output_path=None)

    assert isinstance(result, str)
    assert "Unattached EBS Volume" in result


def test_header_present():
    output = write_markdown([], _make_summary([]))
    assert "## CleanCloud Scan Results" in output
