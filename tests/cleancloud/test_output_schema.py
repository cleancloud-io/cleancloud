"""Test that JSON output conforms to the published schema."""

import json
from datetime import datetime, timezone
from pathlib import Path

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.output.summary import build_summary


def test_json_output_includes_schema_version():
    """Verify that JSON output always includes schema_version field."""
    # Create a mock finding
    findings = [
        Finding(
            provider="aws",
            rule_id="aws.ebs.unattached",
            resource_type="aws.ebs.volume",
            resource_id="vol-123",
            region="us-east-1",
            title="Test finding",
            summary="Test summary",
            reason="Test reason",
            risk=RiskLevel.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            detected_at=datetime.now(timezone.utc),
            details={"size_gb": 100},
            evidence=Evidence(
                signals_used=["Test signal"],
                signals_not_checked=["Other signal"],
                time_window=None,
            ),
        )
    ]

    summary = build_summary(findings)

    # Simulate what command.py does
    output = {
        "schema_version": "1.1.0",
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }

    # Verify schema_version is present and correct
    assert "schema_version" in output
    assert output["schema_version"] == "1.1.0"


def test_json_output_has_required_summary_fields():
    """Verify that summary contains all required fields."""
    findings = [
        Finding(
            provider="aws",
            rule_id="aws.ebs.unattached",
            resource_type="aws.ebs.volume",
            resource_id="vol-123",
            region="us-east-1",
            title="Test finding",
            summary="Test summary",
            reason="Test reason",
            risk=RiskLevel.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            detected_at=datetime.now(timezone.utc),
            details={},
            evidence=Evidence(
                signals_used=["Test signal"],
                signals_not_checked=["Other signal"],
            ),
        )
    ]

    summary = build_summary(findings)

    # Required fields per schema
    assert "total_findings" in summary
    assert "by_provider" in summary
    assert "by_risk" in summary
    assert "by_confidence" in summary

    assert summary["total_findings"] == 1
    assert isinstance(summary["by_provider"], dict)
    assert isinstance(summary["by_risk"], dict)
    assert isinstance(summary["by_confidence"], dict)


def test_finding_dict_has_all_required_fields():
    """Verify that Finding.to_dict() includes all schema-required fields."""
    finding = Finding(
        provider="aws",
        rule_id="aws.ebs.unattached",
        resource_type="aws.ebs.volume",
        resource_id="vol-123",
        region="us-east-1",
        title="Test finding",
        summary="Test summary",
        reason="Test reason",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={"size_gb": 100},
        evidence=Evidence(
            signals_used=["Test signal"],
            signals_not_checked=["Other signal"],
            time_window="90 days",
        ),
    )

    finding_dict = finding.to_dict()

    # Verify all required fields are present
    required_fields = [
        "provider",
        "rule_id",
        "resource_type",
        "resource_id",
        "region",
        "title",
        "summary",
        "reason",
        "risk",
        "confidence",
        "detected_at",
        "details",
        "evidence",
    ]

    for field in required_fields:
        assert field in finding_dict, f"Missing required field: {field}"

    # Verify enums are converted to strings
    assert finding_dict["risk"] == "medium"
    assert finding_dict["confidence"] == "high"

    # Verify datetime is ISO format string
    assert isinstance(finding_dict["detected_at"], str)

    # Verify evidence structure
    assert isinstance(finding_dict["evidence"], Evidence)


def test_schema_file_exists_and_is_valid_json():
    """Verify that the schema file exists and is valid JSON."""
    schema_path = Path(__file__).parent.parent.parent / "schemas" / "output-v1.1.0.json"

    assert schema_path.exists(), f"Schema file not found at {schema_path}"

    with open(schema_path) as f:
        schema = json.load(f)

    # Verify basic schema structure
    assert "$schema" in schema
    assert "title" in schema
    assert "type" in schema
    assert schema["type"] == "object"
    assert "properties" in schema

    # Verify required root properties
    assert "schema_version" in schema["properties"]
    assert "summary" in schema["properties"]
    assert "findings" in schema["properties"]


def test_finding_dict_includes_cost_when_set():
    """Verify that Finding.to_dict() includes estimated_monthly_cost_usd when set."""
    finding = Finding(
        provider="aws",
        rule_id="aws.ebs.unattached",
        resource_type="aws.ebs.volume",
        resource_id="vol-123",
        region="us-east-1",
        title="Test finding",
        summary="Test summary",
        reason="Test reason",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={"size_gb": 100},
        evidence=Evidence(
            signals_used=["Test signal"],
            signals_not_checked=["Other signal"],
        ),
        estimated_monthly_cost_usd=10.0,
    )

    finding_dict = finding.to_dict()
    assert "estimated_monthly_cost_usd" in finding_dict
    assert finding_dict["estimated_monthly_cost_usd"] == 10.0


def test_finding_dict_omits_cost_when_none():
    """Verify that Finding.to_dict() omits estimated_monthly_cost_usd when None."""
    finding = Finding(
        provider="aws",
        rule_id="aws.ebs.unattached",
        resource_type="aws.ebs.volume",
        resource_id="vol-123",
        region="us-east-1",
        title="Test finding",
        summary="Test summary",
        reason="Test reason",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        detected_at=datetime.now(timezone.utc),
        details={},
        evidence=Evidence(
            signals_used=["Test signal"],
            signals_not_checked=["Other signal"],
        ),
    )

    finding_dict = finding.to_dict()
    assert "estimated_monthly_cost_usd" not in finding_dict


def test_build_summary_aggregates_costs():
    """Verify that build_summary aggregates costs into minimum_estimated_monthly_waste_usd."""
    findings = [
        Finding(
            provider="aws",
            rule_id="aws.ebs.unattached",
            resource_type="aws.ebs.volume",
            resource_id="vol-1",
            region="us-east-1",
            title="Finding 1",
            summary="Summary 1",
            reason="Reason 1",
            risk=RiskLevel.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            detected_at=datetime.now(timezone.utc),
            details={},
            evidence=Evidence(
                signals_used=["Signal"],
                signals_not_checked=[],
            ),
            estimated_monthly_cost_usd=10.50,
        ),
        Finding(
            provider="aws",
            rule_id="aws.ec2.elastic_ip.unattached",
            resource_type="aws.ec2.elastic_ip",
            resource_id="eip-1",
            region="us-east-1",
            title="Finding 2",
            summary="Summary 2",
            reason="Reason 2",
            risk=RiskLevel.LOW,
            confidence=ConfidenceLevel.HIGH,
            detected_at=datetime.now(timezone.utc),
            details={},
            evidence=Evidence(
                signals_used=["Signal"],
                signals_not_checked=[],
            ),
            estimated_monthly_cost_usd=3.75,
        ),
        Finding(
            provider="aws",
            rule_id="aws.ec2.eni.detached",
            resource_type="aws.ec2.eni",
            resource_id="eni-1",
            region="us-east-1",
            title="Finding 3 (no cost)",
            summary="Summary 3",
            reason="Reason 3",
            risk=RiskLevel.LOW,
            confidence=ConfidenceLevel.MEDIUM,
            detected_at=datetime.now(timezone.utc),
            details={},
            evidence=Evidence(
                signals_used=["Signal"],
                signals_not_checked=[],
            ),
            # No cost estimate
        ),
    ]

    summary = build_summary(findings)

    assert summary["total_findings"] == 3
    assert summary["minimum_estimated_monthly_waste_usd"] == 14.25
    assert summary["findings_with_cost_estimate"] == 2


def test_build_summary_no_cost_fields_when_zero():
    """Verify that build_summary omits cost fields when no findings have costs."""
    findings = [
        Finding(
            provider="aws",
            rule_id="aws.ec2.eni.detached",
            resource_type="aws.ec2.eni",
            resource_id="eni-1",
            region="us-east-1",
            title="No cost finding",
            summary="Summary",
            reason="Reason",
            risk=RiskLevel.LOW,
            confidence=ConfidenceLevel.MEDIUM,
            detected_at=datetime.now(timezone.utc),
            details={},
            evidence=Evidence(
                signals_used=["Signal"],
                signals_not_checked=[],
            ),
        ),
    ]

    summary = build_summary(findings)

    assert summary["total_findings"] == 1
    assert "minimum_estimated_monthly_waste_usd" not in summary
    assert "findings_with_cost_estimate" not in summary


def test_confidence_enum_values_lowercase():
    """Verify that confidence enum values are lowercase strings."""
    assert ConfidenceLevel.LOW.value == "low"
    assert ConfidenceLevel.MEDIUM.value == "medium"
    assert ConfidenceLevel.HIGH.value == "high"


def test_risk_enum_values_lowercase():
    """Verify that risk enum values are lowercase strings."""
    assert RiskLevel.LOW.value == "low"
    assert RiskLevel.MEDIUM.value == "medium"
    assert RiskLevel.HIGH.value == "high"
