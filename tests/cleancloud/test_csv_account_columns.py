"""
Tests for CSV output — account_id / account_name columns are present
and in the correct position. Single-account findings write empty values.
"""

import csv
from datetime import datetime, timezone

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.output.csv import CSV_FIELDS, write_csv


def _make_finding(**kwargs):
    defaults = dict(
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
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_csv_fields_include_account_columns():
    assert "account_id" in CSV_FIELDS
    assert "account_name" in CSV_FIELDS


def test_account_columns_are_first():
    assert CSV_FIELDS[0] == "account_id"
    assert CSV_FIELDS[1] == "account_name"


def test_csv_writes_account_id_and_name(tmp_path):
    output_file = tmp_path / "results.csv"
    finding = _make_finding(account_id="111111111111", account_name="prod")

    write_csv([finding], output_file)

    with open(output_file) as f:
        rows = list(csv.DictReader(f))

    assert rows[0]["account_id"] == "111111111111"
    assert rows[0]["account_name"] == "prod"


def test_csv_writes_empty_account_for_single_account_scan(tmp_path):
    output_file = tmp_path / "results.csv"
    finding = _make_finding()  # no account_id / account_name

    write_csv([finding], output_file)

    with open(output_file) as f:
        rows = list(csv.DictReader(f))

    assert rows[0]["account_id"] == "None" or rows[0]["account_id"] == ""


def test_csv_still_writes_all_core_fields(tmp_path):
    output_file = tmp_path / "results.csv"
    finding = _make_finding()

    write_csv([finding], output_file)

    with open(output_file) as f:
        rows = list(csv.DictReader(f))

    assert rows[0]["provider"] == "aws"
    assert rows[0]["rule_id"] == "aws.ebs.volume.unattached"
    assert rows[0]["region"] == "us-east-1"
