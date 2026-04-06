from datetime import datetime, timezone

import yaml
from click.testing import CliRunner

from cleancloud.cli import cli
from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.gcp.scan import ProjectScanResult


def _fake_finding(resource_id, tags):
    return Finding(
        provider="aws",
        rule_id="rule",
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
            signals_used=["signal"],
            signals_not_checked=[],
        ),
    )


def _fake_gcp_finding(resource_id, labels):
    return Finding(
        provider="gcp",
        rule_id="gcp.compute.disk.unattached",
        resource_type="gcp.compute.disk",
        resource_id=resource_id,
        region="us-central1-a",
        title="Unattached Persistent Disk",
        summary="Test",
        reason="Test",
        risk=RiskLevel.LOW,
        confidence=ConfidenceLevel.LOW,
        detected_at=datetime.now(timezone.utc),
        details={"labels": labels},
        evidence=Evidence(
            signals_used=["signal"],
            signals_not_checked=[],
        ),
    )


def test_cli_ignore_tag_overrides_yaml(monkeypatch, tmp_path):
    config_path = tmp_path / "cleancloud.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "tag_filtering": {
                    "enabled": True,
                    "ignore": [
                        {"key": "env", "value": "production"},
                    ],
                },
            }
        )
    )

    findings = [
        _fake_finding("vol-1", {"env": "production"}),
        _fake_finding("vol-2", {"team": "platform"}),
    ]

    # Patch AWS scan to return fixed findings
    monkeypatch.setattr(
        "cleancloud.providers.aws.scan._scan_aws_region",
        lambda profile, region, rules: (findings, []),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--provider",
            "aws",
            "--region",
            "us-east-1",
            "--config",
            str(config_path),
            "--ignore-tag",
            "team:platform",
        ],
    )

    assert result.exit_code == 0

    # vol-2 ignored (CLI)
    # vol-1 MUST remain (YAML ignored)
    assert "vol-1" in result.output
    assert "vol-2" not in result.output
    assert "tag: 1" in result.output


def test_gcp_cli_ignore_label_overrides_yaml(monkeypatch, tmp_path):
    """GCP labels are filtered the same way AWS tags are — CLI --ignore-tag wins over YAML."""
    config_path = tmp_path / "cleancloud.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "tag_filtering": {
                    "enabled": True,
                    "ignore": [
                        {"key": "env", "value": "production"},
                    ],
                },
            }
        )
    )

    findings = [
        _fake_gcp_finding("projects/p/zones/us-central1-a/disks/disk-1", {"env": "production"}),
        _fake_gcp_finding("projects/p/zones/us-central1-a/disks/disk-2", {"team": "platform"}),
    ]

    proj = ProjectScanResult(
        project_id="p",
        project_name="My Project",
        status="success",
        findings=findings,
        skipped_rules=[],
        rules_succeeded=5,
    )

    monkeypatch.setattr(
        "cleancloud.scan.command.scan_gcp_with_project_selection",
        lambda **kwargs: ("explicit", findings, ["p"], [], [proj]),
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "scan",
            "--provider",
            "gcp",
            "--project",
            "p",
            "--config",
            str(config_path),
            "--ignore-tag",
            "team:platform",
        ],
    )

    assert result.exit_code == 0

    # disk-2 ignored by CLI --ignore-tag
    # disk-1 MUST remain (YAML ignored env:production)
    assert "disk-1" in result.output
    assert "disk-2" not in result.output
    assert "tag: 1" in result.output
