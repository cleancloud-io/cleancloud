from datetime import datetime, timezone

import yaml
from click.testing import CliRunner

from cleancloud.cli import cli
from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.finding import Evidence, Finding
from cleancloud.core.risk import RiskLevel


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
        "cleancloud.cli._scan_aws_region",
        lambda profile, region: findings,
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
    assert "Ignored by tag policy: 1" in result.output
