import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import botocore.exceptions
import click
import yaml

# ------------------------
# Config + filtering
# ------------------------
from cleancloud.config.schema import (
    CleanCloudConfig,
    IgnoreTagRuleConfig,
    load_config,
)
from cleancloud.core.finding import Finding
from cleancloud.filtering.tags import (
    compile_rules,
    filter_findings_by_tags,
)
from cleancloud.output.csv import write_csv
from cleancloud.output.feedback import should_show_feedback, show_feedback_prompt
from cleancloud.output.human import print_human
from cleancloud.output.json import write_json
from cleancloud.output.summary import _print_summary, build_summary
from cleancloud.policy.exit_policy import (
    CONFIDENCE_ORDER,
    EXIT_ERROR,
    EXIT_PERMISSION_ERROR,
    EXIT_POLICY_VIOLATION,
    determine_exit_code,
)
from cleancloud.providers.aws.scan import scan_aws_with_region_selection
from cleancloud.providers.azure.scan import scan_azure_with_region_selection


@click.command("scan")
@click.option(
    "--provider", required=True, type=click.Choice(["aws", "azure"]), help="Cloud provider to scan"
)
@click.option(
    "--region", default=None, help="Specific region to scan (AWS region or Azure location)"
)
@click.option(
    "--all-regions",
    is_flag=True,
    help="Scan all regions with resources (auto-detects active regions)",
)
@click.option("--profile", default=None, help="AWS CLI profile name")
@click.option(
    "--output",
    default="human",
    type=click.Choice(["human", "json", "csv"]),
)
@click.option(
    "--output-file",
    default=None,
    help="Output file path (required for json/csv)",
)
@click.option(
    "--fail-on-findings",
    is_flag=True,
    help="Exit with non-zero code if findings are detected",
)
@click.option(
    "--fail-on-confidence",
    type=click.Choice(["LOW", "MEDIUM", "HIGH"]),
    default=None,
    help="Fail scan if findings at or above this confidence exist",
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to cleancloud.yaml",
)
@click.option(
    "--ignore-tag",
    multiple=True,
    help="Ignore findings by tag (key or key:value). Overrides config.",
)
@click.option(
    "--no-feedback",
    is_flag=True,
    default=False,
    help="Disable post-scan feedback prompt (recommended for CI/CD runs)",
)
def scan(
    provider: str,
    region: Optional[str],
    all_regions: bool,
    profile: Optional[str],
    output: str,
    output_file: Optional[str],
    fail_on_findings: bool,
    fail_on_confidence: Optional[str],
    config: Optional[str],
    ignore_tag: List[str],
    no_feedback: bool,
):
    click.echo()
    click.echo("🔍 Starting CleanCloud scan...")
    click.echo()
    click.echo(f"Provider: {provider}")
    click.echo()

    try:

        findings: List[Finding] = []

        if provider == "aws":
            region_selection_mode, findings, regions_scanned = scan_aws_with_region_selection(
                profile=profile, region=region, all_regions=all_regions
            )

        elif provider == "azure":
            region_selection_mode, findings, regions_scanned = scan_azure_with_region_selection(
                region=region,
            )

        ignored_count = 0
        rules = []

        cfg = CleanCloudConfig.empty()
        if config:
            with open(config) as f:
                raw = yaml.safe_load(f) or {}
                cfg = load_config(raw)

        # CLI overrides config
        if ignore_tag:
            rules = compile_rules(
                [
                    IgnoreTagRuleConfig(
                        key=item.split(":", 1)[0],
                        value=item.split(":", 1)[1] if ":" in item else None,
                    )
                    for item in ignore_tag
                ]
            )

        elif cfg.tag_filtering and cfg.tag_filtering.enabled:
            rules = compile_rules(cfg.tag_filtering.ignore)

        if rules:
            result = filter_findings_by_tags(findings, rules)
            ignored_count = len(result.ignored)
            findings = result.kept

        summary = build_summary(findings)
        summary["scanned_at"] = datetime.now(timezone.utc).isoformat()
        summary["regions_scanned"] = regions_scanned
        summary["region_selection_mode"] = region_selection_mode
        summary["highest_confidence"] = max(
            (f.confidence for f in findings),
            default=None,
            key=lambda c: CONFIDENCE_ORDER.get(c, 0),
        )
        summary["high_conf_findings"] = len([f for f in findings if f.confidence == "HIGH"])

        if ignored_count > 0:
            summary["ignored_by_tag_policy"] = ignored_count

        output_path = Path(output_file) if output_file else None

        if output in ("json", "csv") and not output_path:
            raise ValueError("--output-file is required for json/csv output")

        if output == "json":
            write_json(
                {
                    "summary": summary,
                    "findings": findings,
                },
                output_path,
            )
            click.echo(f"✓ JSON output written to {output_path}")
            click.echo()

        elif output == "csv":
            write_csv(findings, output_path)
            click.echo(f"✓ CSV output written to {output_path}")
            click.echo()

        else:
            print_human(findings)
            _print_summary(summary, region_selection_mode)

            if should_show_feedback(no_feedback):
                show_feedback_prompt()

        # ========================
        # Exit policy
        # ========================
        exit_code = determine_exit_code(
            findings,
            fail_on_findings=fail_on_findings,
            fail_on_confidence=fail_on_confidence,
        )

        if exit_code == EXIT_POLICY_VIOLATION:
            click.echo("\n❌ CleanCloud policy violation detected")

        sys.exit(exit_code)

    except PermissionError as e:
        click.echo(f"🔒 Permission error: {e}")
        sys.exit(EXIT_PERMISSION_ERROR)

    except botocore.exceptions.NoCredentialsError:
        click.echo("❌ No AWS credentials found")
        sys.exit(EXIT_PERMISSION_ERROR)

    except Exception as e:
        click.echo(f"💥 Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(EXIT_ERROR)
