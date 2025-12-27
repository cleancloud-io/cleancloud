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
from cleancloud.exit_policy import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_PERMISSION_ERROR,
    EXIT_POLICY_VIOLATION,
    determine_exit_code,
)
from cleancloud.filtering.tags import (
    compile_rules,
    filter_findings_by_tags,
)
from cleancloud.models.finding import Finding
from cleancloud.output.csv import write_csv
from cleancloud.output.human import print_human
from cleancloud.output.json import write_json
from cleancloud.output.summary import build_summary
from cleancloud.providers.aws.doctor import run_aws_doctor

# ------------------------
# AWS rules
# ------------------------
from cleancloud.providers.aws.rules.cloudwatch_inactive import (
    find_inactive_cloudwatch_logs,
)
from cleancloud.providers.aws.rules.ebs_snapshot_old import find_old_ebs_snapshots
from cleancloud.providers.aws.rules.ebs_unattached import find_unattached_ebs_volumes
from cleancloud.providers.aws.rules.untagged_resources import (
    find_untagged_resources as find_aws_untagged_resources,
)

# ------------------------
# Sessions / doctor
# ------------------------
from cleancloud.providers.aws.session import create_aws_session
from cleancloud.providers.azure.doctor import run_azure_doctor

# ------------------------
# Azure rules
# ------------------------
from cleancloud.providers.azure.rules.ebs_snapshots_old import find_old_snapshots
from cleancloud.providers.azure.rules.public_ip_unused import find_unused_public_ips
from cleancloud.providers.azure.rules.unattached_managed_disks import (
    find_unattached_managed_disks,
)
from cleancloud.providers.azure.rules.untagged_resources import (
    find_untagged_resources as find_azure_untagged_resources,
)
from cleancloud.providers.azure.session import create_azure_session

CONFIDENCE_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


@click.group()
def cli():
    """CleanCloud – Safe cloud hygiene scanner"""
    pass


# ========================
# Scan Command
# ========================
@cli.command()
@click.option("--provider", default="aws", type=click.Choice(["aws", "azure"]))
@click.option("--region", default=None, help="Cloud region (Azure location or AWS region)")
@click.option("--all-regions", is_flag=True, help="Scan all AWS regions")
@click.option("--profile", default=None, help="AWS CLI profile")
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
):
    click.echo("🔍 Starting CleanCloud scan")
    click.echo(f"Provider: {provider}")

    try:
        # ------------------------
        # Load config (safe)
        # ------------------------
        cfg = CleanCloudConfig.empty()
        if config:
            with open(config) as f:
                raw = yaml.safe_load(f) or {}
                cfg = load_config(raw)

        findings: List[Finding] = []

        # ========================
        # AWS scanning
        # ========================
        if provider == "aws":
            base_session = create_aws_session(profile=profile, region="us-east-1")

            regions_to_scan = [region or "us-east-1"]
            if all_regions:
                regions_to_scan = _get_all_aws_regions(base_session)
                click.echo(f"Scanning all regions: {', '.join(regions_to_scan)}")

            for r in regions_to_scan:
                click.echo(f"\n🔍 Scanning region {r}")
                findings.extend(_scan_aws_region(profile=profile, region=r))

            regions_scanned = regions_to_scan

        # ========================
        # Azure scanning
        # ========================
        elif provider == "azure":
            click.echo("🔍 Authenticating to Azure")

            session = create_azure_session()
            subscription_ids = session.list_subscription_ids()

            if not subscription_ids:
                raise PermissionError("No accessible Azure subscriptions found")

            click.echo(f"Scanning {len(subscription_ids)} subscription(s)")

            for sub_id in subscription_ids:
                click.echo(f"\n📦 Subscription {sub_id}")
                findings.extend(
                    _scan_azure_subscription(
                        subscription_id=sub_id,
                        credential=session.credential,
                        region_filter=region,
                    )
                )

            regions_scanned = ["all"] if not region else [region]

        else:
            click.echo(f"Unknown provider: {provider}")
            sys.exit(EXIT_ERROR)

        # ========================
        # Tag filtering (POST-SCAN)
        # ========================
        ignored_count = 0
        rules = []

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

        # ========================
        # Summary + Output
        # ========================
        summary = build_summary(findings)
        summary["scanned_at"] = datetime.now(timezone.utc).isoformat()
        summary["regions_scanned"] = regions_scanned
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
            click.echo(f"JSON output written to {output_path}")

        elif output == "csv":
            write_csv(findings, output_path)
            click.echo(f"CSV output written to {output_path}")

        else:
            print_human(findings)
            _print_summary(summary)

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


# ========================
# Doctor Command
# ========================
@cli.command()
@click.option("--provider", default="aws", type=click.Choice(["aws", "azure"]))
@click.option("--region", default="us-east-1")
@click.option("--profile", default=None)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to cleancloud.yaml",
)
def doctor(provider: str, region: Optional[str], profile: Optional[str], config: Optional[str]):
    click.echo("🩺 Running CleanCloud doctor")

    try:
        cfg = CleanCloudConfig.empty()
        if config:
            with open(config) as f:
                raw = yaml.safe_load(f) or {}
                cfg = load_config(raw)

        if cfg.tag_filtering and cfg.tag_filtering.enabled:
            click.echo("⚠️  Tag filtering is enabled — some findings may be intentionally ignored")

        if provider == "aws":
            run_aws_doctor(profile=profile, region=region)
            sys.exit(EXIT_OK)

        elif provider == "azure":
            run_azure_doctor()
            sys.exit(EXIT_OK)

        else:
            click.echo(f"Unknown provider: {provider}")
            sys.exit(EXIT_ERROR)

    except Exception as e:
        click.echo(f"❌ Doctor failed: {e}")
        sys.exit(EXIT_ERROR)


# ========================
# Helpers (UNCHANGED)
# ========================
def _get_all_aws_regions(session) -> List[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in response["Regions"]]


def _scan_aws_region(profile: Optional[str], region: str) -> List[Finding]:
    session = create_aws_session(profile=profile, region=region)
    findings: List[Finding] = []

    findings.extend(find_unattached_ebs_volumes(session, region))
    findings.extend(find_old_ebs_snapshots(session, region))
    findings.extend(find_inactive_cloudwatch_logs(session, region))
    findings.extend(find_aws_untagged_resources(session, region))

    for f in findings:
        f.region = region

    return findings


def _scan_azure_subscription(
    subscription_id: str, credential, region_filter: Optional[str]
) -> List[Finding]:
    findings: List[Finding] = []

    findings.extend(
        find_unattached_managed_disks(
            subscription_id=subscription_id,
            credential=credential,
            region_filter=region_filter,
        )
    )
    findings.extend(
        find_old_snapshots(
            subscription_id=subscription_id,
            credential=credential,
            region_filter=region_filter,
        )
    )
    findings.extend(
        find_azure_untagged_resources(
            subscription_id=subscription_id,
            credential=credential,
            region_filter=region_filter,
        )
    )
    findings.extend(
        find_unused_public_ips(
            subscription_id=subscription_id,
            credential=credential,
            region_filter=region_filter,
        )
    )

    return findings


def _print_summary(summary: dict):
    click.echo("\n--- Scan Summary ---")
    click.echo(f"Total findings: {summary['total_findings']}")
    click.echo(f"By risk: {summary.get('by_risk', {})}")
    click.echo(f"By confidence: {summary.get('by_confidence', {})}")
    if "ignored_by_tag_policy" in summary:
        click.echo(f"Ignored by tag policy: {summary['ignored_by_tag_policy']}")
    click.echo(f"Regions scanned: {', '.join(summary.get('regions_scanned', []))}")
    click.echo(f"Scanned at: {summary['scanned_at']}")

    if summary["total_findings"] == 0:
        click.echo("🎉 No hygiene issues detected")


def main():
    cli()


if __name__ == "__main__":
    main()
