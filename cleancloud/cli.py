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
from cleancloud.doctor import run_doctor
from cleancloud.exit_policy import (
    EXIT_ERROR,
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


@cli.command()
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
    """
    Scan cloud infrastructure for orphaned and untagged resources.

    AWS: Must specify EITHER --region OR --all-regions
    Azure: No region required (scans all subscriptions, optionally filter by location)

    Examples:
        # AWS - specific region
        cleancloud scan --provider aws --region us-east-1

        # AWS - all active regions
        cleancloud scan --provider aws --all-regions

        # Azure - all subscriptions
        cleancloud scan --provider azure

        # Azure - filter by location
        cleancloud scan --provider azure --region eastus
    """
    click.echo("🔍 Starting CleanCloud scan")
    click.echo(f"Provider: {provider}")
    click.echo()

    try:
        # ========================
        # Validate region arguments (AWS only)
        # ========================
        if provider == "aws":
            # AWS requires explicit region choice
            if not region and not all_regions:
                click.echo("❌ Error: Must specify either --region or --all-regions for AWS")
                click.echo()
                click.echo("Examples:")
                click.echo("  cleancloud scan --provider aws --region us-east-1")
                click.echo("  cleancloud scan --provider aws --all-regions")
                click.echo()
                click.echo("💡 Tip: Use --all-regions to automatically detect and scan")
                click.echo("   regions with resources (volumes, snapshots, logs)")
                sys.exit(EXIT_ERROR)

            if region and all_regions:
                click.echo("❌ Error: Cannot specify both --region and --all-regions")
                click.echo()
                click.echo("Choose one:")
                click.echo("  --region us-east-1        # Scan specific region")
                click.echo("  --all-regions             # Scan all active regions")
                sys.exit(EXIT_ERROR)

        # Note: Azure doesn't require region validation
        # Azure scans all subscriptions by default, region is optional filter

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

            # Determine which regions to scan
            if region:
                # Explicit region specified
                regions_to_scan = [region]
                click.echo(f"🎯 Scanning region: {region}")
                region_selection_mode = "explicit"

            else:
                # --all-regions: Auto-detect active regions
                click.echo("🔍 Auto-detecting regions with resources...")
                regions_to_scan = _get_active_aws_regions(base_session)

                if regions_to_scan:
                    click.echo(f"✓ Found {len(regions_to_scan)} active regions:")
                    click.echo(f"   {', '.join(regions_to_scan)}")
                    click.echo("   (Regions with EBS volumes, snapshots, or logs)")
                else:
                    click.echo("⚠️  No active regions detected")
                    click.echo("   Falling back to us-east-1")
                    regions_to_scan = ["us-east-1"]

                region_selection_mode = "all-regions"

            click.echo()

            # Scan each region
            for r in regions_to_scan:
                click.echo(f"🔍 Scanning region {r}")
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

            click.echo(f"✓ Found {len(subscription_ids)} subscription(s)")
            click.echo()

            for sub_id in subscription_ids:
                click.echo(f"📦 Subscription {sub_id}")
                findings.extend(
                    _scan_azure_subscription(
                        subscription_id=sub_id,
                        credential=session.credential,
                        region_filter=region,
                    )
                )

            regions_scanned = ["all"] if not region else [region]
            region_selection_mode = "explicit" if region else "all"

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

        elif output == "csv":
            write_csv(findings, output_path)
            click.echo(f"✓ CSV output written to {output_path}")

        else:
            print_human(findings)
            _print_summary(summary, region_selection_mode)

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
# Helper: Get active AWS regions (comprehensive check)
# ========================
def _get_active_aws_regions(session) -> List[str]:
    """
    Auto-detect AWS regions that have resources CleanCloud scans.

    Only called when user specifies --all-regions flag.

    Checks multiple resource types:
    - EBS volumes (unattached volumes rule)
    - EBS snapshots (old snapshots rule)
    - CloudWatch Logs (infinite retention rule)

    Returns:
        List of region names with resources
    """
    try:
        # Get all enabled regions
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.describe_regions(
            AllRegions=False,
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}],
        )

        enabled_regions = [r["RegionName"] for r in response["Regions"]]
        active_regions = []
        errors = []

        # Check each region for CleanCloud-scanned resources
        for region in enabled_regions:
            has_resources, error = _region_has_cleancloud_resources(session, region)

            if has_resources:
                active_regions.append(region)
            elif error:
                # Track errors for reporting
                errors.append((region, error))

        # Report any errors found
        if errors:
            import click

            click.echo()
            click.echo(f"⚠️  Could not check {len(errors)} region(s):")
            for region, error in errors[:5]:  # Show first 5
                click.echo(f"   • {region}: {error[:80]}")
            if len(errors) > 5:
                click.echo(f"   ... and {len(errors) - 5} more")
            click.echo()

        return active_regions

    except Exception:
        # If auto-detection fails, return empty list
        return []


def _region_has_cleancloud_resources(session, region: str) -> tuple[bool, Optional[str]]:
    """
    Check if region has any resources that CleanCloud scans.

    Checks all CleanCloud rules:
    1. EBS volumes (unattached volumes rule)
    2. EBS snapshots (old snapshots rule)
    3. CloudWatch Logs (infinite retention rule)

    Returns:
        Tuple of (has_resources, error_message)
        - (True, None) = Has resources
        - (False, None) = No resources found (empty region)
        - (False, "error message") = Error checking region
    """
    try:
        ec2 = session.client("ec2", region_name=region)

        # 1. Check EBS volumes
        # Note: Use MaxResults=5 - some regions don't accept MaxResults=1
        volumes = ec2.describe_volumes(MaxResults=5)
        if volumes["Volumes"]:
            return True, None

        # 2. Check EBS snapshots (owned by this account)
        # Note: AWS requires MaxResults >= 5 for snapshots
        snapshots = ec2.describe_snapshots(OwnerIds=["self"], MaxResults=5)
        if snapshots["Snapshots"]:
            return True, None

        # 3. Check CloudWatch Logs
        logs = session.client("logs", region_name=region)
        log_groups = logs.describe_log_groups(limit=1)
        if log_groups["logGroups"]:
            return True, None

        # No resources found - this is OK, just an empty region
        return False, None

    except Exception as e:
        # Error checking region - could be permissions, throttling, etc.
        error_msg = str(e)

        # Check if it's a permission/auth error
        if any(
            keyword in error_msg.lower()
            for keyword in [
                "unauthorized",
                "access denied",
                "forbidden",
                "credentials",
                "authentication",
                "not authorized",
            ]
        ):
            return False, f"Permission error: {error_msg}"

        # Other errors (throttling, network, etc.)
        return False, f"Error: {error_msg}"


def _print_summary(summary: dict, region_selection_mode: str = None):
    """Print scan summary with region selection context."""
    click.echo("\n--- Scan Summary ---")
    click.echo(f"Total findings: {summary['total_findings']}")
    click.echo(f"By risk: {summary['by_risk']}")
    click.echo(f"By confidence: {summary['by_confidence']}")

    regions_scanned = summary.get("regions_scanned", [])
    if isinstance(regions_scanned, list):
        regions_str = ", ".join(regions_scanned)
    else:
        regions_str = str(regions_scanned)

    click.echo(f"Regions scanned: {regions_str}", nl=False)

    # Add context about region selection
    if region_selection_mode == "all-regions":
        click.echo(" (auto-detected)")
    elif region_selection_mode == "explicit":
        click.echo(" (explicit)")
    else:
        click.echo()

    click.echo(f"Scanned at: {summary['scanned_at']}")

    if summary.get("ignored_by_tag_policy", 0) > 0:
        click.echo(f"Ignored by tag policy: {summary['ignored_by_tag_policy']}")

    if summary["total_findings"] == 0:
        click.echo("🎉 No hygiene issues detected")


# ========================
# Doctor Command
# ========================
@cli.command()
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["aws", "azure"]),
    help="Cloud provider to validate (omit to check both)",
)
@click.option("--region", default="us-east-1", help="AWS region for validation")
@click.option("--profile", default=None, help="AWS profile name")
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to cleancloud.yaml",
)
def doctor(provider: Optional[str], region: str, profile: Optional[str], config: Optional[str]):
    """
    Validate cloud credentials and permissions.

    Examples:
        cleancloud doctor                    # Check both AWS and Azure
        cleancloud doctor --provider aws     # Check AWS only
        cleancloud doctor --provider azure   # Check Azure only
    """
    click.echo("🩺 Running CleanCloud doctor")
    click.echo()

    run_doctor(provider=provider, profile=profile, region=region)

    try:
        cfg = CleanCloudConfig.empty()
        if config:
            with open(config) as f:
                raw = yaml.safe_load(f) or {}
                cfg = load_config(raw)

        if cfg.tag_filtering and cfg.tag_filtering.enabled:
            click.echo()
            click.echo("ℹ️  Tag filtering is enabled — some findings may be intentionally ignored")
            click.echo()

    except Exception as e:
        # Config validation failure is not fatal for doctor command
        click.echo(f"⚠️  Config validation warning: {e}")
        click.echo()


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


def main():
    cli()


if __name__ == "__main__":
    main()
