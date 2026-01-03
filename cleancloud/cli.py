import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

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

        cfg = CleanCloudConfig.empty()
        if config:
            with open(config) as f:
                raw = yaml.safe_load(f) or {}
                cfg = load_config(raw)

        findings: List[Finding] = []

        if provider == "aws":
            base_session = create_aws_session(profile=profile, region="us-east-1")

            # Determine which regions to scan
            if region:
                # Explicit region specified
                regions_to_scan = [region]
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

            findings = scan_aws_regions(profile, regions_to_scan)
            regions_scanned = regions_to_scan

        elif provider == "azure":
            click.echo("🔍 Authenticating to Azure")
            click.echo()

            session = create_azure_session()
            subscription_ids = session.list_subscription_ids()

            if not subscription_ids:
                raise PermissionError("No accessible Azure subscriptions found")

            click.echo(f"✓ Found {len(subscription_ids)} subscription(s)")
            click.echo()

            findings = scan_azure_subscriptions(subscription_ids, session.credential, region)
            click.echo()

            regions_scanned = ["all"] if not region else [region]
            region_selection_mode = "explicit" if region else "all"

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


def scan_aws_regions(
    profile: Optional[str],
    regions_to_scan: List[str],
) -> List[Finding]:
    findings: List[Finding] = []

    with ThreadPoolExecutor(max_workers=min(5, len(regions_to_scan))) as executor:
        futures = {
            executor.submit(_scan_aws_region, profile, region): region for region in regions_to_scan
        }

        for future in as_completed(futures):
            region = futures[future]
            click.echo(f"✅ Completed region {region}")
            click.echo()
            findings.extend(future.result())

    return findings


def scan_azure_subscriptions(
    subscription_ids: List[str],
    credential,
    region_filter: Optional[str],
) -> List[Finding]:
    all_findings: List[Finding] = []

    with click.progressbar(
        length=len(subscription_ids),
        label="Scanning Azure subscriptions",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(4, len(subscription_ids))) as executor:
            futures = {
                executor.submit(
                    _scan_azure_subscription,
                    subscription_id=sub_id,
                    credential=credential,
                    region_filter=region_filter,
                ): sub_id
                for sub_id in subscription_ids
            }

            for future in as_completed(futures):
                sub_id = futures[future]
                click.echo(f"✅ Completed subscription {sub_id}")
                click.echo()
                try:
                    all_findings.extend(future.result())
                except Exception as e:
                    click.echo(f"⚠️ Subscription {sub_id} failed: {e}")
                finally:
                    bar.update(1)

    return all_findings


def _get_active_aws_regions(session) -> List[str]:
    try:
        ec2 = session.client("ec2", region_name="us-east-1")
        response = ec2.describe_regions(
            AllRegions=False,
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}],
        )

        enabled_regions = [r["RegionName"] for r in response["Regions"]]
        active_regions: List[str] = []
        errors: List[Tuple[str, str]] = []

        # Bound concurrency to avoid throttling
        max_workers = min(8, len(enabled_regions))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_region_has_cleancloud_resources, session, region): region
                for region in enabled_regions
            }

            for future in as_completed(futures):
                region = futures[future]
                try:
                    has_resources, error = future.result()
                    if has_resources:
                        active_regions.append(region)
                    elif error:
                        errors.append((region, error))
                except Exception as e:
                    errors.append((region, str(e)))

        # Optional: user-facing error summary (unchanged behaviour)
        if errors:
            import click

            click.echo()
            click.echo(f"⚠️  Could not check {len(errors)} region(s):")
            for region, error in errors[:5]:
                click.echo(f"   • {region}: {error[:80]}")
            if len(errors) > 5:
                click.echo(f"   ... and {len(errors) - 5} more")
            click.echo()

        return sorted(active_regions)

    except Exception:
        return []


def _region_has_cleancloud_resources(session, region: str) -> tuple[bool, Optional[str]]:
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


def _format_enum_counts(data: dict) -> dict[str, int]:
    result = {}
    for key, value in data.items():
        if hasattr(key, "value"):
            result[key.value] = value
        else:
            result[str(key)] = value
    return result


def _print_summary(summary: dict, region_selection_mode: str = None):
    click.echo("\n--- Scan Summary ---")
    click.echo(f"Total findings: {summary['total_findings']}")

    # By risk
    by_risk = _format_enum_counts(summary.get("by_risk", {}))
    if by_risk:
        click.echo("\nBy risk:")
        for risk in sorted(by_risk):
            click.echo(f"  {risk}: {by_risk[risk]}")

    # By confidence
    by_conf = _format_enum_counts(summary.get("by_confidence", {}))
    if by_conf:
        click.echo("\nBy confidence:")
        for conf in sorted(by_conf):
            click.echo(f"  {conf}: {by_conf[conf]}")

    # Regions scanned
    regions_scanned = summary.get("regions_scanned", [])
    if isinstance(regions_scanned, list):
        regions_str = ", ".join(regions_scanned)
    else:
        regions_str = str(regions_scanned)

    click.echo(f"\nRegions scanned: {regions_str}", nl=False)

    if region_selection_mode == "all-regions":
        click.echo(" (auto-detected)")
    elif region_selection_mode == "explicit":
        click.echo(" (explicit)")
    else:
        click.echo()

    click.echo(f"Scanned at: {summary['scanned_at']}")

    # Tag filtering visibility
    if summary.get("ignored_by_tag_policy", 0) > 0:
        click.echo(f"Ignored by tag policy: {summary['ignored_by_tag_policy']}")

    # Success message
    if summary["total_findings"] == 0:
        click.echo()
        click.echo("🎉 No hygiene issues detected")
        click.echo()


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


def _get_all_aws_regions(session) -> List[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in response["Regions"]]


AWS_RULES: List[Callable] = [
    find_unattached_ebs_volumes,
    find_old_ebs_snapshots,
    find_inactive_cloudwatch_logs,
    find_aws_untagged_resources,
]


def _scan_aws_region(profile: Optional[str], region: str) -> List[Finding]:
    session = create_aws_session(profile=profile, region=region)
    findings: List[Finding] = []

    with click.progressbar(
        length=len(AWS_RULES),
        label=f"Scanning AWS rules in {region}",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(4, len(AWS_RULES))) as executor:
            futures = [executor.submit(rule, session, region) for rule in AWS_RULES]

            for future in as_completed(futures):
                try:
                    rule_findings = future.result()
                    findings.extend(rule_findings)
                except Exception as e:
                    # Trust-first: never fail whole scan
                    click.echo(f"⚠️ Rule failed in {region}: {e}")
                finally:
                    bar.update(1)

    # Ensure region is always set
    for f in findings:
        f.region = region

    return findings


AZURE_RULES: List[Callable] = [
    find_unattached_managed_disks,
    find_old_snapshots,
    find_azure_untagged_resources,
    find_unused_public_ips,
]


def _scan_azure_subscription(
    subscription_id: str,
    credential,
    region_filter: Optional[str],
) -> List[Finding]:
    findings: List[Finding] = []

    with click.progressbar(
        length=len(AZURE_RULES),
        label=f"Scanning Azure rules in subscription {subscription_id}",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(4, len(AZURE_RULES))) as executor:
            futures = [
                executor.submit(
                    rule,
                    subscription_id=subscription_id,
                    credential=credential,
                    region_filter=region_filter,
                )
                for rule in AZURE_RULES
            ]

            for future in as_completed(futures):
                try:
                    rule_findings = future.result()
                    findings.extend(rule_findings)
                except Exception as e:
                    # Trust-first: never fail whole scan
                    click.echo(f"⚠️ Azure rule failed in subscription {subscription_id}: {e}")
                finally:
                    bar.update(1)

    return findings


def should_show_feedback(no_feedback: bool) -> bool:
    if no_feedback:
        return False
    if os.getenv("CI", "").lower() == "true":
        return False
    return True


def show_feedback_prompt():
    click.echo()
    click.echo("-" * 70)
    click.echo("CleanCloud feedback")
    click.echo("-" * 70)
    click.echo()
    click.echo("If this scan surfaced useful (or confusing) findings, we'd love to hear about it.")
    click.echo()
    click.echo(
        "Share feedback or feature requests: https://github.com/cleancloud-io/cleancloud/discussions"
    )
    click.echo()
    click.echo("Report any issues: https://github.com/cleancloud-io/cleancloud/issues")
    click.echo()
    click.echo("Or email: suresh@sure360.io")
    click.echo()


def main():
    cli()


if __name__ == "__main__":
    main()
