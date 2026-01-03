from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Tuple

import click

from cleancloud.core.finding import Finding
from cleancloud.providers.aws.rules.cloudwatch_inactive import (
    find_inactive_cloudwatch_logs,
)
from cleancloud.providers.aws.rules.ebs_snapshot_old import find_old_ebs_snapshots
from cleancloud.providers.aws.rules.ebs_unattached import find_unattached_ebs_volumes
from cleancloud.providers.aws.rules.untagged_resources import (
    find_untagged_resources as find_aws_untagged_resources,
)
from cleancloud.providers.aws.session import create_aws_session
from cleancloud.providers.aws.validate import validate_region_params

AWS_RULES: List[Callable] = [
    find_unattached_ebs_volumes,
    find_old_ebs_snapshots,
    find_inactive_cloudwatch_logs,
    find_aws_untagged_resources,
]


def scan_aws_with_region_selection(
    *, profile: Optional[str], region: Optional[str], all_regions: bool
) -> Tuple[str, List[Finding], List[str]]:

    validate_region_params(region, all_regions)

    base_session = create_aws_session(profile=profile, region="us-east-1")

    # Determine which regions to scan
    if region:
        regions_to_scan = [region]
        region_selection_mode = "explicit"

    else:
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

    return region_selection_mode, findings, regions_scanned


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


def _get_all_aws_regions(session) -> List[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in response["Regions"]]


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
