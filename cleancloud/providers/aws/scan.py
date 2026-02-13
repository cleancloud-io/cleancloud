from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Tuple

import botocore.exceptions
import click

from cleancloud.core.finding import Finding
from cleancloud.output.progress import advance
from cleancloud.providers.aws.rules.ami_old import find_old_amis
from cleancloud.providers.aws.rules.cloudwatch_inactive import (
    find_inactive_cloudwatch_logs,
)
from cleancloud.providers.aws.rules.ebs_snapshot_old import find_old_ebs_snapshots
from cleancloud.providers.aws.rules.ebs_unattached import find_unattached_ebs_volumes
from cleancloud.providers.aws.rules.elastic_ip_unattached import (
    find_unattached_elastic_ips,
)
from cleancloud.providers.aws.rules.eni_detached import find_detached_enis
from cleancloud.providers.aws.rules.nat_gateway_idle import find_idle_nat_gateways
from cleancloud.providers.aws.rules.rds_idle import find_idle_rds_instances
from cleancloud.providers.aws.rules.untagged_resources import (
    find_untagged_resources as find_aws_untagged_resources,
)
from cleancloud.providers.aws.session import create_aws_session
from cleancloud.providers.aws.validate import validate_region_params

AWS_RULES: List[Callable] = [
    find_unattached_ebs_volumes,
    find_old_ebs_snapshots,
    find_inactive_cloudwatch_logs,
    find_unattached_elastic_ips,
    find_detached_enis,
    find_aws_untagged_resources,
    find_old_amis,
    find_idle_nat_gateways,
    find_idle_rds_instances,
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
        click.echo("Auto-detecting regions with resources...")
        regions_to_scan = _get_active_aws_regions(base_session)

        if regions_to_scan:
            click.echo(f"Found {len(regions_to_scan)} active regions:")
            click.echo(f"   {', '.join(regions_to_scan)}")
            click.echo(
                "   (Regions with EBS volumes, snapshots, logs, Elastic IPs, ENIs, RDS, or NAT Gateways)"
            )
        else:
            click.echo("No active regions detected")
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
    except Exception as e:
        click.echo(f"Failed to list AWS regions: {e}")
        return []

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

    if errors:
        click.echo()
        click.echo(f"Could not check {len(errors)} region(s):")
        for region, error in errors[:5]:
            click.echo(f"   - {region}: {error[:80]}")
        if len(errors) > 5:
            click.echo(f"   ... and {len(errors) - 5} more")
        click.echo()

    return sorted(active_regions)


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

        # 4. Check Elastic IPs
        # DescribeAddresses is non-paginated, returns all EIPs in one call
        addresses = ec2.describe_addresses()
        if addresses["Addresses"]:
            return True, None

        # 5. Check Network Interfaces (ENIs)
        enis = ec2.describe_network_interfaces(MaxResults=5)
        if enis["NetworkInterfaces"]:
            return True, None

        # 6. Check RDS instances
        rds = session.client("rds", region_name=region)
        instances = rds.describe_db_instances(MaxRecords=20)
        if instances["DBInstances"]:
            return True, None

        # 7. Check NAT Gateways
        nat_gws = ec2.describe_nat_gateways(MaxResults=5)
        if nat_gws["NatGateways"]:
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

    with click.progressbar(
        length=len(regions_to_scan),
        label="Scanning AWS regions",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(5, len(regions_to_scan))) as executor:
            futures = {
                executor.submit(_scan_aws_region, profile, region): region
                for region in regions_to_scan
            }

            for future in as_completed(futures):
                region = futures[future]
                try:
                    findings.extend(future.result())
                except RuntimeError as e:
                    # RuntimeError indicates a complete region failure (all rules failed)
                    # This is fatal for explicitly requested regions
                    click.echo(f"Region {region} failed: {e}")
                    advance(bar)
                    raise  # Re-raise to fail the entire scan
                except Exception as e:
                    # Other exceptions might be transient - log and continue
                    click.echo(f"Region {region} failed: {e}")
                    advance(bar)

    return findings


def _scan_aws_region(profile: Optional[str], region: str) -> List[Finding]:
    session = create_aws_session(profile=profile, region=region)
    findings: List[Finding] = []
    rules_succeeded = 0
    rules_failed = 0
    endpoint_errors = 0

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
                    rules_succeeded += 1
                except botocore.exceptions.EndpointConnectionError as e:
                    # Endpoint connection error - likely invalid region
                    rules_failed += 1
                    endpoint_errors += 1
                    click.echo(f"Rule failed in {region}: {e}")
                except Exception as e:
                    # Other errors (permissions, throttling, etc.)
                    rules_failed += 1
                    click.echo(f"Rule failed in {region}: {e}")
                finally:
                    advance(bar)

    # If ALL rules failed due to endpoint errors, this is an invalid region
    if rules_succeeded == 0 and endpoint_errors == rules_failed:
        raise RuntimeError(
            f"Region '{region}' appears to be invalid or inaccessible. "
            f"All {rules_failed} rules failed with endpoint connectivity errors. "
            f"Check that the region name is correct (e.g., us-east-1, eu-west-1)."
        )

    # If ALL rules failed for any reason, something is seriously wrong
    if rules_succeeded == 0 and rules_failed > 0:
        raise RuntimeError(
            f"All {rules_failed} rules failed in region '{region}'. "
            f"This indicates a serious configuration or permissions issue."
        )

    # Ensure region is always set
    for f in findings:
        f.region = region

    return findings
