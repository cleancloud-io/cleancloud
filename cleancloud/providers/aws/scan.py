import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple

import botocore.exceptions
import click

from cleancloud.core.finding import Finding
from cleancloud.output.progress import advance
from cleancloud.providers.aws.region_cache import get_cached_regions, set_cached_regions
from cleancloud.providers.aws.rules.ai.bedrock_provisioned_idle import (
    find_idle_bedrock_provisioned_throughputs,
)
from cleancloud.providers.aws.rules.ai.ec2_gpu_idle import find_idle_gpu_instances
from cleancloud.providers.aws.rules.ai.sagemaker_domain_idle import (
    find_idle_sagemaker_domains,
)
from cleancloud.providers.aws.rules.ai.sagemaker_endpoint_idle import (
    find_idle_sagemaker_endpoints,
)
from cleancloud.providers.aws.rules.ai.sagemaker_notebook_idle import (
    find_idle_sagemaker_notebooks,
)
from cleancloud.providers.aws.rules.ai.sagemaker_studio_app_idle import (
    find_idle_sagemaker_studio_apps,
)
from cleancloud.providers.aws.rules.ai.sagemaker_training_job_long_running import (
    find_long_running_sagemaker_training_jobs,
)
from cleancloud.providers.aws.rules.ami_old import find_old_amis
from cleancloud.providers.aws.rules.cloudwatch_logs_no_retention import (
    find_cloudwatch_logs_no_retention,
)
from cleancloud.providers.aws.rules.ebs_snapshot_old import find_old_ebs_snapshots
from cleancloud.providers.aws.rules.ebs_unattached import find_unattached_ebs_volumes
from cleancloud.providers.aws.rules.ec2_sg_unused import find_unused_security_groups
from cleancloud.providers.aws.rules.ec2_stopped import find_stopped_ec2_instances
from cleancloud.providers.aws.rules.elastic_ip_unattached import (
    find_unattached_elastic_ips,
)
from cleancloud.providers.aws.rules.elb_idle import find_idle_load_balancers
from cleancloud.providers.aws.rules.eni_detached import find_detached_enis
from cleancloud.providers.aws.rules.nat_gateway_idle import find_idle_nat_gateways
from cleancloud.providers.aws.rules.rds_idle import find_idle_rds_instances
from cleancloud.providers.aws.rules.rds_snapshot_old import find_old_rds_snapshots
from cleancloud.providers.aws.rules.untagged_resources import (
    find_untagged_resources as find_aws_untagged_resources,
)
from cleancloud.providers.aws.session import BOTO_CONFIG, create_aws_session
from cleancloud.providers.aws.validate import validate_region_params

AWS_RULE_MAP: Dict[str, Callable] = {
    "aws.ebs.unattached": find_unattached_ebs_volumes,
    "aws.ebs.snapshot.old": find_old_ebs_snapshots,
    "aws.cloudwatch.logs.infinite_retention": find_cloudwatch_logs_no_retention,
    "aws.ec2.elastic_ip.unattached": find_unattached_elastic_ips,
    "aws.ec2.eni.detached": find_detached_enis,
    "aws.resource.untagged": find_aws_untagged_resources,
    "aws.ec2.ami.old": find_old_amis,
    "aws.ec2.nat_gateway.idle": find_idle_nat_gateways,
    "aws.rds.instance.idle": find_idle_rds_instances,
    "aws.elbv2.load_balancer.idle": find_idle_load_balancers,  # aggregate key — params/enabled only
    "aws.elbv2.alb.idle": find_idle_load_balancers,  # split IDs for exceptions/filters
    "aws.elbv2.nlb.idle": find_idle_load_balancers,
    "aws.elb.clb.idle": find_idle_load_balancers,
    "aws.ec2.instance.stopped": find_stopped_ec2_instances,
    "aws.ec2.security_group.unused": find_unused_security_groups,
    "aws.rds.snapshot.old": find_old_rds_snapshots,
}

AWS_RULE_MAP_AI: Dict[str, Callable] = {
    "aws.sagemaker.endpoint.idle": find_idle_sagemaker_endpoints,
    "aws.sagemaker.notebook.idle": find_idle_sagemaker_notebooks,
    "aws.sagemaker.domain.idle": find_idle_sagemaker_domains,
    "aws.ec2.gpu.idle": find_idle_gpu_instances,
    "aws.bedrock.provisioned_throughput.idle": find_idle_bedrock_provisioned_throughputs,
    "aws.sagemaker.studio_app.idle": find_idle_sagemaker_studio_apps,
    "aws.sagemaker.training_job.long_running": find_long_running_sagemaker_training_jobs,
}

AWS_RULES: List[Callable] = list(dict.fromkeys(AWS_RULE_MAP.values()))

# AI/ML waste rules — not run by default; use --category ai or --category all
AWS_AI_RULES: List[Callable] = list(AWS_RULE_MAP_AI.values())


def _unwrap_rule_callable(rule: Callable) -> Callable:
    while isinstance(rule, functools.partial):
        rule = rule.func
    return rule


def _rule_name(rule: Callable) -> str:
    return getattr(
        rule, "__name__", getattr(_unwrap_rule_callable(rule), "__name__", "unknown_rule")
    )


def rules_include_ai(rules: Optional[List[Callable]]) -> bool:
    if rules is None:
        return True
    ai_rules = set(AWS_AI_RULES)
    return any(_unwrap_rule_callable(rule) in ai_rules for rule in rules)


def scan_aws_with_region_selection(
    *,
    profile: Optional[str],
    region: Optional[str],
    all_regions: bool,
    rules: Optional[List[Callable]] = None,
) -> Tuple[str, List[Finding], List[str], List[dict]]:

    validate_region_params(region, all_regions)

    base_session = create_aws_session(profile=profile, region="us-east-1")

    # Pre-flight: one STS call to verify credentials before spawning threads.
    # Cheaper than letting 10 rules fail in parallel with the same root cause.
    try:
        base_session.client("sts").get_caller_identity()
    except botocore.exceptions.NoCredentialsError:
        raise
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidClientTokenId", "AuthFailure", "ExpiredTokenException"):
            raise botocore.exceptions.NoCredentialsError()

    # Determine which regions to scan
    if region:
        regions_to_scan = [region]
        region_selection_mode = "explicit"

    else:
        click.echo("Auto-detecting regions with resources...")
        # rules=None means "run everything" — include AI probes so
        # Bedrock/SageMaker-only regions are not skipped during auto-discovery.
        include_ai = rules_include_ai(rules)
        regions_to_scan = _get_active_aws_regions(base_session, include_ai=include_ai)

        if regions_to_scan:
            click.echo(f"Found {len(regions_to_scan)} active regions:")
            click.echo(f"   {', '.join(regions_to_scan)}")
            if include_ai:
                click.echo(
                    "   (Regions with EBS volumes, snapshots, logs, Elastic IPs, ENIs, RDS, "
                    "NAT Gateways, ELBs, SageMaker endpoints/notebooks, or Bedrock provisioned throughputs)"
                )
            else:
                click.echo(
                    "   (Regions with EBS volumes, snapshots, logs, Elastic IPs, ENIs, RDS, NAT Gateways, or ELBs)"
                )
        else:
            click.echo("No active regions detected")
            click.echo("   Falling back to us-east-1")
            regions_to_scan = ["us-east-1"]

        region_selection_mode = "all-regions"

    click.echo()

    findings, skipped_rules = scan_aws_regions(profile, regions_to_scan, rules=rules)
    regions_scanned = regions_to_scan

    return region_selection_mode, findings, regions_scanned, skipped_rules


def _get_active_aws_regions(session, include_ai: bool = False) -> List[str]:
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        cached = get_cached_regions(account_id, include_ai=include_ai)
        if cached is not None:
            click.echo(
                f"Using cached regions (account {account_id}) — delete ~/.cleancloud/region_cache.json to refresh"
            )
            return cached
    except Exception:
        account_id = None

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
            executor.submit(_region_has_cleancloud_resources, session, region, include_ai): region
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

    result = sorted(active_regions)
    if account_id and result and not errors:
        try:
            set_cached_regions(account_id, result, include_ai=include_ai)
        except OSError:
            pass  # cache write failure is non-fatal

    return result


def _region_has_cleancloud_resources(
    session, region: str, include_ai: bool = False
) -> tuple[bool, Optional[str]]:
    try:
        ec2 = session.client("ec2", region_name=region, config=BOTO_CONFIG)

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
        logs = session.client("logs", region_name=region, config=BOTO_CONFIG)
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
        rds = session.client("rds", region_name=region, config=BOTO_CONFIG)
        instances = rds.describe_db_instances(MaxRecords=20)
        if instances["DBInstances"]:
            return True, None

        # 7. Check NAT Gateways
        nat_gws = ec2.describe_nat_gateways(MaxResults=5)
        if nat_gws["NatGateways"]:
            return True, None

        # 8. Check Elastic Load Balancers (ALB/NLB)
        elbv2 = session.client("elbv2", region_name=region, config=BOTO_CONFIG)
        lbs = elbv2.describe_load_balancers(PageSize=1)
        if lbs.get("LoadBalancers"):
            return True, None

        # AI resource probes — only when running AI/ML rules.
        # Wrapped individually so a missing permission for one service doesn't
        # prevent the other from being checked.
        if include_ai:
            # 9. Check SageMaker endpoints
            try:
                sagemaker = session.client("sagemaker", region_name=region, config=BOTO_CONFIG)
                endpoints = sagemaker.list_endpoints(MaxResults=1)
                if endpoints.get("Endpoints"):
                    return True, None
                notebooks = sagemaker.list_notebook_instances(MaxResults=1)
                if notebooks.get("NotebookInstances"):
                    return True, None
                apps = sagemaker.list_apps(MaxResults=1)
                if apps.get("Apps"):
                    return True, None
            except Exception:
                pass  # no SageMaker perms or service not available in region — skip

            # 10. Check Bedrock provisioned throughputs
            try:
                bedrock = session.client("bedrock", region_name=region, config=BOTO_CONFIG)
                response = bedrock.list_provisioned_model_throughputs(statusEquals="InService")
                if response.get("provisionedModelSummaries"):
                    return True, None
            except Exception:
                pass  # no Bedrock perms or service not available in region — skip

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
    rules: Optional[List[Callable]] = None,
) -> Tuple[List[Finding], List[dict]]:
    active_rules = rules if rules is not None else AWS_RULES
    findings: List[Finding] = []
    all_skipped_rules: List[dict] = []

    with click.progressbar(
        length=len(regions_to_scan),
        label="Scanning AWS regions",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(5, len(regions_to_scan))) as executor:
            futures = {
                executor.submit(_scan_aws_region, profile, region, active_rules): region
                for region in regions_to_scan
            }

            for future in as_completed(futures):
                region = futures[future]
                try:
                    region_findings, region_skipped = future.result()
                    findings.extend(region_findings)
                    # Deduplicate skipped rules across regions
                    for skipped in region_skipped:
                        if not any(s["rule"] == skipped["rule"] for s in all_skipped_rules):
                            all_skipped_rules.append(skipped)
                except botocore.exceptions.NoCredentialsError:
                    # Credentials missing or expired — re-raise to fail the scan fast.
                    raise
                except Exception as e:
                    # Any other region-level error: log and continue scanning remaining regions
                    click.echo(f"Region {region} failed: {e}")
                finally:
                    advance(bar)

    return findings, all_skipped_rules


def scan_aws_regions_with_session(
    session,
    regions_to_scan: List[str],
    rules: Optional[List[Callable]] = None,
) -> Tuple[List[Finding], List[dict], List[str]]:
    """
    Scan a list of regions using a pre-existing boto3 session (e.g. assumed role).
    Used by multi-account scanning. No progress bars — account-level logging handles UX.
    Returns (findings, skipped_rules, failed_regions).
    """
    active_rules = rules if rules is not None else AWS_RULES
    findings: List[Finding] = []
    all_skipped_rules: List[dict] = []
    failed_regions: List[str] = []

    with ThreadPoolExecutor(max_workers=min(5, len(regions_to_scan))) as executor:
        futures = {
            executor.submit(_scan_aws_region_with_session, session, region, active_rules): region
            for region in regions_to_scan
        }
        for future in as_completed(futures):
            region = futures[future]
            try:
                region_findings, region_skipped = future.result()
                findings.extend(region_findings)
                for skipped in region_skipped:
                    if not any(s["rule"] == skipped["rule"] for s in all_skipped_rules):
                        all_skipped_rules.append(skipped)
            except Exception as e:
                click.echo(f"  Region {region} failed: {e}")
                failed_regions.append(region)

    return findings, all_skipped_rules, failed_regions


def _scan_aws_region_with_session(
    session, region: str, rules: List[Callable]
) -> Tuple[List[Finding], List[dict]]:
    """
    Scan a single region using a pre-existing session. Used for assumed-role
    (multi-account) scans where the session is already scoped to the target account.
    """
    findings: List[Finding] = []
    skipped_rules: List[dict] = []

    with ThreadPoolExecutor(max_workers=min(4, len(rules))) as executor:
        futures = {executor.submit(rule, session, region): rule for rule in rules}

        for future in as_completed(futures):
            rule = futures[future]
            rule_name = _rule_name(rule)
            try:
                rule_findings = future.result()
                findings.extend(rule_findings)
            except botocore.exceptions.NoCredentialsError:
                raise
            except PermissionError as e:
                skipped_rules.append({"rule": rule_name, "missing_permissions": str(e)})
            except botocore.exceptions.EndpointConnectionError as e:
                skipped_rules.append({"rule": rule_name, "error": f"EndpointConnectionError: {e}"})
            except Exception as e:
                skipped_rules.append({"rule": rule_name, "error": f"{type(e).__name__}: {e}"})
                click.echo(f"    Rule {rule_name} failed in {region}: {type(e).__name__}: {e}")

    for f in findings:
        f.region = region

    return findings, skipped_rules


def _scan_aws_region(
    profile: Optional[str], region: str, rules: List[Callable]
) -> Tuple[List[Finding], List[dict]]:
    session = create_aws_session(profile=profile, region=region)
    findings: List[Finding] = []
    skipped_rules: List[dict] = []
    rules_succeeded = 0
    rules_failed = 0
    endpoint_errors = 0

    with click.progressbar(
        length=len(rules),
        label=f"Scanning AWS rules in {region}",
        show_eta=True,
        show_percent=True,
    ) as bar:
        with ThreadPoolExecutor(max_workers=min(4, len(rules))) as executor:
            futures = {executor.submit(rule, session, region): rule for rule in rules}

            for future in as_completed(futures):
                rule = futures[future]
                rule_name = _rule_name(rule)
                try:
                    rule_findings = future.result()
                    findings.extend(rule_findings)
                    rules_succeeded += 1
                except botocore.exceptions.NoCredentialsError:
                    # Credentials missing or expired mid-scan — re-raise immediately.
                    # The pre-flight check should have caught this; if we're here,
                    # the token expired during the scan. Don't swallow it.
                    raise
                except PermissionError as e:
                    # Graceful degradation — missing permissions skip this rule
                    skipped_rules.append({"rule": rule_name, "missing_permissions": str(e)})
                except botocore.exceptions.EndpointConnectionError as e:
                    rules_failed += 1
                    endpoint_errors += 1
                    skipped_rules.append(
                        {"rule": rule_name, "error": f"EndpointConnectionError: {e}"}
                    )
                    click.echo(f"Rule failed in {region} [{rule_name}]: {e}")
                except Exception as e:
                    rules_failed += 1
                    skipped_rules.append({"rule": rule_name, "error": f"{type(e).__name__}: {e}"})
                    click.echo(f"Rule failed in {region} [{rule_name}]: {type(e).__name__}: {e}")
                finally:
                    advance(bar)

    if rules_succeeded == 0 and endpoint_errors == rules_failed and rules_failed > 0:
        click.echo(
            f"Warning: region '{region}' may be invalid or inaccessible — "
            f"all {rules_failed} rules failed with endpoint connectivity errors."
        )

    # Ensure region is always set
    for f in findings:
        f.region = region

    return findings, skipped_rules
