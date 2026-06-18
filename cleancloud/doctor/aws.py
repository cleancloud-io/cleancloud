import os
import sys
from typing import Optional

import botocore.exceptions
import click

from cleancloud.config.accounts import MultiAccountConfig
from cleancloud.doctor.common import fail, info, success, warn
from cleancloud.policy.exit_policy import EXIT_ERROR
from cleancloud.providers.aws.session import (
    BOTO_CONFIG,
    assume_role,
    create_aws_session,
)
from cleancloud.providers.aws.validate import KNOWN_AWS_REGIONS


def detect_aws_auth_method(session) -> tuple[str, str, dict]:
    try:
        credentials = session.get_credentials()

        if credentials is None:
            return "none", "No credentials found", {}

        # Get what boto3 ACTUALLY used (not just env vars)
        provider_name = credentials.method

        # Determine if credentials are temporary
        is_temporary = hasattr(credentials, "token") and credentials.token is not None

        metadata = {
            "provider_name": provider_name,
            "is_temporary": is_temporary,
            "recommended": False,
            "ci_cd_ready": False,
            "security_grade": "unknown",
        }

        # OIDC / Web Identity (GitHub Actions, GitLab CI, EKS)
        if provider_name == "assume-role-with-web-identity":
            metadata.update(
                {
                    "recommended": True,
                    "ci_cd_ready": True,
                    "security_grade": "excellent",
                    "credential_lifetime": "1 hour (temporary)",
                    "rotation_required": False,
                }
            )
            return "oidc", "OIDC (AssumeRoleWithWebIdentity)", metadata

        # EC2 Instance Profile
        elif provider_name == "iam-role":
            metadata.update(
                {
                    "recommended": True,
                    "ci_cd_ready": False,
                    "security_grade": "excellent",
                    "credential_lifetime": "temporary (auto-rotated)",
                    "rotation_required": False,
                }
            )
            return "instance_profile", "EC2 Instance Profile", metadata

        # ECS Task Role
        elif provider_name == "container-role":
            metadata.update(
                {
                    "recommended": True,
                    "ci_cd_ready": False,
                    "security_grade": "excellent",
                    "credential_lifetime": "temporary (auto-rotated)",
                    "rotation_required": False,
                }
            )
            return "ecs_task_role", "ECS Task Role", metadata

        # AssumeRole (cross-account or role switching)
        elif provider_name == "assume-role":
            metadata.update(
                {
                    "recommended": True,
                    "ci_cd_ready": True,
                    "security_grade": "good",
                    "credential_lifetime": "1-12 hours (temporary)",
                    "rotation_required": False,
                }
            )
            return "assume_role", "AssumeRole (IAM Role)", metadata

        # AWS CLI Profile (~/.aws/credentials)
        elif provider_name == "shared-credentials-file":
            profile = os.getenv("AWS_PROFILE", "default")
            metadata.update(
                {
                    "recommended": False,
                    "ci_cd_ready": False,
                    "security_grade": "acceptable",
                    "credential_lifetime": "long-lived (access keys)",
                    "rotation_required": True,
                    "profile_name": profile,
                }
            )
            return "profile", f"AWS CLI Profile ({profile})", metadata

        # Environment variables (AWS_ACCESS_KEY_ID/SECRET)
        elif provider_name == "env":
            if is_temporary:
                metadata.update(
                    {
                        "recommended": True,
                        "ci_cd_ready": True,
                        "security_grade": "good",
                        "credential_lifetime": "temporary (with session token)",
                        "rotation_required": False,
                    }
                )
                return "temporary_keys", "Temporary Credentials (Environment)", metadata
            else:
                metadata.update(
                    {
                        "recommended": False,
                        "ci_cd_ready": False,
                        "security_grade": "poor",
                        "credential_lifetime": "long-lived (access keys)",
                        "rotation_required": True,
                        "rotation_interval": "90 days",
                    }
                )
                return "static_keys", "Static Access Keys (Environment)", metadata

        # Explicitly configured credentials
        elif provider_name in ("explicit", "static"):
            if is_temporary:
                metadata.update(
                    {
                        "recommended": True,
                        "ci_cd_ready": True,
                        "security_grade": "good",
                        "credential_lifetime": "temporary",
                        "rotation_required": False,
                    }
                )
                return "temporary_keys", "Temporary Credentials", metadata
            else:
                metadata.update(
                    {
                        "recommended": False,
                        "ci_cd_ready": False,
                        "security_grade": "poor",
                        "credential_lifetime": "long-lived",
                        "rotation_required": True,
                    }
                )
                return "static_keys", "Static Access Keys", metadata

        # Unknown/other
        else:
            metadata.update(
                {
                    "recommended": False,
                    "ci_cd_ready": False,
                    "security_grade": "unknown",
                }
            )
            return "unknown", f"Other ({provider_name})", metadata

    except Exception as e:
        return "error", f"Error detecting method: {e}", {"error": str(e)}


def run_aws_doctor(profile: Optional[str], region: Optional[str] = None) -> None:
    if region is None:
        region = "us-east-1"

    # Validate region before proceeding
    if region not in KNOWN_AWS_REGIONS:
        click.echo(f"Error: '{region}' is not a valid AWS region")
        click.echo()
        click.echo("Common AWS regions:")
        click.echo("  us-east-1, us-east-2, us-west-1, us-west-2")
        click.echo("  eu-west-1, eu-central-1, ap-southeast-1, ap-northeast-1")
        click.echo()
        click.echo("All known regions:")
        regions_list = sorted(KNOWN_AWS_REGIONS)
        for i in range(0, len(regions_list), 4):
            click.echo("  " + ", ".join(regions_list[i : i + 4]))
        click.echo()
        click.echo("Tip: Doctor validates credentials using a single region")
        click.echo("   Default region is us-east-1 if not specified")
        sys.exit(EXIT_ERROR)

    info("")
    info("=" * 70)
    info("AWS ENVIRONMENT VALIDATION")
    info("=" * 70)
    info("")

    # Step 1: Create session
    info("Step 1: AWS Credential Resolution")
    info("-" * 70)

    try:
        session = create_aws_session(profile=profile, region=region)
        success("AWS session created successfully")
    except Exception as e:
        fail(f"Failed to create AWS session: {e}")

    # Step 2: Detect authentication method
    info("")
    info("Step 2: Authentication Method Detection")
    info("-" * 70)

    method_id, description, metadata = detect_aws_auth_method(session)

    # Display auth method with context
    info(f"Authentication Method: {description}")

    if method_id == "none":
        info("")
        warn("No AWS credentials found. CleanCloud cannot run without credentials.")
        info("")
        info("To configure credentials, choose one of:")
        info("  - AWS CloudShell: credentials are injected automatically from your portal session")
        info("  - Local AWS CLI:  run `aws configure` or set AWS_PROFILE")
        info("  - CI/CD (OIDC):   see docs/aws.md for OIDC role setup")
        info("  - Environment:    set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN")
        info("")
        info("Permissions required (attach to your IAM role or user):")
        info("  ec2:DescribeVolumes")
        info("  ec2:DescribeSnapshots")
        info("  ec2:DescribeSnapshotAttribute")
        info("  ec2:DescribeRegions")
        info("  ec2:DescribeAddresses")
        info("  ec2:DescribeNetworkInterfaces")
        info("  ec2:DescribeImages")
        info("  ec2:DescribeNatGateways")
        info("  ec2:DescribeInstances")
        info("  ec2:DescribeSecurityGroups")
        info("  rds:DescribeDBInstances")
        info("  rds:DescribeDBSnapshots")
        info("  rds:DescribeDBSnapshotAttributes")
        info("  cloudtrail:LookupEvents")
        info("  redshift:DescribeClusters")
        info("  es:ListDomainNames")
        info("  es:DescribeDomain")
        info("  elasticloadbalancing:DescribeLoadBalancers")
        info("  elasticloadbalancing:DescribeTargetGroups")
        info("  logs:DescribeLogGroups")
        info("  cloudwatch:GetMetricStatistics")
        info("  s3:ListAllMyBuckets")
        info("  s3:GetBucketTagging")
        info("  sts:GetCallerIdentity")
        info("")
        info("Copy the ready-to-use IAM policies from:")
        info("  security/aws/base-readonly.json     (required for all scans)")
        info("  security/aws/hygiene-readonly.json  (hygiene rules, default)")
        info("  or: docs/aws.md (full setup guide with OIDC)")
        fail("No credentials — configure AWS access and re-run doctor")

    if metadata.get("provider_name"):
        info(f"  Boto3 Provider: {metadata['provider_name']}")

    if metadata.get("is_temporary") is not None:
        credential_type = "Temporary" if metadata["is_temporary"] else "Long-lived"
        info(f"  Credential Type: {credential_type}")

    if metadata.get("credential_lifetime"):
        info(f"  Lifetime: {metadata['credential_lifetime']}")

    if metadata.get("rotation_required"):
        info(f"  Rotation Required: Yes (every {metadata.get('rotation_interval', '90 days')})")
    else:
        info("  Rotation Required: No (auto-rotated)")

    # Security assessment
    info("")
    security_grade = metadata.get("security_grade", "unknown")

    if security_grade == "excellent":
        success("Security Grade: EXCELLENT")
        success("  - Temporary credentials")
        success("  - Auto-rotated")
        success("  - No secret storage required")

    elif security_grade == "good":
        success("Security Grade: GOOD")
        info("  - Temporary credentials")
        if not metadata.get("rotation_required"):
            info("  - Auto-rotated")

    elif security_grade == "acceptable":
        warn("Security Grade: ACCEPTABLE")
        warn("  - Long-lived credentials")
        warn("  - Manual rotation required")
        info("")
        info("  Recommendation for local development:")
        info("    Current setup is acceptable")

    elif security_grade == "poor":
        warn("Security Grade: POOR")
        warn("  - Long-lived access keys")
        warn("  - Requires 90-day rotation")
        warn("  - High blast radius if compromised")
        info("")
        info("  Recommendation for CI/CD:")
        info("    Switch to OIDC (OpenID Connect)")
        info("    See: https://docs.cleancloud.io/aws#oidc")

    else:
        info(f"Security Grade: {security_grade.upper()}")

    # CI/CD readiness
    info("")
    if metadata.get("ci_cd_ready"):
        success("CI/CD Ready: YES")
        # Safety guarantees (informational only)
        info("")
        info("CleanCloud Safety Guarantees")
        info("-" * 70)
        success("- Read-only operations only")
        success("- No resource creation, modification, or deletion")
        success("- Only Describe / List / Get APIs invoked")
        success("- Enforced by CI safety regression tests")

        success("  Suitable for production CI/CD pipelines")
    else:
        if method_id == "profile":
            info("CI/CD Ready: NO (Local development only)")
            info("AWS CLI profiles are not available in CI/CD")
        else:
            warn("CI/CD Ready: NO")
            warn("Not recommended for automated pipelines")

    # Compliance notes
    info("")
    if metadata.get("security_grade") in ("excellent", "good"):
        success("Compliance: SOC2/ISO27001 Compatible")
    elif metadata.get("security_grade") == "acceptable":
        info("Compliance: Acceptable for development environments")
    else:
        warn("Compliance: May not meet enterprise security requirements")

    # Step 3: Identity verification
    info("")
    info("Step 3: Identity Verification")
    info("-" * 70)

    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
    except Exception as e:
        fail(f"AWS identity verification failed: {e}")

    arn = identity["Arn"]
    account = identity["Account"]
    user_id = identity["UserId"]

    success(f"Account ID: {account}")
    success(f"User ID: {user_id}")
    success(f"ARN: {arn}")

    # Parse ARN for additional context
    if ":assumed-role/" in arn:
        role_name = arn.split("/")[-2]
        session_name = arn.split("/")[-1]
        info(f"  Role Name: {role_name}")
        info(f"  Session Name: {session_name}")

        # Check if it's OIDC-based role
        if method_id == "oidc":
            success("  - OIDC-based assumed role (recommended)")

    elif ":user/" in arn:
        user_name = arn.split("/")[-1]
        info(f"  IAM User: {user_name}")

        if method_id == "static_keys":
            warn("  - Using IAM user credentials (not recommended for CI/CD)")

    # Region scope clarification
    info("")
    info("Region Scope")
    info("-" * 70)
    info(f"Active Region: {region}")
    info("Doctor validates permissions for the active region only")
    info("Use 'cleancloud scan --provider aws --all-regions' to scan all active regions")

    # Step 4: Permission validation
    info("")
    info("Step 4: Read-Only Permission Validation")
    info("-" * 70)

    permissions_tested = []
    permissions_failed = []

    try:
        ec2 = session.client("ec2", region_name=region)

        # Test EC2 permissions
        try:
            ec2.describe_volumes(MaxResults=6)
            permissions_tested.append("ec2:DescribeVolumes")
            success("ec2:DescribeVolumes")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeVolumes", str(e)))
            warn(f"ec2:DescribeVolumes - {e}")

        try:
            ec2.describe_snapshots(OwnerIds=["self"], MaxResults=5)
            permissions_tested.append("ec2:DescribeSnapshots")
            success("ec2:DescribeSnapshots")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeSnapshots", str(e)))
            warn(f"ec2:DescribeSnapshots - {e}")

        try:
            _snaps = ec2.describe_snapshots(OwnerIds=["self"], MaxResults=5).get("Snapshots", [])
            if _snaps:
                ec2.describe_snapshot_attribute(
                    SnapshotId=_snaps[0]["SnapshotId"], Attribute="createVolumePermission"
                )
            permissions_tested.append("ec2:DescribeSnapshotAttribute")
            success("ec2:DescribeSnapshotAttribute")
        except Exception as e:
            if "AccessDenied" in str(e) or "not authorized" in str(e).lower():
                permissions_failed.append(("ec2:DescribeSnapshotAttribute", str(e)))
                warn(f"ec2:DescribeSnapshotAttribute - {e}")
            else:
                permissions_tested.append("ec2:DescribeSnapshotAttribute")
                success("ec2:DescribeSnapshotAttribute")

        try:
            ec2.describe_regions()
            permissions_tested.append("ec2:DescribeRegions")
            success("ec2:DescribeRegions")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeRegions", str(e)))
            warn(f"ec2:DescribeRegions - {e}")

        try:
            ec2.describe_addresses()
            permissions_tested.append("ec2:DescribeAddresses")
            success("ec2:DescribeAddresses")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeAddresses", str(e)))
            warn(f"ec2:DescribeAddresses - {e}")

        try:
            ec2.describe_network_interfaces(MaxResults=5)
            permissions_tested.append("ec2:DescribeNetworkInterfaces")
            success("ec2:DescribeNetworkInterfaces")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeNetworkInterfaces", str(e)))
            warn(f"ec2:DescribeNetworkInterfaces - {e}")

        try:
            ec2.describe_images(Owners=["self"], MaxResults=5)
            permissions_tested.append("ec2:DescribeImages")
            success("ec2:DescribeImages")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeImages", str(e)))
            warn(f"ec2:DescribeImages - {e}")

        try:
            ec2.describe_nat_gateways(MaxResults=5)
            permissions_tested.append("ec2:DescribeNatGateways")
            success("ec2:DescribeNatGateways")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeNatGateways", str(e)))
            warn(f"ec2:DescribeNatGateways - {e}")

        try:
            ec2.describe_instances(MaxResults=5)
            permissions_tested.append("ec2:DescribeInstances")
            success("ec2:DescribeInstances")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeInstances", str(e)))
            warn(f"ec2:DescribeInstances - {e}")

        try:
            ec2.describe_security_groups(MaxResults=5)
            permissions_tested.append("ec2:DescribeSecurityGroups")
            success("ec2:DescribeSecurityGroups")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeSecurityGroups", str(e)))
            warn(f"ec2:DescribeSecurityGroups - {e}")

        # Test RDS permissions
        rds = session.client("rds", region_name=region)
        try:
            rds.describe_db_instances(MaxRecords=20)
            permissions_tested.append("rds:DescribeDBInstances")
            success("rds:DescribeDBInstances")
        except Exception as e:
            permissions_failed.append(("rds:DescribeDBInstances", str(e)))
            warn(f"rds:DescribeDBInstances - {e}")

        try:
            rds.describe_db_snapshots(MaxRecords=20, SnapshotType="manual")
            permissions_tested.append("rds:DescribeDBSnapshots")
            success("rds:DescribeDBSnapshots")
        except Exception as e:
            permissions_failed.append(("rds:DescribeDBSnapshots", str(e)))
            warn(f"rds:DescribeDBSnapshots - {e}")

        try:
            _rds_snaps = rds.describe_db_snapshots(MaxRecords=20, SnapshotType="manual").get(
                "DBSnapshots", []
            )
            if _rds_snaps:
                rds.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=_rds_snaps[0]["DBSnapshotIdentifier"]
                )
            permissions_tested.append("rds:DescribeDBSnapshotAttributes")
            success("rds:DescribeDBSnapshotAttributes")
        except Exception as e:
            if "AccessDenied" in str(e) or "not authorized" in str(e).lower():
                permissions_failed.append(("rds:DescribeDBSnapshotAttributes", str(e)))
                warn(f"rds:DescribeDBSnapshotAttributes - {e}")
            else:
                permissions_tested.append("rds:DescribeDBSnapshotAttributes")
                success("rds:DescribeDBSnapshotAttributes")

        # Test Redshift permissions
        try:
            redshift = session.client("redshift", region_name=region)
            redshift.describe_clusters(MaxRecords=20)
            permissions_tested.append("redshift:DescribeClusters")
            success("redshift:DescribeClusters")
        except Exception as e:
            permissions_failed.append(("redshift:DescribeClusters", str(e)))
            warn(f"redshift:DescribeClusters - {e}")

        # Test OpenSearch permissions
        try:
            opensearch = session.client("opensearch", region_name=region)
            opensearch.list_domain_names()
            permissions_tested.append("es:ListDomainNames")
            success("es:ListDomainNames")
        except Exception as e:
            permissions_failed.append(("es:ListDomainNames", str(e)))
            warn(f"es:ListDomainNames - {e}")

        try:
            # Use a non-existent domain to test permission
            opensearch.describe_domain(DomainName="cleancloud-perm-test-nonexistent")
            permissions_tested.append("es:DescribeDomain")
            success("es:DescribeDomain")
        except Exception as e:
            if "ResourceNotFoundException" in str(e) or "not found" in str(e).lower():
                permissions_tested.append("es:DescribeDomain")
                success("es:DescribeDomain")
            elif "AccessDenied" in str(e) or "not authorized" in str(e).lower():
                permissions_failed.append(("es:DescribeDomain", str(e)))
                warn(f"es:DescribeDomain - {e}")
            else:
                permissions_tested.append("es:DescribeDomain")
                success("es:DescribeDomain")

        # Test ELB permissions
        try:
            elbv2 = session.client("elbv2", region_name=region)
            elbv2.describe_load_balancers(PageSize=1)
            permissions_tested.append("elasticloadbalancing:DescribeLoadBalancers")
            success("elasticloadbalancing:DescribeLoadBalancers")
        except Exception as e:
            permissions_failed.append(("elasticloadbalancing:DescribeLoadBalancers", str(e)))
            warn(f"elasticloadbalancing:DescribeLoadBalancers - {e}")

        try:
            elbv2.describe_target_groups(PageSize=1)
            permissions_tested.append("elasticloadbalancing:DescribeTargetGroups")
            success("elasticloadbalancing:DescribeTargetGroups")
        except Exception as e:
            permissions_failed.append(("elasticloadbalancing:DescribeTargetGroups", str(e)))
            warn(f"elasticloadbalancing:DescribeTargetGroups - {e}")

        # Test CloudWatch Logs permissions
        try:
            logs = session.client("logs", region_name=region)
            logs.describe_log_groups(limit=1)
            permissions_tested.append("logs:DescribeLogGroups")
            success("logs:DescribeLogGroups")
        except Exception as e:
            permissions_failed.append(("logs:DescribeLogGroups", str(e)))
            warn(f"logs:DescribeLogGroups - {e}")

        # Test CloudWatch Metrics permissions (for NAT Gateway idle detection)
        try:
            from datetime import datetime, timedelta, timezone

            cloudwatch = session.client("cloudwatch", region_name=region)
            now = datetime.now(timezone.utc)
            cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                Dimensions=[],
                StartTime=now - timedelta(hours=1),
                EndTime=now,
                Period=3600,
                Statistics=["Average"],
            )
            permissions_tested.append("cloudwatch:GetMetricStatistics")
            success("cloudwatch:GetMetricStatistics")
        except Exception as e:
            permissions_failed.append(("cloudwatch:GetMetricStatistics", str(e)))
            warn(f"cloudwatch:GetMetricStatistics - {e}")

        # Test S3 permissions
        try:
            s3 = session.client("s3")
            s3.list_buckets()
            permissions_tested.append("s3:ListAllMyBuckets")
            success("s3:ListAllMyBuckets")
        except Exception as e:
            permissions_failed.append(("s3:ListAllMyBuckets", str(e)))
            warn(f"s3:ListAllMyBuckets - {e}")

        try:
            # Use a non-existent bucket to test permission without needing real buckets
            # NoSuchBucket error means we have the permission, AccessDenied means we don't
            s3.get_bucket_tagging(Bucket="cleancloud-permission-test-nonexistent")
            permissions_tested.append("s3:GetBucketTagging")
            success("s3:GetBucketTagging")
        except s3.exceptions.NoSuchBucket:
            # Permission exists, bucket just doesn't exist - that's fine
            permissions_tested.append("s3:GetBucketTagging")
            success("s3:GetBucketTagging")
        except Exception as e:
            if "NoSuchBucket" in str(e):
                permissions_tested.append("s3:GetBucketTagging")
                success("s3:GetBucketTagging")
            elif "AccessDenied" in str(e):
                permissions_failed.append(("s3:GetBucketTagging", str(e)))
                warn(f"s3:GetBucketTagging - {e}")
            else:
                permissions_failed.append(("s3:GetBucketTagging", str(e)))
                warn(f"s3:GetBucketTagging - {e}")

        # Test CloudTrail permissions (aws.ec2.instance.stopped — stopped-duration probe)
        try:
            from datetime import datetime, timedelta
            from datetime import timezone as _tz

            cloudtrail = session.client("cloudtrail", region_name=region)
            _now = datetime.now(_tz.utc)
            cloudtrail.lookup_events(
                StartTime=_now - timedelta(hours=1),
                EndTime=_now,
                MaxResults=1,
            )
            permissions_tested.append("cloudtrail:LookupEvents")
            success("cloudtrail:LookupEvents")
        except Exception as e:
            permissions_failed.append(("cloudtrail:LookupEvents", str(e)))
            warn(f"cloudtrail:LookupEvents - {e}")

    except Exception:
        fail("CleanCloud cannot run safely with missing read-only permissions")

    # Summary
    info("")
    info("=" * 70)
    info("VALIDATION SUMMARY")
    info("=" * 70)

    total_permissions = len(permissions_tested) + len(permissions_failed)
    success_count = len(permissions_tested)

    info(f"Authentication: {description}")
    info(f"Security Grade: {security_grade.upper()}")
    info(f"Permissions Tested: {success_count}/{total_permissions} passed")

    info("")
    if permissions_failed:
        warn(f"Missing Permissions: {len(permissions_failed)}/{total_permissions}")
        for perm, _ in permissions_failed:
            warn(f"  - {perm}")
        info("")
        info("Rules that need these permissions will be skipped during scan.")
        info("To enable full coverage:")
        info("  Attach the CleanCloudReadOnly policy to your IAM role/user")
        info("  See: docs/aws.md for the full policy JSON")
        info("")
        warn("AWS ENVIRONMENT READY (partial coverage)")
    else:
        success("AWS ENVIRONMENT READY FOR CLEANCLOUD")
        info("")
        info("Tip: To also validate AI/ML permissions (SageMaker rules), run:")
        info("  cleancloud doctor --provider aws --category ai")
    info("=" * 70)
    info("")


def run_aws_ai_doctor(profile: Optional[str], region: Optional[str] = None) -> None:
    """Validate AWS permissions for --category ai (SageMaker rules)."""
    if region is None:
        region = "us-east-1"

    info("")
    info("=" * 70)
    info("AWS AI/ML PERMISSION VALIDATION")
    info("=" * 70)
    info("")
    info("Validating permissions for: cleancloud scan --provider aws --category ai")
    info(f"Region: {region}")
    info("")

    try:
        session = create_aws_session(profile=profile, region=region)
    except Exception as e:
        fail(f"Failed to create AWS session: {e}")
        return

    # Verify identity
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        success(f"Account: {identity['Account']}  ({identity['Arn']})")
    except Exception as e:
        fail(f"AWS identity verification failed: {e}")
        return

    info("")
    info("Permission Checks")
    info("-" * 70)

    permissions_tested = []
    permissions_failed = []

    from datetime import datetime, timedelta, timezone

    sagemaker = session.client("sagemaker", region_name=region)

    try:
        sagemaker.list_endpoints(MaxResults=1)
        permissions_tested.append("sagemaker:ListEndpoints")
        success("sagemaker:ListEndpoints")
    except Exception as e:
        permissions_failed.append(("sagemaker:ListEndpoints", str(e)))
        warn(f"sagemaker:ListEndpoints - {e}")

    try:
        # Describe the first InService endpoint if one exists; otherwise permission is assumed
        # present since ListEndpoints already confirmed SageMaker access.
        endpoints = sagemaker.list_endpoints(MaxResults=1, StatusEquals="InService")
        endpoint_list = endpoints.get("Endpoints", [])
        endpoint_config_name = None
        if endpoint_list:
            ep = sagemaker.describe_endpoint(EndpointName=endpoint_list[0]["EndpointName"])
            endpoint_config_name = ep.get("EndpointConfigName")
        permissions_tested.append("sagemaker:DescribeEndpoint")
        success("sagemaker:DescribeEndpoint")
    except Exception as e:
        permissions_failed.append(("sagemaker:DescribeEndpoint", str(e)))
        warn(f"sagemaker:DescribeEndpoint - {e}")
        endpoint_config_name = None

    try:
        # DescribeEndpointConfig — needed to resolve instance type (not in DescribeEndpoint response)
        if endpoint_config_name:
            sagemaker.describe_endpoint_config(EndpointConfigName=endpoint_config_name)
        permissions_tested.append("sagemaker:DescribeEndpointConfig")
        success("sagemaker:DescribeEndpointConfig")
    except Exception as e:
        permissions_failed.append(("sagemaker:DescribeEndpointConfig", str(e)))
        warn(f"sagemaker:DescribeEndpointConfig - {e}")

    try:
        sagemaker.list_notebook_instances(MaxResults=1)
        permissions_tested.append("sagemaker:ListNotebookInstances")
        success("sagemaker:ListNotebookInstances")
    except Exception as e:
        permissions_failed.append(("sagemaker:ListNotebookInstances", str(e)))
        warn(f"sagemaker:ListNotebookInstances - {e}")

    try:
        # DescribeNotebookInstance — attempt only if a notebook exists to avoid a spurious miss
        notebooks = sagemaker.list_notebook_instances(MaxResults=1, StatusEquals="InService")
        notebook_list = notebooks.get("NotebookInstances", [])
        if notebook_list:
            sagemaker.describe_notebook_instance(
                NotebookInstanceName=notebook_list[0]["NotebookInstanceName"]
            )
        permissions_tested.append("sagemaker:DescribeNotebookInstance")
        success("sagemaker:DescribeNotebookInstance")
    except Exception as e:
        permissions_failed.append(("sagemaker:DescribeNotebookInstance", str(e)))
        warn(f"sagemaker:DescribeNotebookInstance - {e}")

    # --- sagemaker:ListDomains + sagemaker:DescribeDomain (aws.sagemaker.domain.idle) ---
    try:
        sagemaker.list_domains(MaxResults=1)
        permissions_tested.append("sagemaker:ListDomains")
        success("sagemaker:ListDomains")
    except Exception as e:
        permissions_failed.append(("sagemaker:ListDomains", str(e)))
        warn(f"sagemaker:ListDomains - {e}")

    try:
        # DescribeDomain — attempt only if a domain exists to avoid a spurious miss
        _domains = sagemaker.list_domains(MaxResults=1)
        _domain_list = _domains.get("Domains", [])
        if _domain_list:
            sagemaker.describe_domain(DomainId=_domain_list[0]["DomainId"])
            permissions_tested.append("sagemaker:DescribeDomain")
            success("sagemaker:DescribeDomain")
        else:
            info("sagemaker:DescribeDomain - not tested (no SageMaker domain found to probe)")
    except Exception as e:
        permissions_failed.append(("sagemaker:DescribeDomain", str(e)))
        warn(f"sagemaker:DescribeDomain - {e}")

    # --- sagemaker:ListApps (aws.sagemaker.studio_app.idle + aws.sagemaker.domain.idle) ---
    try:
        sagemaker.list_apps(MaxResults=1)
        permissions_tested.append("sagemaker:ListApps")
        success("sagemaker:ListApps")
    except Exception as e:
        permissions_failed.append(("sagemaker:ListApps", str(e)))
        warn(f"sagemaker:ListApps - {e}")

    try:
        # Paginate through all apps to find the first qualifying one — checking only
        # the first page can leave describe_app untested in accounts with many apps.
        _target_app = None
        _paginator = sagemaker.get_paginator("list_apps")
        for _page in _paginator.paginate(PaginationConfig={"PageSize": 20}):
            for _a in _page.get("Apps", []):
                if _a.get("Status") == "InService" and _a.get("AppType") in (
                    "KernelGateway",
                    "JupyterLab",
                    "CodeEditor",
                ):
                    _target_app = _a
                    break
            if _target_app:
                break

        if _target_app:
            describe_kwargs = {
                "DomainId": _target_app["DomainId"],
                "AppType": _target_app["AppType"],
                "AppName": _target_app["AppName"],
            }
            if _target_app.get("SpaceName"):
                describe_kwargs["SpaceName"] = _target_app["SpaceName"]
            elif _target_app.get("UserProfileName"):
                describe_kwargs["UserProfileName"] = _target_app["UserProfileName"]
            sagemaker.describe_app(**describe_kwargs)
            permissions_tested.append("sagemaker:DescribeApp")
            success("sagemaker:DescribeApp")
        else:
            # No qualifying InService app exists in this account/region — describe_app
            # cannot be exercised, so the permission remains untested.
            info(
                "sagemaker:DescribeApp - not tested (no InService KernelGateway/JupyterLab/CodeEditor app found to probe)"
            )
    except Exception as e:
        permissions_failed.append(("sagemaker:DescribeApp", str(e)))
        warn(f"sagemaker:DescribeApp - {e}")

    # --- sagemaker:ListTrainingJobs + sagemaker:DescribeTrainingJob (aws.sagemaker.training_job.long_running) ---
    try:
        sagemaker.list_training_jobs(MaxResults=1, StatusEquals="InProgress")
        permissions_tested.append("sagemaker:ListTrainingJobs")
        success("sagemaker:ListTrainingJobs")
    except Exception as e:
        permissions_failed.append(("sagemaker:ListTrainingJobs", str(e)))
        warn(f"sagemaker:ListTrainingJobs - {e}")

    try:
        _tj_paginator = sagemaker.get_paginator("list_training_jobs")
        _target_job = None
        for _tj_page in _tj_paginator.paginate(
            StatusEquals="InProgress", PaginationConfig={"PageSize": 20}
        ):
            for _tj in _tj_page.get("TrainingJobSummaries", []):
                _target_job = _tj
                break
            if _target_job:
                break

        if _target_job:
            sagemaker.describe_training_job(TrainingJobName=_target_job["TrainingJobName"])
            permissions_tested.append("sagemaker:DescribeTrainingJob")
            success("sagemaker:DescribeTrainingJob")
        else:
            info(
                "sagemaker:DescribeTrainingJob - not tested (no InProgress training job found to probe)"
            )
    except Exception as e:
        permissions_failed.append(("sagemaker:DescribeTrainingJob", str(e)))
        warn(f"sagemaker:DescribeTrainingJob - {e}")

    # --- sagemaker:ListProcessingJobs + sagemaker:DescribeProcessingJob (aws.sagemaker.processing_job.long_running) ---
    try:
        sagemaker.list_processing_jobs(MaxResults=1)
        permissions_tested.append("sagemaker:ListProcessingJobs")
        success("sagemaker:ListProcessingJobs")
    except Exception as e:
        permissions_failed.append(("sagemaker:ListProcessingJobs", str(e)))
        warn(f"sagemaker:ListProcessingJobs - {e}")

    try:
        _pj_paginator = sagemaker.get_paginator("list_processing_jobs")
        _target_job = None
        for _pj_page in _pj_paginator.paginate(PaginationConfig={"PageSize": 20}):
            for _pj in _pj_page.get("ProcessingJobSummaries", []):
                _target_job = _pj
                break
            if _target_job:
                break

        if _target_job:
            sagemaker.describe_processing_job(ProcessingJobName=_target_job["ProcessingJobName"])
            permissions_tested.append("sagemaker:DescribeProcessingJob")
            success("sagemaker:DescribeProcessingJob")
        else:
            info("sagemaker:DescribeProcessingJob - not tested (no processing job found to probe)")
    except Exception as e:
        permissions_failed.append(("sagemaker:DescribeProcessingJob", str(e)))
        warn(f"sagemaker:DescribeProcessingJob - {e}")

    try:
        cloudwatch = session.client("cloudwatch", region_name=region)
        now = datetime.now(timezone.utc)
        cloudwatch.get_metric_statistics(
            Namespace="AWS/SageMaker",
            MetricName="Invocations",
            Dimensions=[],
            StartTime=now - timedelta(hours=1),
            EndTime=now,
            Period=3600,
            Statistics=["Sum"],
        )
        permissions_tested.append("cloudwatch:GetMetricStatistics")
        success("cloudwatch:GetMetricStatistics")
    except Exception as e:
        permissions_failed.append(("cloudwatch:GetMetricStatistics", str(e)))
        warn(f"cloudwatch:GetMetricStatistics - {e}")

    # --- bedrock:ListProvisionedModelThroughputs (aws.bedrock.provisioned_throughput.idle) ---
    try:
        bedrock = session.client("bedrock", region_name=region)
        bedrock.list_provisioned_model_throughputs(maxResults=1)
        permissions_tested.append("bedrock:ListProvisionedModelThroughputs")
        success("bedrock:ListProvisionedModelThroughputs")
    except Exception as e:
        permissions_failed.append(("bedrock:ListProvisionedModelThroughputs", str(e)))
        warn(f"bedrock:ListProvisionedModelThroughputs - {e}")

    # --- ec2:DescribeInstances (aws.ec2.gpu.idle) ---
    try:
        ec2 = session.client("ec2", region_name=region)
        ec2.describe_instances(
            MaxResults=5,
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}],
        )
        permissions_tested.append("ec2:DescribeInstances")
        success("ec2:DescribeInstances")
    except Exception as e:
        permissions_failed.append(("ec2:DescribeInstances", str(e)))
        warn(f"ec2:DescribeInstances - {e}")

    # --- cloudwatch:ListMetrics (aws.ec2.gpu.idle — GPU metric probe) ---
    try:
        cloudwatch.list_metrics(Namespace="CWAgent", MetricName="nvidia_smi_utilization_gpu")
        permissions_tested.append("cloudwatch:ListMetrics")
        success("cloudwatch:ListMetrics")
    except Exception as e:
        permissions_failed.append(("cloudwatch:ListMetrics", str(e)))
        warn(f"cloudwatch:ListMetrics - {e}")

    info("")
    info("=" * 70)
    total = len(permissions_tested) + len(permissions_failed)
    info(f"Permissions: {len(permissions_tested)}/{total} passed")

    if permissions_failed:
        info("")
        for perm, _ in permissions_failed:
            warn(f"  missing: {perm}")
        info("")
        info("Attach security/aws/ai-readonly.json to your IAM role/user.")
        info("Then re-run: cleancloud doctor --provider aws --category ai")
        info("")
        warn("AWS AI/ML PERMISSIONS INCOMPLETE")
    else:
        info("")
        success("AWS AI/ML PERMISSIONS READY")
        info("Run: cleancloud scan --provider aws --category ai")
    info("=" * 70)
    info("")


def run_aws_multi_account_doctor(
    config: MultiAccountConfig,
    profile: Optional[str] = None,
    region: Optional[str] = None,
) -> None:
    # STS is global — region only selects the endpoint; us-east-1 is the canonical global endpoint
    region = region or "us-east-1"

    info("")
    info("=" * 70)
    info("MULTI-ACCOUNT VALIDATION")
    info("=" * 70)
    info(f"Role name    : {config.role_name}")
    info(f"External ID  : {config.external_id or '(none)'}")
    info(f"Accounts     : {len(config.accounts)}")
    info("")

    # Validate hub credentials first
    info("Step 1: Hub Account Credentials")
    info("-" * 70)
    try:
        hub_session = create_aws_session(profile=profile, region=region)
        sts = hub_session.client("sts", config=BOTO_CONFIG)
        identity = sts.get_caller_identity()
        success(f"Hub account: {identity['Account']}  ({identity['Arn']})")
    except Exception as e:
        fail(f"Hub credentials failed: {e}")
        return

    # Check sts:AssumeRole permission
    info("")
    info("Step 2: Hub Role Permissions")
    info("-" * 70)
    try:
        orgs = hub_session.client("organizations", config=BOTO_CONFIG)
        orgs.list_accounts(MaxResults=1)
        success("organizations:ListAccounts  (--org flag will work)")
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "AWSOrganizationsNotInUseException"):
            warn("organizations:ListAccounts  (--org flag will not work)")
        else:
            warn(f"organizations:ListAccounts  {code}")
    except Exception as e:
        warn(f"organizations:ListAccounts  {e}")

    # Validate each target account
    info("")
    info("Step 3: Cross-Account Role Validation")
    info("-" * 70)

    passed = 0
    failed_accounts = []

    for account in config.accounts:
        label = f"{account.name} ({account.id})"
        try:
            assumed = assume_role(
                session=hub_session,
                account_id=account.id,
                role_name=config.role_name,
                region=region,
                external_id=config.external_id,
            )
            assumed_identity = assumed.client("sts", config=BOTO_CONFIG).get_caller_identity()
            success(f"{label}  ->  {assumed_identity['Arn']}")
            passed += 1
        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"]["Message"]
            warn(f"{label}  {code}: {msg}")
            failed_accounts.append((label, f"{code}: {msg}"))
        except Exception as e:
            warn(f"{label}  {e}")
            failed_accounts.append((label, str(e)))

    info("")
    info("=" * 70)
    info("MULTI-ACCOUNT SUMMARY")
    info("=" * 70)
    info(f"Accounts passed : {passed}/{len(config.accounts)}")
    if failed_accounts:
        info(f"Accounts failed : {len(failed_accounts)}")
        info("")
        info("Failed accounts — check that the role exists and trust policy allows assumption:")
        for label, error in failed_accounts:
            warn(f"  {label}: {error}")
        info("")
        info(f"Expected role ARN format: arn:aws:iam::<ACCOUNT_ID>:role/{config.role_name}")
        info("See docs/aws.md for cross-account IAM setup instructions")
    else:
        success("All accounts reachable — ready for multi-account scan")
    info("=" * 70)
    info("")
