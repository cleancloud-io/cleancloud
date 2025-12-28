"""
Enterprise-grade AWS doctor with robust auth detection and acquirer-friendly logging.
"""

import os
from typing import Optional

from cleancloud.doctor.common import fail, info, success, warn
from cleancloud.providers.aws.session import create_aws_session


def detect_aws_auth_method(session) -> tuple[str, str, dict]:
    """
    Detect how AWS credentials are being sourced.

    IMPORTANT: Uses credentials.method (what boto3 actually used),
    NOT environment variables (which might be stale or overridden).

    Returns:
        tuple: (method_id, human_readable_description, metadata_dict)
    """
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
                {"recommended": False, "ci_cd_ready": False, "security_grade": "unknown"}
            )
            return "unknown", f"Other ({provider_name})", metadata

    except Exception as e:
        return "error", f"Error detecting method: {e}", {"error": str(e)}


def run_aws_doctor(profile: Optional[str], region: str) -> None:
    """
    Validate AWS credentials and permissions with enterprise-grade logging.

    Provides detailed authentication diagnostics suitable for security audits
    and acquirer due diligence.
    """

    # Header
    info("")
    info("=" * 70)
    info("AWS ENVIRONMENT VALIDATION")
    info("=" * 70)
    info("")

    # Step 1: Create session
    info("🔐 Step 1: AWS Credential Resolution")
    info("-" * 70)

    try:
        session = create_aws_session(profile=profile, region=region)
        success("AWS session created successfully")
    except Exception as e:
        fail(f"Failed to create AWS session: {e}")

    # Step 2: Detect authentication method
    info("")
    info("🔍 Step 2: Authentication Method Detection")
    info("-" * 70)

    method_id, description, metadata = detect_aws_auth_method(session)

    # Display auth method with context
    info(f"Authentication Method: {description}")

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
        success("Security Grade: EXCELLENT ✅")
        success("  ✓ Temporary credentials")
        success("  ✓ Auto-rotated")
        success("  ✓ No secret storage required")

    elif security_grade == "good":
        success("Security Grade: GOOD ✅")
        info("  ✓ Temporary credentials")
        if not metadata.get("rotation_required"):
            info("  ✓ Auto-rotated")

    elif security_grade == "acceptable":
        warn("Security Grade: ACCEPTABLE ⚠️")
        warn("  ⚠ Long-lived credentials")
        warn("  ⚠ Manual rotation required")
        info("")
        info("  Recommendation for local development:")
        info("    Current setup is acceptable")

    elif security_grade == "poor":
        warn("Security Grade: POOR ⚠️")
        warn("  ⚠ Long-lived access keys")
        warn("  ⚠ Requires 90-day rotation")
        warn("  ⚠ High blast radius if compromised")
        info("")
        info("  Recommendation for CI/CD:")
        info("    Switch to OIDC (OpenID Connect)")
        info("    See: https://docs.cleancloud.io/aws#oidc")

    else:
        info(f"Security Grade: {security_grade.upper()}")

    # CI/CD readiness
    info("")
    if metadata.get("ci_cd_ready"):
        success("CI/CD Ready: YES ✅")
        success("  Suitable for production CI/CD pipelines")
    else:
        if method_id == "profile":
            info("CI/CD Ready: NO (Local development only)")
            info("  AWS CLI profiles are not available in CI/CD")
        else:
            warn("CI/CD Ready: NO ⚠️")
            warn("  Not recommended for automated pipelines")

    # Compliance notes
    info("")
    if metadata.get("security_grade") in ("excellent", "good"):
        success("Compliance: SOC2/ISO27001 Compatible ✅")
    elif metadata.get("security_grade") == "acceptable":
        info("Compliance: Acceptable for development environments")
    else:
        warn("Compliance: May not meet enterprise security requirements ⚠️")

    # Step 3: Identity verification
    info("")
    info("👤 Step 3: Identity Verification")
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
            success("  ✓ OIDC-based assumed role (recommended)")

    elif ":user/" in arn:
        user_name = arn.split("/")[-1]
        info(f"  IAM User: {user_name}")

        if method_id == "static_keys":
            warn("  ⚠ Using IAM user credentials (not recommended for CI/CD)")

    # Step 4: Permission validation
    info("")
    info("🔒 Step 4: Read-Only Permission Validation")
    info("-" * 70)

    permissions_tested = []
    permissions_failed = []

    try:
        ec2 = session.client("ec2", region_name=region)

        # Test EC2 permissions
        try:
            ec2.describe_volumes(MaxResults=6)
            permissions_tested.append("ec2:DescribeVolumes")
            success("✓ ec2:DescribeVolumes")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeVolumes", str(e)))
            warn(f"✗ ec2:DescribeVolumes - {e}")

        try:
            ec2.describe_snapshots(OwnerIds=["self"], MaxResults=5)
            permissions_tested.append("ec2:DescribeSnapshots")
            success("✓ ec2:DescribeSnapshots")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeSnapshots", str(e)))
            warn(f"✗ ec2:DescribeSnapshots - {e}")

        try:
            ec2.describe_regions()
            permissions_tested.append("ec2:DescribeRegions")
            success("✓ ec2:DescribeRegions")
        except Exception as e:
            permissions_failed.append(("ec2:DescribeRegions", str(e)))
            warn(f"✗ ec2:DescribeRegions - {e}")

        # Test CloudWatch Logs permissions
        try:
            logs = session.client("logs", region_name=region)
            logs.describe_log_groups(limit=1)
            permissions_tested.append("logs:DescribeLogGroups")
            success("✓ logs:DescribeLogGroups")
        except Exception as e:
            permissions_failed.append(("logs:DescribeLogGroups", str(e)))
            warn(f"✗ logs:DescribeLogGroups - {e}")

        # Test S3 permissions
        try:
            s3 = session.client("s3")
            s3.list_buckets()
            permissions_tested.append("s3:ListAllMyBuckets")
            success("✓ s3:ListAllMyBuckets")
        except Exception as e:
            permissions_failed.append(("s3:ListAllMyBuckets", str(e)))
            warn(f"✗ s3:ListAllMyBuckets - {e}")

    except Exception as e:
        fail(f"Permission validation failed: {e}")

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

    if permissions_failed:
        info("")
        warn("Missing Permissions:")
        for perm, error in permissions_failed:
            warn(f"  - {perm}")
        info("")
        info("To fix: Attach CleanCloudReadOnly policy to your IAM role/user")
        info("See: https://docs.cleancloud.io/aws#iam-policy")
        fail("AWS permission validation failed")

    info("")
    success("🎉 AWS ENVIRONMENT READY FOR CLEANCLOUD")
    info("=" * 70)
    info("")
