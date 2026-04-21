"""
Rule: aws.resource.untagged

    (spec — docs/specs/aws/untagged_resources.md)

Intent:
    Detect supported AWS resources in the currently evaluated account scope that
    have no current tags according to authoritative service-native tagging APIs,
    so they can be reviewed for governance, ownership, allocability, and FinOps
    hygiene gaps.

    This is a read-only hygiene rule. Not a waste rule, not proof that a resource
    is unused, and not proof that the resource violates a mandatory tag policy.

Supported resource families:
    - EBS volumes (ec2:DescribeVolumes + Tags from inventory)
    - S3 general purpose buckets (s3:ListBuckets + s3:GetBucketTagging)
    - CloudWatch log groups (logs:DescribeLogGroups + logs:ListTagsForResource)

Exclusions:
    - resource_id absent (malformed identity)
    - resource has one or more current tags (current_tag_count > 0)
    - S3: bucket where GetBucketTagging fails for reasons other than NoSuchTagSet
    - CloudWatch log group: ARN absent (cannot call ListTagsForResource)
    - CloudWatch log group: ListTagsForResource fails
    - S3 directory buckets

Key rules:
    - DescribeVolumes, ListBuckets, DescribeLogGroups failure → FAIL RULE.
    - GetBucketTagging failure (non-NoSuchTagSet) → SKIP ITEM.
    - ListTagsForResource failure → SKIP ITEM.
    - S3 NoSuchTagSet → untagged (tag_count = 0), not failure.
    - DescribeLogGroups does not return tags; ListTagsForResource is required.
    - estimated_monthly_cost_usd = None.
    - Confidence: HIGH always.
    - Risk: MEDIUM always.

Blind spots:
    - Whether the resource is intentionally exempt from tagging
    - Whether specific required business tags should exist
    - Whether the effective AWS Organizations tag policy marks the resource compliant
    - Application/service criticality
    - Planned future usage
    - Exact cost impact

APIs:
    - ec2:DescribeVolumes
    - s3:ListAllMyBuckets
    - s3:GetBucketTagging
    - logs:DescribeLogGroups
    - logs:ListTagsForResource
"""

from datetime import datetime, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

_FAMILY_EBS = "ebs_volume"
_FAMILY_S3 = "s3_bucket"
_FAMILY_LOG_GROUP = "cloudwatch_log_group"

_TAG_SOURCE_EBS = "ec2:DescribeVolumes"
_TAG_SOURCE_S3 = "s3:GetBucketTagging"
_TAG_SOURCE_LOG_GROUP = "logs:ListTagsForResource"

_SIGNALS_NOT_CHECKED = (
    "Whether the resource is intentionally exempt from tagging",
    "Whether specific required business tags should exist",
    "Whether the effective AWS Organizations tag policy marks the resource compliant",
    "Application/service criticality",
    "Planned future usage",
    "Exact cost impact",
)


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


# ---------------------------------------------------------------------------
# EBS volume normalization
# ---------------------------------------------------------------------------


def _normalize_ebs_volume(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw DescribeVolumes item.

    Returns None when identity is absent/malformed — caller must skip the item.
    `current_tag_count` is always computable (non-list Tags → treated as empty).
    """
    if not isinstance(item, dict):
        return None

    resource_id = _str(item.get("VolumeId"))
    if resource_id is None:
        return None

    # Tags: authoritative source is DescribeVolumes.Tags.
    # Non-list values (including None) are treated as empty (conservative normalization).
    raw_tags = item.get("Tags")
    tags = raw_tags if isinstance(raw_tags, list) else []
    current_tag_count = len(tags)

    # Optional context fields
    availability_zone = _str(item.get("AvailabilityZone"))
    raw_size = item.get("Size")
    size_gib = raw_size if isinstance(raw_size, int) else None
    volume_type = _str(item.get("VolumeType"))
    state = _str(item.get("State"))
    raw_encrypted = item.get("Encrypted")
    encrypted = raw_encrypted if isinstance(raw_encrypted, bool) else None

    # Age is contextual only; invalid/missing → null (does not suppress detection)
    create_time_utc = None
    age_days = None
    raw_ct = item.get("CreateTime")
    if isinstance(raw_ct, datetime) and raw_ct.tzinfo is not None:
        ct = raw_ct.astimezone(timezone.utc)
        if ct <= now_utc:
            create_time_utc = ct
            age_days = int((now_utc - ct).total_seconds() // 86400)

    return {
        "resource_family": _FAMILY_EBS,
        "resource_id": resource_id,
        "resource_arn": None,
        "current_tag_count": current_tag_count,
        "availability_zone": availability_zone,
        "size_gib": size_gib,
        "volume_type": volume_type,
        "state": state,
        "encrypted": encrypted,
        "create_time_utc": create_time_utc,
        "age_days": age_days,
    }


# ---------------------------------------------------------------------------
# S3 bucket normalization and tag lookup
# ---------------------------------------------------------------------------


def _normalize_s3_bucket(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw ListBuckets bucket item.

    Returns None when identity is absent/malformed — caller must skip the item.
    `current_tag_count` is not included here; it is fetched separately via
    GetBucketTagging and set by the caller.
    """
    if not isinstance(item, dict):
        return None

    resource_id = _str(item.get("Name"))
    if resource_id is None:
        return None

    native_region = _str(item.get("BucketRegion"))
    resource_arn = _str(item.get("BucketArn"))

    # Age is contextual only; invalid/missing → null
    create_time_utc = None
    age_days = None
    raw_ct = item.get("CreationDate")
    if isinstance(raw_ct, datetime) and raw_ct.tzinfo is not None:
        ct = raw_ct.astimezone(timezone.utc)
        if ct <= now_utc:
            create_time_utc = ct
            age_days = int((now_utc - ct).total_seconds() // 86400)

    return {
        "resource_family": _FAMILY_S3,
        "resource_id": resource_id,
        "resource_arn": resource_arn,
        "native_region": native_region,
        "create_time_utc": create_time_utc,
        "age_days": age_days,
    }


def _get_s3_tag_count(s3, bucket_name: str) -> Optional[int]:
    """Fetch the current tag count for a general purpose S3 bucket.

    Returns tag count (>= 0) on success.
    Returns None when tag visibility is unavailable for this item — caller must SKIP ITEM.
    NoSuchTagSet → 0 (untagged, not failure).
    Other ClientError / BotoCoreError → None (SKIP ITEM).
    """
    try:
        tag_set = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
        if not isinstance(tag_set, list):
            return None  # Malformed tag payload → visibility unavailable → SKIP ITEM
        return len(tag_set)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchTagSet":
            return 0  # No tag set → untagged
        return None  # Other API failure → SKIP ITEM
    except BotoCoreError:
        return None  # API failure → SKIP ITEM


# ---------------------------------------------------------------------------
# CloudWatch log group normalization and tag lookup
# ---------------------------------------------------------------------------


def _normalize_log_group(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw DescribeLogGroups item.

    Returns None when identity is absent/malformed — caller must skip the item.
    Tags are not available from DescribeLogGroups; they must be fetched separately
    via ListTagsForResource using the log group ARN.
    """
    if not isinstance(item, dict):
        return None

    resource_id = _str(item.get("logGroupName"))
    if resource_id is None:
        return None

    # ARN: try logGroupArn first (preferred), fall back to arn
    resource_arn = _str(item.get("logGroupArn")) or _str(item.get("arn"))
    log_group_class = _str(item.get("logGroupClass"))

    # Age is contextual only; creationTime is milliseconds since epoch
    create_time_utc = None
    age_days = None
    raw_ct = item.get("creationTime")
    if isinstance(raw_ct, (int, float)) and raw_ct > 0:
        try:
            ct = datetime.fromtimestamp(raw_ct / 1000, tz=timezone.utc)
            if ct <= now_utc:
                create_time_utc = ct
                age_days = int((now_utc - ct).total_seconds() // 86400)
        except (OSError, OverflowError, ValueError):
            pass  # Invalid timestamp → contextual null; does not suppress detection

    return {
        "resource_family": _FAMILY_LOG_GROUP,
        "resource_id": resource_id,
        "resource_arn": resource_arn,
        "log_group_class": log_group_class,
        "create_time_utc": create_time_utc,
        "age_days": age_days,
    }


def _get_log_group_tag_count(logs, resource_arn: Optional[str]) -> Optional[int]:
    """Fetch the current tag count for a CloudWatch log group via ListTagsForResource.

    Returns tag count (>= 0) on success.
    Returns None when tag visibility is unavailable — caller must SKIP ITEM.
    ARN absent → None (SKIP ITEM; cannot call ListTagsForResource without ARN).
    ClientError / BotoCoreError → None (SKIP ITEM).
    """
    if resource_arn is None:
        return None  # ARN required for ListTagsForResource
    try:
        resp = logs.list_tags_for_resource(resourceArn=resource_arn)
        tags = resp.get("tags", {})
        if not isinstance(tags, dict):
            return None  # Malformed tag payload → visibility unavailable → SKIP ITEM
        return len(tags)
    except (ClientError, BotoCoreError):
        return None  # API failure → SKIP ITEM


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------


def _emit_finding(
    n: dict,
    region: str,
    now: datetime,
    tag_source_api: str,
    extra_details: Optional[dict] = None,
) -> Finding:
    family = n["resource_family"]

    if family == _FAMILY_EBS:
        title = "Untagged EBS volume"
        resource_type = "aws.ebs.volume"
        native_region = region
    elif family == _FAMILY_S3:
        title = "Untagged S3 bucket"
        resource_type = "aws.s3.bucket"
        native_region = n.get("native_region")
    else:
        title = "Untagged CloudWatch log group"
        resource_type = "aws.cloudwatch.log_group"
        native_region = region

    details = {
        "evaluation_path": "untagged-supported-resource",
        "resource_family": family,
        "resource_id": n["resource_id"],
        "current_tag_count": 0,
        "native_region": native_region,
        "resource_arn": n.get("resource_arn"),
        "create_time": n["create_time_utc"].isoformat() if n.get("create_time_utc") else None,
        "age_days": n.get("age_days"),
        "tag_source_api": tag_source_api,
    }
    if extra_details:
        details.update(extra_details)

    signals_used = [
        f"{family} resource identified in supported canonical scope",
        f"Authoritative current-tag source ({tag_source_api}) was consulted",
        "No current tags were present at evaluation time",
    ]

    return Finding(
        provider="aws",
        rule_id="aws.resource.untagged",
        resource_type=resource_type,
        resource_id=n["resource_id"],
        region=native_region or region,
        estimated_monthly_cost_usd=None,
        title=title,
        summary=f"{n['resource_id']} has no current tags",
        reason="No current tags found in authoritative tag source",
        risk=RiskLevel.MEDIUM,
        confidence=ConfidenceLevel.HIGH,
        detected_at=now,
        evidence=Evidence(
            signals_used=signals_used,
            signals_not_checked=list(_SIGNALS_NOT_CHECKED),
            time_window=None,
        ),
        details=details,
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def find_untagged_resources(
    session: boto3.Session,
    region: str,
) -> List[Finding]:
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    # --- EBS volumes ---
    ec2 = session.client("ec2", region_name=region)
    try:
        paginator = ec2.get_paginator("describe_volumes")
        ebs_pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError("Missing required IAM permission: ec2:DescribeVolumes") from exc
        raise
    except BotoCoreError:
        raise

    for page in ebs_pages:
        for raw_item in page.get("Volumes", []):
            n = _normalize_ebs_volume(raw_item, now)
            if n is None:
                continue
            if n["current_tag_count"] > 0:
                continue
            findings.append(
                _emit_finding(
                    n,
                    region,
                    now,
                    _TAG_SOURCE_EBS,
                    extra_details={
                        "availability_zone": n["availability_zone"],
                        "size_gib": n["size_gib"],
                        "volume_type": n["volume_type"],
                        "state": n["state"],
                        "encrypted": n["encrypted"],
                    },
                )
            )

    # --- S3 buckets ---
    s3 = session.client("s3")
    try:
        paginator = s3.get_paginator("list_buckets")
        s3_pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError("Missing required IAM permission: s3:ListAllMyBuckets") from exc
        raise
    except BotoCoreError:
        raise

    for page in s3_pages:
        for raw_item in page.get("Buckets", []):
            n = _normalize_s3_bucket(raw_item, now)
            if n is None:
                continue
            tag_count = _get_s3_tag_count(s3, n["resource_id"])
            if tag_count is None:
                continue  # Tag visibility unavailable → SKIP ITEM
            if tag_count > 0:
                continue
            findings.append(_emit_finding(n, region, now, _TAG_SOURCE_S3))

    # --- CloudWatch log groups ---
    logs = session.client("logs", region_name=region)
    try:
        paginator = logs.get_paginator("describe_log_groups")
        log_pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permission: logs:DescribeLogGroups"
            ) from exc
        raise
    except BotoCoreError:
        raise

    for page in log_pages:
        for raw_item in page.get("logGroups", []):
            n = _normalize_log_group(raw_item, now)
            if n is None:
                continue
            tag_count = _get_log_group_tag_count(logs, n["resource_arn"])
            if tag_count is None:
                continue  # Tag visibility unavailable → SKIP ITEM
            if tag_count > 0:
                continue
            findings.append(
                _emit_finding(
                    n,
                    region,
                    now,
                    _TAG_SOURCE_LOG_GROUP,
                    extra_details={"log_group_class": n["log_group_class"]},
                )
            )

    return findings
