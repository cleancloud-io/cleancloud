"""
Rule: aws.ebs.unattached

    (spec — docs/specs/aws/ebs_unattached.md)

Intent:
    Detect currently unattached EBS volumes that are old enough to be cleanup review
    candidates.

Exclusions:
    - volume state is not available
    - any attachment entry is returned
    - volume is explicitly service-managed (Operator.Managed == True)
    - required fields are missing
    - volume is younger than the configured threshold

Detection:
    - normalized_status == available
    - normalized attachment_count == 0
    - age >= threshold
    - service_managed_check != True

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - Do not treat missing instanceId as proof of no attachment.
    - Normalize SDK field shapes before evaluating attachments or operator state.
    - service_managed_check == true excludes; unknown is not an exclusion.
    - Do not use a flat size-only cost estimate across all EBS types.

Blind spots:
    - business/DR/future-attachment intent is not known
    - backup/snapshot recoverability is not checked
    - available does not mean safe to delete

APIs:
    - ec2:DescribeVolumes
"""

from datetime import datetime, timezone
from typing import List, Optional, Union

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_DEFAULT_MIN_UNATTACHED_AGE_DAYS: int = 7


def _normalize(volume: dict) -> Optional[dict]:
    """Normalize raw SDK volume dict to the canonical field shape.

    Returns None when required fields are absent and the item must be skipped.
    All rule logic must operate only on the returned normalized dict.
    """
    # Required identity and timing fields — absence means malformed, skip item.
    volume_id = volume.get("VolumeId") or volume.get("volumeId")
    if not volume_id:
        return None

    normalized_status = volume.get("State") or volume.get("state") or volume.get("status")
    if not normalized_status:
        return None

    create_time = volume.get("CreateTime") or volume.get("createTime")
    if create_time is None:
        return None
    if not isinstance(create_time, datetime):
        return None

    # Attachments — prefer Attachments; fall back to attachmentSet; missing → [].
    # Flatten any SDK-specific wrapper/container variants to a canonical list before
    # deriving attachment_count.  A dict shape (single attachment not in a list, or a
    # service-variant wrapper) is flattened to [dict] so attachment_count == 1 and the
    # attachment_count > 0 exclusion rule fires rather than a normalization skip.
    # Truly unrecognized scalar shapes (string, int, …) cannot be flattened → skip item.
    try:
        if "Attachments" in volume:
            raw_attach = volume["Attachments"]
        elif "attachmentSet" in volume:
            raw_attach = volume["attachmentSet"]
        else:
            raw_attach = None

        if raw_attach is None:
            normalized_attachments = []
        elif isinstance(raw_attach, list):
            # Already a flat list — use directly.
            normalized_attachments = raw_attach
        elif isinstance(raw_attach, dict):
            # Single-attachment or wrapper dict — flatten to one-element list.
            normalized_attachments = [raw_attach]
        else:
            # Scalar (string, int, …) — cannot derive canonical attachment list → skip.
            return None

        attachment_count = len(normalized_attachments)
    except Exception:
        return None

    # Operator metadata → service_managed_check and operator_principal.
    # Malformed operator becomes unknown; it never causes item skip.
    try:
        raw_operator = volume.get("Operator")
        normalized_operator = raw_operator if isinstance(raw_operator, dict) else {}

        # managed flag — check both casings; unwrap nested dict if needed.
        managed_raw = normalized_operator.get("Managed")
        if managed_raw is None:
            managed_raw = normalized_operator.get("managed")

        if managed_raw is True:
            service_managed_check: Union[bool, str] = True
        elif managed_raw is False:
            service_managed_check = False
        elif isinstance(managed_raw, dict):
            # Wrapped value — attempt to unwrap to explicit bool.
            unwrapped = managed_raw.get("Value")
            if unwrapped is None:
                unwrapped = managed_raw.get("value")
            if unwrapped is True:
                service_managed_check = True
            elif unwrapped is False:
                service_managed_check = False
            else:
                service_managed_check = "unknown"
        else:
            # Absent, null, or ambiguous → unknown (not an exclusion).
            service_managed_check = "unknown"

        # principal — check both casings; unwrap nested dict to string if needed.
        principal_raw = normalized_operator.get("Principal")
        if principal_raw is None:
            principal_raw = normalized_operator.get("principal")

        if isinstance(principal_raw, str):
            operator_principal: Optional[str] = principal_raw or None
        elif isinstance(principal_raw, dict):
            unwrapped_p = principal_raw.get("Value") or principal_raw.get("value")
            operator_principal = unwrapped_p if isinstance(unwrapped_p, str) else None
        else:
            operator_principal = None

    except Exception:
        # Unexpected failure in operator metadata → unknown, not skip-item.
        service_managed_check = "unknown"
        operator_principal = None

    # Contextual fields — absent → null; never block evaluation.
    availability_zone: Optional[str] = (
        volume.get("AvailabilityZone") or volume.get("availabilityZone") or None
    )
    size_gib: Optional[int] = volume.get("Size") if "Size" in volume else volume.get("size")
    volume_type: Optional[str] = volume.get("VolumeType") or volume.get("volumeType") or None
    multi_attach_enabled: Optional[bool] = (
        volume.get("MultiAttachEnabled")
        if "MultiAttachEnabled" in volume
        else volume.get("multiAttachEnabled")
    )
    iops: Optional[int] = volume.get("Iops") if "Iops" in volume else volume.get("iops")
    throughput_mibps: Optional[int] = (
        volume.get("Throughput") if "Throughput" in volume else volume.get("throughput")
    )
    encrypted: Optional[bool] = (
        volume.get("Encrypted") if "Encrypted" in volume else volume.get("encrypted")
    )
    snapshot_id: Optional[str] = volume.get("SnapshotId") or volume.get("snapshotId") or None

    return {
        "volume_id": volume_id,
        "normalized_status": normalized_status,
        "create_time": create_time,
        "normalized_attachments": normalized_attachments,
        "attachment_count": attachment_count,
        "normalized_operator": normalized_operator,
        "service_managed_check": service_managed_check,
        "operator_principal": operator_principal,
        "availability_zone": availability_zone,
        "size_gib": size_gib,
        "volume_type": volume_type,
        "multi_attach_enabled": multi_attach_enabled,
        "iops": iops,
        "throughput_mibps": throughput_mibps,
        "encrypted": encrypted,
        "snapshot_id": snapshot_id,
    }


def find_unattached_ebs_volumes(
    session: boto3.Session,
    region: str,
    min_unattached_age_days: int = _DEFAULT_MIN_UNATTACHED_AGE_DAYS,
) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)

    try:
        paginator = ec2.get_paginator("describe_volumes")
        pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "UnauthorizedOperation":
            raise PermissionError("Missing required IAM permission: ec2:DescribeVolumes") from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    for page in pages:
        for raw_volume in page.get("Volumes", []):
            # --- Step 1: Normalize ---
            v = _normalize(raw_volume)
            if v is None:
                # Malformed record — required field absent.
                continue

            # --- Step 2: EXCLUSION_RULES (top-down, first match skips) ---

            # EXCLUSION: service-managed (Operator.Managed == True)
            if v["service_managed_check"] is True:
                continue

            # EXCLUSION: state must be available
            if v["normalized_status"] != "available":
                continue

            # EXCLUSION: any returned attachment entry
            if v["attachment_count"] > 0:
                continue

            # EXCLUSION: age threshold
            age_days = (now - v["create_time"]).days
            if age_days < min_unattached_age_days:
                continue

            # --- Detection path: unattached-volume-review-candidate ---

            evidence = Evidence(
                signals_used=[
                    "Volume state is available with attachment_count == 0",
                    f"Volume age is {age_days} days, exceeding threshold of {min_unattached_age_days} days",
                    f"service_managed_check is {v['service_managed_check']!r} (not excluded)",
                ],
                signals_not_checked=[
                    "Business/application retention intent not known",
                    "Disaster recovery, rollback, or migration retention intent not known",
                    "Future planned attachment not known",
                    "Backup/snapshot recoverability for safe deletion not verified",
                    "Filesystem or application-level dependency before detachment not known",
                    "Deletion approval workflow not checked",
                    "Volume deletion destroys data unless recoverability is handled elsewhere",
                    "Attachment/detachment transitions can be subject to short-lived AWS eventual consistency",
                ],
                time_window=f"{min_unattached_age_days} days",
            )

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.ebs.unattached",
                    resource_type="aws.ebs.volume",
                    resource_id=v["volume_id"],
                    region=region,
                    estimated_monthly_cost_usd=None,  # spec §9: flat rate invalid across volume types
                    title="Unattached EBS volume review candidate",
                    summary=(
                        f"EBS volume has been unattached for {age_days} days "
                        f"(threshold: {min_unattached_age_days} days); "
                        "review as cleanup candidate"
                    ),
                    reason=(
                        "Volume has normalized attachment_count == 0 and the "
                        "service-managed exclusion did not match"
                    ),
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.MEDIUM,
                    detected_at=now,
                    evidence=evidence,
                    details={
                        "evaluation_path": "unattached-volume-review-candidate",
                        "volume_id": v["volume_id"],
                        "create_time": v["create_time"].isoformat(),
                        "age_days": age_days,
                        "normalized_status": v["normalized_status"],
                        "attachment_count": v["attachment_count"],
                        "service_managed_check": v["service_managed_check"],
                        "operator_principal": v["operator_principal"],
                        "availability_zone": v["availability_zone"],
                        "size_gib": v["size_gib"],
                        "volume_type": v["volume_type"],
                        "multi_attach_enabled": v["multi_attach_enabled"],
                        "iops": v["iops"],
                        "throughput_mibps": v["throughput_mibps"],
                        "encrypted": v["encrypted"],
                        "snapshot_id": v["snapshot_id"],
                    },
                )
            )

    return findings
