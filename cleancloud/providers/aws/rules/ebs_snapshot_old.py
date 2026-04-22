"""
Rule: aws.ebs.snapshot.old

    (spec — docs/specs/aws/ebs_snapshot_old.md)

Intent:
    Detect old self-owned EBS snapshots that are conservative cleanup review candidates.

Exclusions:
    - status is not completed
    - storage tier is not standard
    - snapshot is linked to a self-owned AMI
    - snapshot is shared publicly or to other accounts
    - snapshot is explicitly identified as AWS Backup-managed
    - blocker checks are unavailable

Detection:
    - age >= threshold after blocker checks pass

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - Snapshot billing is incremental; cost must not be inferred from volumeSize.
    - Missing blocker visibility must cause skip, not optimism.

Blind spots:
    - business/DR intent is not known
    - AWS Backup management is not fully known unless explicitly integrated
    - deleting a snapshot might not reduce storage cost

APIs:
    - ec2:DescribeSnapshots
    - ec2:DescribeImages
    - ec2:DescribeSnapshotAttribute
"""

from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple

import boto3

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_DEFAULT_MAX_AGE_DAYS: int = 90

# Tag key prefix that indicates explicit AWS Backup management (spec 4, 5A.6).
# Only aws:backup: is defined by this spec. DLM is not in scope.
_BACKUP_TAG_PREFIX: str = "aws:backup:"


def _build_ami_snapshot_index(ec2) -> Tuple[Set[str], bool]:
    """Pre-fetch self-owned AMI block device mapping snapshot IDs.

    Returns (referenced_snapshot_ids, failed).
    If failed is True the index is incomplete and AMI linkage cannot be verified.
    Partial data collected before a failure is still used — any snapshot found in
    the partial index is still excluded.
    """
    referenced: Set[str] = set()
    try:
        paginator = ec2.get_paginator("describe_images")
        for page in paginator.paginate(Owners=["self"]):
            for ami in page.get("Images", []):
                for bdm in ami.get("BlockDeviceMappings", []):
                    snap_id = bdm.get("Ebs", {}).get("SnapshotId")
                    if snap_id:
                        referenced.add(snap_id)
    except Exception:
        return referenced, True
    return referenced, False


def _check_external_sharing(ec2, snap_id: str) -> Tuple[bool, bool]:
    """Check createVolumePermission for public or cross-account sharing.

    Returns (shared_externally, check_failed).
    Any entry in CreateVolumePermissions indicates external access because the owner
    always has implicit permission and does not appear in explicit permission entries.
    """
    try:
        resp = ec2.describe_snapshot_attribute(
            SnapshotId=snap_id,
            Attribute="createVolumePermission",
        )
        for perm in resp.get("CreateVolumePermissions", []):
            if perm.get("Group") == "all":  # public
                return True, False
            if perm.get("UserId"):  # explicit cross-account
                return True, False
        return False, False
    except Exception:
        return False, True


def _is_backup_managed(snap: dict) -> bool:
    """Return True if the snapshot has an explicit aws:backup: tag (spec 4, 5A.6).

    Only tag-based detection; full AWS Backup API integration is not in this spec.
    A negative result means UNKNOWN (no tag evidence found), not confirmed non-Backup.
    """
    for tag in snap.get("Tags", []):
        if tag.get("Key", "").startswith(_BACKUP_TAG_PREFIX):
            return True
    return False


def find_old_ebs_snapshots(
    session: boto3.Session,
    region: str,
    max_age_days: int = _DEFAULT_MAX_AGE_DAYS,
) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)

    # Build AMI snapshot index before evaluating snapshots (spec 5A.4, 6, 10).
    # If this fails, AMI linkage cannot be verified → all candidates are skipped.
    ami_snapshot_ids, ami_index_failed = _build_ami_snapshot_index(ec2)

    paginator = ec2.get_paginator("describe_snapshots")
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    for page in paginator.paginate(OwnerIds=["self"]):
        for snap in page.get("Snapshots", []):
            # --- Step 1: Parse and normalize ---
            snap_id = snap.get("SnapshotId")
            start_time = snap.get("StartTime")

            # EXCLUSION: malformed record (spec 3)
            if not snap_id or start_time is None:
                continue

            # EXCLUSION: status != completed (spec 5A.1)
            if snap.get("State") != "completed":
                continue

            # EXCLUSION: non-standard storage tier (spec 5A.2)
            # StorageTier absent → treated as standard per AWS default.
            storage_tier = snap.get("StorageTier", "standard")
            if storage_tier != "standard":
                continue

            # EXCLUSION: age threshold (spec 5A.3)
            age_days = (now - start_time).days
            if age_days < max_age_days:
                continue

            # EXCLUSION: AMI linkage (spec 5A.4, 10)
            # If the index build failed, AMI linkage cannot be verified → SKIP.
            # Never treat missing visibility as "no AMI links".
            if ami_index_failed:
                continue
            if snap_id in ami_snapshot_ids:
                continue

            # EXCLUSION: external sharing (spec 5A.5, 10)
            # Per-snapshot check. If the check fails → SKIP that snapshot.
            shared_externally, sharing_check_failed = _check_external_sharing(ec2, snap_id)
            if sharing_check_failed:
                continue
            if shared_externally:
                continue

            # EXCLUSION: explicit AWS Backup-managed (spec 5A.6)
            # Tag-based heuristic (aws:backup: prefix only). Only explicit True suppresses;
            # unknown (no tag evidence) does not block.
            if _is_backup_managed(snap):
                continue

            # --- Detection path: old-snapshot-review-candidate ---

            volume_id: Optional[str] = snap.get("VolumeId")
            volume_size_gib: Optional[int] = snap.get("VolumeSize")
            full_snapshot_size_bytes: Optional[int] = snap.get("FullSnapshotSizeInBytes")

            evidence = Evidence(
                signals_used=[
                    f"Snapshot age is {age_days} days, exceeding threshold of {max_age_days} days",
                    "No self-owned AMI linkage found",
                    "No public or cross-account create-volume permissions found",
                    "No explicit AWS Backup management tags found (tag-based check only)",
                ],
                signals_not_checked=[
                    "Business/application retention intent not known",
                    "Disaster recovery or operational workflow dependency not known",
                    "Later snapshots may reference data blocks from this snapshot — "
                    "deleting this snapshot might not reduce billed storage cost",
                    "AWS Backup management not fully verified (tag inspection only; "
                    "full AWS Backup API not integrated)",
                    "Cross-account AMI references not checked (only self-owned AMIs scanned)",
                    "Multi-volume snapshot set handling not checked",
                ],
                time_window=f"{max_age_days} days",
            )

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.ebs.snapshot.old",
                    resource_type="aws.ebs.snapshot",
                    resource_id=snap_id,
                    region=region,
                    estimated_monthly_cost_usd=None,  # spec 9: no cost from volumeSize
                    title="Old EBS snapshot review candidate",
                    summary=(
                        f"EBS snapshot is {age_days} days old "
                        f"(threshold: {max_age_days} days); "
                        "review as cleanup candidate"
                    ),
                    reason=(
                        "Snapshot exceeds age threshold and no AMI linkage, external sharing, "
                        "or explicit AWS Backup-managed signal was found"
                    ),
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.LOW,
                    detected_at=now,
                    evidence=evidence,
                    details={
                        "evaluation_path": "old-snapshot-review-candidate",
                        "snapshot_id": snap_id,
                        "start_time": start_time.isoformat(),
                        "age_days": age_days,
                        "status": snap.get("State"),
                        "storage_tier": storage_tier,
                        "ami_linked_check": False,  # checked and not present (not "not checked")
                        "create_volume_permission_check": False,  # checked and not present (not "not checked")
                        "backup_managed_check": "unknown",  # tag inspection only; absence ≠ proof of non-Backup
                        "volume_id": volume_id,
                        "volume_size_gib": volume_size_gib,
                        "full_snapshot_size_bytes": full_snapshot_size_bytes,
                    },
                )
            )

    return findings
