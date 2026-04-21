"""
Rule: aws.rds.snapshot.old

    (spec — docs/specs/aws/rds_snapshot_old.md)

Intent:
    Detect self-owned manual RDS DB snapshots that are old enough to be cleanup
    review candidates after excluding AWS-documented blocker conditions and
    externally shared/public restore dependencies.

    This is a read-only review-candidate rule. It is not a delete-safe rule,
    not proof that a snapshot is unused, and not proof that deleting it will
    reduce cost.

Exclusions:
    - db_snapshot_id absent (malformed identity)
    - snapshot_type absent or not "manual"
    - normalized_status absent or not "available"
    - trusted_snapshot_age_time_utc absent, naive, or in the future
    - age_days < max_age_days (below threshold)
    - restore-sharing attributes unavailable (DescribeDBSnapshotAttributes failure)
    - restore attribute contains "all" (public snapshot)
    - restore attribute contains one or more AWS account IDs (externally shared)

Detection:
    - db_snapshot_id present, snapshot_type == "manual", status == "available"
    - age_days >= max_age_days
    - restore-sharing attributes retrieved and confirm no public or external access

Key rules:
    - OriginalSnapshotCreateTime preferred over SnapshotCreateTime for age.
    - DescribeDBSnapshotAttributes failure → SKIP ITEM (not optimistically private).
    - DescribeDBSnapshots failure → FAIL RULE.
    - estimated_monthly_cost_usd = None.
    - Confidence: LOW always.
    - Risk: LOW always.

Blind spots:
    - Legal / compliance retention requirements
    - Disaster recovery intent
    - Restore runbook dependency
    - Operational dependency in another account or region not visible from age alone
    - Exact monthly storage cost

APIs:
    - rds:DescribeDBSnapshots
    - rds:DescribeDBSnapshotAttributes
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

_DEFAULT_MAX_AGE_DAYS = 90
_ELIGIBLE_STATUS = "available"
_ELIGIBLE_SNAPSHOT_TYPE = "manual"

_FINDING_TITLE = "Old manual RDS snapshot review candidate"

_SIGNALS_NOT_CHECKED = (
    "Legal / compliance retention requirements",
    "Disaster recovery intent",
    "Restore runbook dependency",
    "Operational dependency in another account or region not visible from age alone",
    "Exact monthly storage cost",
)


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _normalize_snapshot(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw DescribeDBSnapshots item to the canonical field shape.

    Returns None when the item is not a dict or required identity/type/status/age
    fields are absent or invalid — the caller must skip the item.
    All rule logic must operate only on the returned normalized dict.
    """
    if not isinstance(item, dict):
        return None

    # --- Identity fields (required; absent → skip) ---
    db_snapshot_id = _str(item.get("DBSnapshotIdentifier"))
    if db_snapshot_id is None:
        return None

    # --- Snapshot type (required; absent or not "manual" → skip) ---
    snapshot_type = _str(item.get("SnapshotType"))
    if snapshot_type is None:
        return None

    # --- Status (required; absent → skip) ---
    normalized_status = _str(item.get("Status"))
    if normalized_status is None:
        return None

    # --- Trusted age timestamp (required; absent/naive/future → skip item) ---
    # OriginalSnapshotCreateTime is preferred when present because it does not change
    # on copy. Fallback to SnapshotCreateTime only when OriginalSnapshotCreateTime is
    # absent (not a datetime). If the preferred field IS present but malformed (naive,
    # future, non-datetime), skip the item — no silent downgrade to secondary source.
    raw_original = item.get("OriginalSnapshotCreateTime")
    raw_create = item.get("SnapshotCreateTime")

    if raw_original is not None:
        # OriginalSnapshotCreateTime present in any form — must be a valid datetime.
        # Any non-None value that is malformed (wrong type, naive, future) → skip item.
        if not isinstance(raw_original, datetime):
            return None  # Present but wrong type → skip
        if raw_original.tzinfo is None:
            return None  # Present but naive → skip
        trusted_snapshot_age_time_utc = raw_original.astimezone(timezone.utc)
        if trusted_snapshot_age_time_utc > now_utc:
            return None  # Present but future → skip
    else:
        # OriginalSnapshotCreateTime absent (None); fall back to SnapshotCreateTime.
        if not isinstance(raw_create, datetime):
            return None
        if raw_create.tzinfo is None:
            return None  # Naive → skip
        trusted_snapshot_age_time_utc = raw_create.astimezone(timezone.utc)
        if trusted_snapshot_age_time_utc > now_utc:
            return None  # Future → skip

    age_days = int((now_utc - trusted_snapshot_age_time_utc).total_seconds() // 86400)

    # --- Core context fields (optional → null / []) ---
    db_instance_id = _str(item.get("DBInstanceIdentifier"))
    db_snapshot_arn = _str(item.get("DBSnapshotArn"))
    dbi_resource_id = _str(item.get("DbiResourceId"))
    engine = _str(item.get("Engine"))
    engine_version = _str(item.get("EngineVersion"))
    storage_type = _str(item.get("StorageType"))
    snapshot_target = _str(item.get("SnapshotTarget"))
    source_region = _str(item.get("SourceRegion"))
    source_db_snapshot_identifier = _str(item.get("SourceDBSnapshotIdentifier"))
    kms_key_id = _str(item.get("KmsKeyId"))

    raw_storage = item.get("AllocatedStorage")
    allocated_storage_gib = raw_storage if isinstance(raw_storage, int) else None

    raw_encrypted = item.get("Encrypted")
    encrypted = raw_encrypted if isinstance(raw_encrypted, bool) else None

    raw_tags = item.get("TagList")
    tag_set: list = raw_tags if isinstance(raw_tags, list) else []

    return {
        "resource_id": db_snapshot_id,
        "db_snapshot_id": db_snapshot_id,
        "snapshot_type": snapshot_type,
        "normalized_status": normalized_status,
        "trusted_snapshot_age_time_utc": trusted_snapshot_age_time_utc,
        "age_days": age_days,
        "db_instance_id": db_instance_id,
        "db_snapshot_arn": db_snapshot_arn,
        "dbi_resource_id": dbi_resource_id,
        "engine": engine,
        "engine_version": engine_version,
        "allocated_storage_gib": allocated_storage_gib,
        "storage_type": storage_type,
        "snapshot_target": snapshot_target,
        "source_region": source_region,
        "source_db_snapshot_identifier": source_db_snapshot_identifier,
        "encrypted": encrypted,
        "kms_key_id": kms_key_id,
        "tag_set": tag_set,
    }


def _get_restore_sharing(rds, db_snapshot_id: str) -> Optional[list]:
    """Fetch the restore attribute values for a manual DB snapshot.

    Returns the list of restore attribute values (may be empty) on success.
    Returns None if the API call fails — the caller must SKIP ITEM (not treat
    as optimistically private).

    A non-empty restore value containing "all" means the snapshot is public.
    A non-empty restore value containing AWS account IDs means externally shared.
    """
    try:
        resp = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=db_snapshot_id)
        attrs_result = resp.get("DBSnapshotAttributesResult", {})
        attributes = attrs_result.get("DBSnapshotAttributes", [])
        for attr in attributes:
            if attr.get("AttributeName") == "restore":
                raw_values = attr.get("AttributeValues", [])
                return raw_values if isinstance(raw_values, list) else []
        # "restore" attribute absent → no external/public restore sharing
        return []
    except (ClientError, BotoCoreError):
        return None  # API failure → visibility unavailable → caller must SKIP ITEM


def find_old_rds_snapshots(
    session: boto3.Session,
    region: str,
    max_age_days: int = _DEFAULT_MAX_AGE_DAYS,
) -> List[Finding]:
    rds = session.client("rds", region_name=region)

    try:
        paginator = rds.get_paginator("describe_db_snapshots")
        pages = list(paginator.paginate(SnapshotType=_ELIGIBLE_SNAPSHOT_TYPE))
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permission: rds:DescribeDBSnapshots"
            ) from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    for page in pages:
        for raw_item in page.get("DBSnapshots", []):
            # --- Step 1: Normalize ---
            n = _normalize_snapshot(raw_item, now)
            if n is None:
                continue

            # --- Step 2: EXCLUSION RULES ---

            # EXCLUSION: snapshot type must be manual
            if n["snapshot_type"] != _ELIGIBLE_SNAPSHOT_TYPE:
                continue

            # EXCLUSION: status must be available
            if n["normalized_status"] != _ELIGIBLE_STATUS:
                continue

            # EXCLUSION: too young
            if n["age_days"] < max_age_days:
                continue

            # --- Step 3: Restore-sharing blocker check ---
            # DescribeDBSnapshotAttributes failure → SKIP ITEM (not optimistically private)
            restore_values = _get_restore_sharing(rds, n["db_snapshot_id"])
            if restore_values is None:
                # Visibility unavailable → SKIP ITEM
                continue

            # Public snapshot: restore contains "all"
            if "all" in restore_values:
                continue

            # Externally shared: restore contains one or more AWS account IDs
            # Account IDs are strings of 12 digits; any non-"all" value is an account ID.
            account_ids = [v for v in restore_values if isinstance(v, str) and v != "all"]
            if account_ids:
                continue

            # --- Step 4: EMIT ---
            signals_used = [
                f"Snapshot type is '{_ELIGIBLE_SNAPSHOT_TYPE}'",
                f"Snapshot status is '{_ELIGIBLE_STATUS}'",
                f"Snapshot age is {n['age_days']} days, exceeding the "
                f"{max_age_days}-day configured threshold",
                "DescribeDBSnapshotAttributes restore attribute indicated no public "
                "or external restore access at evaluation time",
            ]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.rds.snapshot.old",
                    resource_type="aws.rds.snapshot",
                    resource_id=n["db_snapshot_id"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"Manual RDS snapshot {n['db_snapshot_id']} is {n['age_days']} days old "
                        f"and is a cleanup review candidate"
                    ),
                    reason=(
                        f"Manual RDS snapshot exceeds the {max_age_days}-day age threshold "
                        f"and has no public or external restore sharing"
                    ),
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.LOW,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{n['age_days']} days",
                    ),
                    details={
                        "evaluation_path": "old-manual-rds-snapshot-review-candidate",
                        "db_snapshot_id": n["db_snapshot_id"],
                        "snapshot_type": n["snapshot_type"],
                        "normalized_status": n["normalized_status"],
                        "trusted_snapshot_age_time": n["trusted_snapshot_age_time_utc"].isoformat(),
                        "age_days": n["age_days"],
                        "max_age_days": max_age_days,
                        "db_instance_id": n["db_instance_id"],
                        "engine": n["engine"],
                        "engine_version": n["engine_version"],
                        "allocated_storage_gib": n["allocated_storage_gib"],
                        "db_snapshot_arn": n["db_snapshot_arn"],
                        "dbi_resource_id": n["dbi_resource_id"],
                        "storage_type": n["storage_type"],
                        "snapshot_target": n["snapshot_target"],
                        "source_region": n["source_region"],
                        "source_db_snapshot_identifier": n["source_db_snapshot_identifier"],
                        "encrypted": n["encrypted"],
                        "kms_key_id": n["kms_key_id"],
                        "tag_set": n["tag_set"],
                    },
                )
            )

    return findings
