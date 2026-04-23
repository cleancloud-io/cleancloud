"""
Rule: azure.resource.untagged

Intent:
    Detect Azure managed disks and snapshots that currently have zero direct
    resource tags and have remained in that state long enough to be conservative
    governance review candidates.

    This is a read-only hygiene rule. It is not a waste rule, not proof that a
    resource violates a mandatory tagging policy, and not proof that a resource
    is safe to delete.

Exclusions:
    - id absent or empty
    - name absent or empty
    - outside optional region filter (exact lowercase match)
    - provisioning state does not resolve to exactly "Succeeded"
    - direct tag state is unknown or cannot be resolved reliably
    - direct current tag count > 0 (resource is tagged)
    - resource age is unknown, invalid, in the future, or less than 7 days

Detection:
    - provisioning state is "Succeeded"
    - direct resource tags resolve to zero (None or {})
    - resource age >= 7 days (time_created; SDK-first with nested fallback)

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)
    Missing tags are a governance / allocability metadata issue, not a canonical
    Azure price signal.

APIs:
    - Microsoft.Compute/disks/read (compute_client.disks.list)
    - Microsoft.Compute/snapshots/read (compute_client.snapshots.list)
"""

from datetime import datetime, timezone
from typing import List, Optional

from azure.mgmt.compute import ComputeManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.resource.untagged"
_MIN_UNTAGGED_AGE_DAYS = 7

# Sentinel: field cannot be determined reliably (absent from payload OR
# conflicting across control-plane surfaces). Callers must skip.
_UNRESOLVABLE = object()


def _norm_location(s: str) -> str:
    """Lowercase only -- exact lowercase match per spec 7."""
    return s.lower() if s else ""


# ---------------------------------------------------------------------------
# SDK-first / nested-fallback resolvers with conflict detection
# ---------------------------------------------------------------------------


def _resolve_provisioning_state(resource) -> Optional[str]:
    """
    Resolve provisioning state per spec 9.2.

    Reads both SDK projection and nested fallback. Returns None on conflict
    (both non-None but different values) or when both absent.

    Only "Succeeded" is eligible for evaluation; caller skips on anything else.
    """
    sdk_val = getattr(resource, "provisioning_state", None)

    props = getattr(resource, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, "provisioning_state", None)
        if nested_val is None:
            nested_val = getattr(props, "provisioningState", None)

    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None  # conflict -> skip

    return sdk_val or nested_val


def _resolve_tags(resource):
    """
    Resolve direct resource tag state per spec 9.3.

    Returns:
    - dict (may be empty {}): tag state resolved; caller checks len()
    - _UNRESOLVABLE: field missing entirely or non-mapping non-None value -> skip

    Required behavior:
    - None value        -> {} (zero direct tags)
    - {} empty mapping  -> {} (zero direct tags)
    - non-empty mapping -> return it (tagged -> caller skips)
    - field missing     -> _UNRESOLVABLE (unknown -> skip)
    - non-mapping, non-None -> _UNRESOLVABLE (unresolved -> skip)
    """
    raw = getattr(resource, "tags", _UNRESOLVABLE)
    if raw is _UNRESOLVABLE:
        return _UNRESOLVABLE  # field absent entirely -> unknown
    if raw is None:
        return {}  # confirmed: no tags
    if isinstance(raw, dict):
        return raw  # may be empty or non-empty; caller decides
    return _UNRESOLVABLE  # non-mapping non-None -> unresolved -> skip


def _coerce_datetime(val) -> Optional[datetime]:
    """
    Coerce val to a timezone-aware UTC datetime.

    Accepts datetime objects and ISO 8601 strings (Azure REST payloads
    use "Z" or "+00:00" suffixes). Returns None for None, unsupported
    types, or unparseable strings.
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    if isinstance(val, str):
        try:
            # Python 3.7-3.9 fromisoformat does not support "Z"; normalize first
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            return None
    return None


def _resolve_time_created(resource) -> Optional[datetime]:
    """
    Resolve creation time per spec 9.4.

    Priority:
    1. SDK projection: resource.time_created
    2. nested/raw properties: resource.properties.timeCreated

    Fail-closed: if a surface is present but unparseable or invalid, return
    None immediately -- do not fall back to the other surface.
    If both present and valid but conflict materially (> 60s difference) -> None (skip).
    If absent from all sources -> None (skip).
    """

    def _get_nested(props, snake, camel):
        val = getattr(props, snake, None)
        if val is None:
            val = getattr(props, camel, None)
        return val

    sdk_raw = getattr(resource, "time_created", None)

    props = getattr(resource, "properties", None)
    nested_raw = None
    if props is not None:
        nested_raw = _get_nested(props, "time_created", "timeCreated")

    # If a surface is present, it must parse cleanly -- no cross-surface fallback
    if sdk_raw is not None:
        sdk_dt = _coerce_datetime(sdk_raw)
        if sdk_dt is None:
            return None  # present but invalid/unparseable -> skip
    else:
        sdk_dt = None

    if nested_raw is not None:
        nested_dt = _coerce_datetime(nested_raw)
        if nested_dt is None:
            return None  # present but invalid/unparseable -> skip
    else:
        nested_dt = None

    # Conflict: both present and valid but disagree materially
    if sdk_dt is not None and nested_dt is not None:
        if abs((sdk_dt - nested_dt).total_seconds()) > 60:
            return None  # conflict -> skip

    return sdk_dt if sdk_dt is not None else nested_dt


def _resolve_disk_attachment_context(disk) -> str:
    """
    Resolve disk attachment context for confidence determination per spec 9.5.

    This is confidence-only context; it never gates emission.

    Returns:
    - "unattached":   disk_state == "Unattached", managed_by confirmed absent,
                      managed_by_extended confirmed empty -> MEDIUM confidence
    - "attached":     any attachment surface confirmed present
    - "special_state": disk_state present but not "Unattached" or "Attached"
    - "unresolved":   any required surface is unknown or conflicting

    Confidence is MEDIUM only when this returns "unattached".
    """
    props = getattr(disk, "properties", None)

    # --- disk_state ---
    sdk_ds = getattr(disk, "disk_state", None)
    nested_ds = None
    if props is not None:
        nested_ds = getattr(props, "disk_state", None)
        if nested_ds is None:
            nested_ds = getattr(props, "diskState", None)
    if sdk_ds is not None and nested_ds is not None and sdk_ds != nested_ds:
        disk_state = None  # conflict
    else:
        disk_state = sdk_ds or nested_ds

    # --- managed_by ---
    sdk_mb = getattr(disk, "managed_by", _UNRESOLVABLE)
    nested_mb = _UNRESOLVABLE
    if props is not None:
        nested_mb = getattr(props, "managed_by", _UNRESOLVABLE)
        if nested_mb is _UNRESOLVABLE:
            nested_mb = getattr(props, "managedBy", _UNRESOLVABLE)
    sdk_mb_found = sdk_mb is not _UNRESOLVABLE
    nested_mb_found = nested_mb is not _UNRESOLVABLE

    if sdk_mb_found and nested_mb_found:
        sdk_eff = sdk_mb or None
        nested_eff = nested_mb or None
        if sdk_eff != nested_eff:
            return "unresolved"  # conflict
        managed_by = sdk_eff
    elif sdk_mb_found:
        managed_by = sdk_mb or None
    elif nested_mb_found:
        managed_by = nested_mb or None
    else:
        managed_by = _UNRESOLVABLE

    if managed_by is _UNRESOLVABLE:
        return "unresolved"
    if managed_by:
        return "attached"

    # --- managed_by_extended ---
    def _to_list(raw):
        if raw is None:
            return []
        if raw is _UNRESOLVABLE:
            return _UNRESOLVABLE
        try:
            return list(raw)
        except TypeError:
            return _UNRESOLVABLE

    sdk_mbe_raw = getattr(disk, "managed_by_extended", _UNRESOLVABLE)
    nested_mbe_raw = _UNRESOLVABLE
    if props is not None:
        nested_mbe_raw = getattr(props, "managed_by_extended", _UNRESOLVABLE)
        if nested_mbe_raw is _UNRESOLVABLE:
            nested_mbe_raw = getattr(props, "managedByExtended", _UNRESOLVABLE)
    sdk_mbe_found = sdk_mbe_raw is not _UNRESOLVABLE
    nested_mbe_found = nested_mbe_raw is not _UNRESOLVABLE

    if not sdk_mbe_found and not nested_mbe_found:
        mbe = _UNRESOLVABLE
    else:
        sdk_mbe = _to_list(sdk_mbe_raw) if sdk_mbe_found else _UNRESOLVABLE
        nested_mbe = _to_list(nested_mbe_raw) if nested_mbe_found else _UNRESOLVABLE
        if (sdk_mbe_found and sdk_mbe is _UNRESOLVABLE) or (
            nested_mbe_found and nested_mbe is _UNRESOLVABLE
        ):
            mbe = _UNRESOLVABLE
        elif sdk_mbe_found and nested_mbe_found:
            if bool(sdk_mbe) != bool(nested_mbe):
                mbe = _UNRESOLVABLE
            else:
                mbe = sdk_mbe
        elif sdk_mbe_found:
            mbe = sdk_mbe
        else:
            mbe = nested_mbe

    if mbe is _UNRESOLVABLE:
        return "unresolved"
    if mbe:
        return "attached"

    # --- disk_state final check ---
    if disk_state is None:
        return "unresolved"
    if disk_state == "Unattached":
        return "unattached"
    if disk_state in ("Attached", "Reserved"):
        return "attached"
    return "special_state"


def find_untagged_resources(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[ComputeManagementClient] = None,
) -> List[Finding]:
    """
    Find Azure managed disks and snapshots with zero direct resource tags.

    Detection requires (for each resource):
    - provisioning state resolves to exactly "Succeeded"
    - direct resource tag state resolves reliably and is zero
    - resource age >= 7 days (time_created; SDK-first with nested fallback)

    IAM permissions:
    - Microsoft.Compute/disks/read
    - Microsoft.Compute/snapshots/read
    """
    findings: List[Finding] = []

    compute_client = client or ComputeManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)

    # ======================
    # Managed Disks
    # ======================
    for disk in compute_client.disks.list():
        # spec 8.2: id must be present and non-empty
        disk_id = getattr(disk, "id", None)
        if not disk_id:
            continue

        # spec 8.3: name must be present and non-empty
        disk_name = getattr(disk, "name", None)
        if not disk_name:
            continue

        # spec 8.4: region filter -- exact lowercase match
        location = _norm_location(getattr(disk, "location", "") or "")
        if region_filter and location != _norm_location(region_filter):
            continue

        # spec 8.5 / 9.2: provisioning state must resolve to exactly "Succeeded"
        prov_state = _resolve_provisioning_state(disk)
        if prov_state != "Succeeded":
            continue

        # spec 8.6 / 9.3: direct tag state must resolve reliably
        tags = _resolve_tags(disk)
        if tags is _UNRESOLVABLE:
            continue

        # spec 8.7: skip if tagged
        if tags:
            continue

        # spec 8.8 / 9.4: resource age must resolve and be >= 7 days
        time_created = _resolve_time_created(disk)
        if time_created is None or time_created > now:
            continue
        age_days = (now - time_created).total_seconds() / 86400
        if age_days < _MIN_UNTAGGED_AGE_DAYS:
            continue

        # spec 9.5: disk attachment context for confidence (never gates emission)
        attachment_context = _resolve_disk_attachment_context(disk)
        confidence = (
            ConfidenceLevel.MEDIUM if attachment_context == "unattached" else ConfidenceLevel.LOW
        )
        if attachment_context == "unattached":
            confidence_note = (
                "Attachment context appears ordinarily unattached (strengthened to MEDIUM)"
            )
        else:
            confidence_note = f"Attachment context: {attachment_context} (confidence remains LOW)"

        # Best-effort context values for details (spec 11.4)
        disk_state_detail = getattr(disk, "disk_state", None)
        managed_by_detail = getattr(disk, "managed_by", None)
        managed_by_extended_detail = getattr(disk, "managed_by_extended", None)

        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type="azure.compute.disk",
                resource_id=disk_id,
                region=location,
                estimated_monthly_cost_usd=None,  # spec 10: always None
                title="Untagged Azure Managed Disk",
                summary=(
                    f"Managed disk '{disk_name}' has zero direct tags "
                    f"and is {age_days:.0f} days old"
                ),
                reason="No direct tags found on managed disk resource",
                risk=RiskLevel.LOW,
                confidence=confidence,
                detected_at=now,
                evidence=Evidence(
                    signals_used=[
                        "Supported resource family: managed_disk",
                        "Provisioning state is 'Succeeded'",
                        "Direct resource tags resolved to zero current tags",
                        f"Resource age: {age_days:.1f} days (>= {_MIN_UNTAGGED_AGE_DAYS} days)",
                        confidence_note,
                    ],
                    signals_not_checked=[
                        "Required tag-key or tag-value policy compliance",
                        "Azure Policy remediation status",
                        "Resource-group or subscription tag intent",
                        "IaC-managed ownership intent",
                        "Future planned usage or DR / backup purpose",
                    ],
                    time_window=None,
                ),
                details={
                    "resource_name": disk_name,
                    "subscription_id": subscription_id,
                    "resource_family": "managed_disk",
                    "tags_present": False,
                    "current_tag_count": 0,
                    "age_days": round(age_days, 1),
                    "provisioning_state": prov_state,
                    "tags": tags,
                    "disk_state": disk_state_detail,
                    "managed_by": managed_by_detail,
                    "managed_by_extended": managed_by_extended_detail,
                },
            )
        )

    # ======================
    # Snapshots
    # ======================
    for snap in compute_client.snapshots.list():
        # spec 8.2: id must be present and non-empty
        snap_id = getattr(snap, "id", None)
        if not snap_id:
            continue

        # spec 8.3: name must be present and non-empty
        snap_name = getattr(snap, "name", None)
        if not snap_name:
            continue

        # spec 8.4: region filter -- exact lowercase match
        location = _norm_location(getattr(snap, "location", "") or "")
        if region_filter and location != _norm_location(region_filter):
            continue

        # spec 8.5 / 9.2: provisioning state must resolve to exactly "Succeeded"
        prov_state = _resolve_provisioning_state(snap)
        if prov_state != "Succeeded":
            continue

        # spec 8.6 / 9.3: direct tag state must resolve reliably
        tags = _resolve_tags(snap)
        if tags is _UNRESOLVABLE:
            continue

        # spec 8.7: skip if tagged
        if tags:
            continue

        # spec 8.8 / 9.4: resource age must resolve and be >= 7 days
        time_created = _resolve_time_created(snap)
        if time_created is None or time_created > now:
            continue
        age_days = (now - time_created).total_seconds() / 86400
        if age_days < _MIN_UNTAGGED_AGE_DAYS:
            continue

        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type="azure.compute.snapshot",
                resource_id=snap_id,
                region=location,
                estimated_monthly_cost_usd=None,  # spec 10: always None
                title="Untagged Azure Snapshot",
                summary=(
                    f"Snapshot '{snap_name}' has zero direct tags "
                    f"and is {age_days:.0f} days old"
                ),
                reason="No direct tags found on snapshot resource",
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.LOW,
                detected_at=now,
                evidence=Evidence(
                    signals_used=[
                        "Supported resource family: snapshot",
                        "Provisioning state is 'Succeeded'",
                        "Direct resource tags resolved to zero current tags",
                        f"Resource age: {age_days:.1f} days (>= {_MIN_UNTAGGED_AGE_DAYS} days)",
                    ],
                    signals_not_checked=[
                        "Required tag-key or tag-value policy compliance",
                        "Azure Policy remediation status",
                        "Resource-group or subscription tag intent",
                        "IaC-managed ownership intent",
                        "Future planned usage or DR / backup purpose",
                    ],
                    time_window=f">={_MIN_UNTAGGED_AGE_DAYS} days",
                ),
                details={
                    "resource_name": snap_name,
                    "subscription_id": subscription_id,
                    "resource_family": "snapshot",
                    "tags_present": False,
                    "current_tag_count": 0,
                    "age_days": round(age_days, 1),
                    "provisioning_state": prov_state,
                    "tags": tags,
                },
            )
        )

    return findings
