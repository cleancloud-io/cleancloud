"""
Rule: azure.compute.disk.unattached

Intent:
    Detect Azure managed disks that are truly unattached and have remained
    unattached long enough to be conservative cleanup review candidates.

    This is a deliberately low-noise review-candidate rule only. It does not
    prove that a disk is safe to delete, that no cluster / migration / DR
    workflow exists, or that a specific monthly saving will be realized.

Exclusions:
    - id absent or empty
    - name absent or empty
    - outside optional region filter (exact lowercase match)
    - provisioning state does not resolve to exactly "Succeeded"
    - disk state does not resolve to exactly "Unattached"
    - any attachment surface present, unknown, or conflicting
    - shared-disk exclusion triggered (max_shares > 1 or unresolvable)
    - frequent-attach exclusion triggered or unresolvable
    - unattached age unknown, invalid, in the future, or less than 7 days

Detection:
    - provisioning state is "Succeeded"
    - disk state is "Unattached"
    - managed_by confirmed absent
    - managed_by_extended confirmed absent / empty
    - max_shares is known and not greater than 1
    - optimized_for_frequent_attach is False
    - unattached age >= 7 days (last_ownership_update_time primary; time_created fallback)

Cost model (spec 10):
    estimated_monthly_cost_usd = None (always)
    Azure managed disk pricing varies by disk type, size tier, redundancy, and
    for some SKUs performance configuration and shared-disk behavior.

APIs:
    - Microsoft.Compute/disks/read (compute_client.disks.list)
"""

from datetime import datetime, timezone
from typing import List, Optional, Tuple

from azure.mgmt.compute import ComputeManagementClient

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_RULE_ID = "azure.compute.disk.unattached"
_RESOURCE_TYPE = "azure.compute.disk"
_MIN_UNATTACHED_DAYS = 7

# Sentinel: field cannot be determined reliably (absent from payload OR conflicting
# across control-plane surfaces). Callers must skip when they receive this.
_UNRESOLVABLE = object()


def _norm_location(s: str) -> str:
    """Lowercase only -- exact lowercase match per spec 7."""
    return s.lower() if s else ""


# ---------------------------------------------------------------------------
# SDK-first / nested-fallback resolvers with conflict detection (spec 9.1-9.6)
# ---------------------------------------------------------------------------


def _resolve_provisioning_state(disk) -> Optional[str]:
    """
    Resolve provisioning state per spec 9.1.
    Reads both SDK projection and nested fallback. Returns None (skip) on
    conflict (both non-None but different values) or when both absent.

    Only "Succeeded" is eligible for evaluation; caller skips on anything else.
    """
    sdk_val = getattr(disk, "provisioning_state", None)

    props = getattr(disk, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, "provisioning_state", None)
        if nested_val is None:
            nested_val = getattr(props, "provisioningState", None)

    # Conflict: both surfaces have a value and they disagree -> unknown -> skip
    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None

    return sdk_val or nested_val


def _resolve_disk_state(disk) -> Optional[str]:
    """
    Resolve disk state per spec 9.2.
    Reads both SDK projection and nested fallback. Returns None (skip) on
    conflict (both non-None but different values) or when both absent.

    Only "Unattached" is eligible for emission; caller skips on anything else.
    """
    sdk_val = getattr(disk, "disk_state", None)

    props = getattr(disk, "properties", None)
    nested_val = None
    if props is not None:
        nested_val = getattr(props, "disk_state", None)
        if nested_val is None:
            nested_val = getattr(props, "diskState", None)

    # Conflict: both surfaces have a value and they disagree -> unknown -> skip
    if sdk_val is not None and nested_val is not None and sdk_val != nested_val:
        return None

    return sdk_val or nested_val


def _resolve_managed_by(disk):
    """
    Resolve managed_by per spec 9.3. Uses getattr with _UNRESOLVABLE sentinel
    to distinguish "field present with None value" (confirmed absent = not
    attached) from "field missing entirely" (unknown).

    Returns:
    - None: confirmed absent (disk not attached via managed_by)
    - str:  confirmed attached (non-empty VM resource ID)
    - _UNRESOLVABLE: field not found in any source, or SDK and nested conflict

    Callers must skip when they receive _UNRESOLVABLE.
    """
    sdk_val = getattr(disk, "managed_by", _UNRESOLVABLE)

    props = getattr(disk, "properties", None)
    nested_val = _UNRESOLVABLE
    if props is not None:
        nested_val = getattr(props, "managed_by", _UNRESOLVABLE)
        if nested_val is _UNRESOLVABLE:
            nested_val = getattr(props, "managedBy", _UNRESOLVABLE)

    sdk_found = sdk_val is not _UNRESOLVABLE
    nested_found = nested_val is not _UNRESOLVABLE

    if sdk_found and nested_found:
        # Normalize empty string to None for comparison
        sdk_eff = sdk_val or None
        nested_eff = nested_val or None
        if sdk_eff != nested_eff:
            return _UNRESOLVABLE  # surfaces disagree -> cannot resolve reliably
        return sdk_eff

    if sdk_found:
        return sdk_val or None

    if nested_found:
        return nested_val or None

    return _UNRESOLVABLE  # field absent from all sources -> unknown


def _resolve_managed_by_extended(disk):
    """
    Resolve managed_by_extended per spec 9.3. Uses _UNRESOLVABLE sentinel to
    distinguish confirmed-empty from unresolvable.

    Returns:
    - [] (empty list): confirmed absent or empty (no shared-attachment)
    - list (non-empty): confirmed shared-attached
    - _UNRESOLVABLE: field missing from all sources, uncoercible, or conflicting

    Callers must skip when they receive _UNRESOLVABLE.
    """

    def _to_list(raw):
        """Coerce raw field value to a list. Returns _UNRESOLVABLE if not iterable."""
        if raw is None:
            return []
        if raw is _UNRESOLVABLE:
            return _UNRESOLVABLE
        try:
            return list(raw)
        except TypeError:
            return _UNRESOLVABLE

    sdk_raw = getattr(disk, "managed_by_extended", _UNRESOLVABLE)

    props = getattr(disk, "properties", None)
    nested_raw = _UNRESOLVABLE
    if props is not None:
        nested_raw = getattr(props, "managed_by_extended", _UNRESOLVABLE)
        if nested_raw is _UNRESOLVABLE:
            nested_raw = getattr(props, "managedByExtended", _UNRESOLVABLE)

    sdk_found = sdk_raw is not _UNRESOLVABLE
    nested_found = nested_raw is not _UNRESOLVABLE

    if not sdk_found and not nested_found:
        return _UNRESOLVABLE  # field absent from all sources

    sdk_list = _to_list(sdk_raw) if sdk_found else _UNRESOLVABLE
    nested_list = _to_list(nested_raw) if nested_found else _UNRESOLVABLE

    # If any *present* source is uncoercible, state is unreliable -> skip.
    # sdk_list/_nested_list is _UNRESOLVABLE either because the source was absent
    # (not found) or because coercion failed; only the latter warrants a skip.
    if (sdk_found and sdk_list is _UNRESOLVABLE) or (nested_found and nested_list is _UNRESOLVABLE):
        return _UNRESOLVABLE

    if sdk_found and nested_found:
        # Conflict: one says empty, other says non-empty
        if bool(sdk_list) != bool(nested_list):
            return _UNRESOLVABLE
        return sdk_list  # both agree; SDK is authoritative

    if sdk_found:
        return sdk_list

    return nested_list


def _resolve_max_shares(disk) -> Optional[int]:
    """
    Resolve max_shares per spec 9.4.
    Reads both SDK and nested sources. Returns None (unknown -> caller skips) when
    the field is absent from all sources, when coercion fails on a present value
    (malformed -> unresolvable), or when the two surfaces disagree.
    Unknown must not be treated as equivalent to max_shares == 1.
    """

    def _to_int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None  # malformed -> caller treats source as unresolvable

    sdk_raw = getattr(disk, "max_shares", None)
    if sdk_raw is not None:
        sdk_int = _to_int(sdk_raw)
        if sdk_int is None:
            return None  # present but uncoercible -> unresolvable -> skip
    else:
        sdk_int = None

    props = getattr(disk, "properties", None)
    nested_raw = None
    if props is not None:
        nested_raw = getattr(props, "max_shares", None)
        if nested_raw is None:
            nested_raw = getattr(props, "maxShares", None)
    if nested_raw is not None:
        nested_int = _to_int(nested_raw)
        if nested_int is None:
            return None  # present but uncoercible -> unresolvable -> skip
    else:
        nested_int = None

    # Conflict: both surfaces have a value and they disagree -> unknown -> skip
    if sdk_int is not None and nested_int is not None and sdk_int != nested_int:
        return None

    return sdk_int if sdk_int is not None else nested_int


def _resolve_optimized_for_frequent_attach(disk) -> Optional[bool]:
    """
    Resolve optimized_for_frequent_attach per spec 9.5.
    Reads both SDK and nested sources. Returns None (unknown -> caller skips) when
    the field is absent from all sources, when a present value is not a reliable
    boolean (e.g. strings like "false" or unexpected types), or when surfaces disagree.
    Unknown must not be treated as False.
    """

    def _to_bool(v):
        # Only actual Python booleans are reliable. Strings such as "false" or
        # "true" must not be coerced -- bool("false") == True, which is wrong.
        if isinstance(v, bool):
            return v
        return None  # anything else -> unresolvable

    sdk_raw = getattr(disk, "optimized_for_frequent_attach", None)
    if sdk_raw is not None:
        sdk_bool = _to_bool(sdk_raw)
        if sdk_bool is None:
            return None  # present but not a reliable boolean -> unresolvable -> skip
    else:
        sdk_bool = None

    props = getattr(disk, "properties", None)
    nested_raw = None
    if props is not None:
        nested_raw = getattr(props, "optimized_for_frequent_attach", None)
        if nested_raw is None:
            nested_raw = getattr(props, "optimizedForFrequentAttach", None)
    if nested_raw is not None:
        nested_bool = _to_bool(nested_raw)
        if nested_bool is None:
            return None  # present but not a reliable boolean -> unresolvable -> skip
    else:
        nested_bool = None

    # Conflict: both surfaces have a value and they disagree -> unknown -> skip
    if sdk_bool is not None and nested_bool is not None and sdk_bool != nested_bool:
        return None

    return sdk_bool if sdk_bool is not None else nested_bool


def _coerce_datetime(val) -> Optional[datetime]:
    """
    Coerce val to a timezone-aware UTC datetime.

    Accepts:
    - datetime objects (with or without tzinfo)
    - ISO 8601 strings (Azure REST payloads use "Z" or "+00:00" suffixes)

    Returns None for None, unsupported types, or unparseable strings.
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


def _resolve_age_anchor(disk, now: datetime) -> Optional[Tuple[str, float]]:
    """
    Resolve unattached age anchor per spec 9.6.
    Returns (anchor_label, age_days) or None (skip).

    Priority:
    1. last_ownership_update_time (primary)
    2. time_created (fallback, only when primary is absent)

    If the primary is present but invalid or in the future -> skip (no fallback).
    If neither can be resolved -> skip (age unknown).
    """

    def _get_raw(obj, snake, camel):
        val = getattr(obj, snake, None)
        if val is None:
            val = getattr(obj, camel, None)
        return val

    # Primary: last_ownership_update_time
    lowt_raw = getattr(disk, "last_ownership_update_time", None)
    if lowt_raw is None:
        props = getattr(disk, "properties", None)
        if props is not None:
            lowt_raw = _get_raw(props, "last_ownership_update_time", "lastOwnershipUpdateTime")

    if lowt_raw is not None:
        # Primary is present -- use it; if invalid/future -> skip without falling back
        lowt = _coerce_datetime(lowt_raw)
        if lowt is None or lowt > now:
            return None
        return ("last_ownership_update_time", (now - lowt).total_seconds() / 86400)

    # Fallback: time_created (only when primary is absent)
    tc_raw = getattr(disk, "time_created", None)
    if tc_raw is None:
        props = getattr(disk, "properties", None)
        if props is not None:
            tc_raw = _get_raw(props, "time_created", "timeCreated")

    if tc_raw is not None:
        tc = _coerce_datetime(tc_raw)
        if tc is None or tc > now:
            return None
        return ("time_created", (now - tc).total_seconds() / 86400)

    return None  # both absent -> age unknown -> skip


def find_unattached_managed_disks(
    *,
    subscription_id: str,
    credential,
    region_filter: str = None,
    client: Optional[ComputeManagementClient] = None,
) -> List[Finding]:
    """
    Find Azure managed disks that are truly unattached and have remained
    unattached for at least 7 days.

    Detection requires:
    - provisioning state resolves to exactly "Succeeded"
    - disk state resolves to exactly "Unattached"
    - managed_by confirmed absent (not unresolvable)
    - managed_by_extended confirmed absent / empty (not unresolvable)
    - max_shares is known and not greater than 1
    - optimized_for_frequent_attach is False
    - unattached age >= 7 days (last_ownership_update_time primary; time_created fallback)

    IAM permissions:
    - Microsoft.Compute/disks/read
    """
    findings: List[Finding] = []

    compute_client = client or ComputeManagementClient(
        credential=credential,
        subscription_id=subscription_id,
    )

    now = datetime.now(timezone.utc)

    for disk in compute_client.disks.list():
        # spec 8.1: id must be present and non-empty
        disk_id = getattr(disk, "id", None)
        if not disk_id:
            continue

        # spec 8.2: name must be present and non-empty
        disk_name = getattr(disk, "name", None)
        if not disk_name:
            continue

        # spec 8.3: region filter -- exact lowercase match
        location = _norm_location(getattr(disk, "location", "") or "")
        if region_filter and location != _norm_location(region_filter):
            continue

        # spec 8.4 / 9.1: provisioning state must resolve to exactly "Succeeded"
        # Returns None on conflict or both-absent -> skip
        if _resolve_provisioning_state(disk) != "Succeeded":
            continue

        # spec 8.5 / 9.2: disk state must resolve to exactly "Unattached"
        # Returns None on conflict or both-absent -> skip
        disk_state = _resolve_disk_state(disk)
        if disk_state != "Unattached":
            continue

        # spec 8.6 / 9.3: managed_by must be confirmed absent (not attached, not unknown)
        # _UNRESOLVABLE means field absent from all sources or SDK/nested conflict -> skip
        managed_by = _resolve_managed_by(disk)
        if managed_by is _UNRESOLVABLE or managed_by:
            continue

        # spec 8.6 / 9.3: managed_by_extended must be confirmed empty (not unknown)
        managed_by_extended = _resolve_managed_by_extended(disk)
        if managed_by_extended is _UNRESOLVABLE or managed_by_extended:
            continue

        # spec 8.7 / 9.4: max_shares must be known and not > 1
        max_shares = _resolve_max_shares(disk)
        if max_shares is None or max_shares > 1:
            continue

        # spec 8.8 / 9.5: optimized_for_frequent_attach must be False (not True, not unknown)
        optimized_for_frequent_attach = _resolve_optimized_for_frequent_attach(disk)
        if optimized_for_frequent_attach is None or optimized_for_frequent_attach:
            continue

        # spec 8.9 / 9.6: unattached age must resolve and be >= 7 days
        age_result = _resolve_age_anchor(disk, now)
        if age_result is None:
            continue
        age_anchor, age_days = age_result
        if age_days < _MIN_UNATTACHED_DAYS:
            continue

        # --- EMIT ---
        sku = getattr(disk, "sku", None)
        sku_name = getattr(sku, "name", None) if sku else None
        tags = getattr(disk, "tags", None) or {}

        findings.append(
            Finding(
                provider="azure",
                rule_id=_RULE_ID,
                resource_type=_RESOURCE_TYPE,
                resource_id=disk_id,
                region=location,
                estimated_monthly_cost_usd=None,  # spec 10: always None
                title="Unattached Azure Managed Disk",
                summary=(
                    f"Managed disk '{disk_name}' has been unattached for " f"{age_days:.0f} days"
                ),
                reason=(
                    f"Disk state is 'Unattached' with no attachment surfaces and "
                    f"unattached age {age_days:.0f} days >= {_MIN_UNATTACHED_DAYS} days"
                ),
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.MEDIUM,
                detected_at=now,
                evidence=Evidence(
                    signals_used=[
                        "Provisioning state is 'Succeeded'",
                        "Disk state is 'Unattached'",
                        "managed_by confirmed absent",
                        "managed_by_extended confirmed absent / empty",
                        f"Shared-disk exclusion not triggered: max_shares = {max_shares} (not > 1)",
                        "Frequent-attach exclusion not triggered: optimized_for_frequent_attach = False",
                        f"Unattached age anchor: {age_anchor}",
                        f"Unattached age: {age_days:.1f} days (>= {_MIN_UNATTACHED_DAYS} days)",
                    ],
                    signals_not_checked=[
                        "Planned future VM attachment",
                        "Undeclared migration or restore intent",
                        "DR / backup planning intent",
                        "Exact Azure billing amount for this disk",
                        "Resource locks or delete-protection context",
                    ],
                    time_window=None,
                ),
                details={
                    "resource_name": disk_name,
                    "subscription_id": subscription_id,
                    "disk_state": disk_state,
                    "managed_by": managed_by,
                    "managed_by_extended": managed_by_extended,
                    "max_shares": max_shares,
                    "optimized_for_frequent_attach": optimized_for_frequent_attach,
                    "age_anchor": age_anchor,
                    "age_days": round(age_days, 1),
                    "sku": sku_name,
                    "size_gb": getattr(disk, "disk_size_gb", None),
                    "tags": tags,
                },
            )
        )

    return findings
