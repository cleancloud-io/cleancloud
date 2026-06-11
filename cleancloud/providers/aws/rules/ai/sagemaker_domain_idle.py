"""
Rule: aws.sagemaker.domain.idle

    (spec — docs/specs/aws/ai/sagemaker_domain_idle.md)

Intent:
    Detect Amazon SageMaker Domains that are InService, old enough to evaluate,
    and have no currently running apps across all user profiles and spaces, so
    they can be reviewed as potential FinOps cleanup candidates.

    A SageMaker Domain creates a managed EFS file system on first user onboarding.
    That file system persists and incurs continuous storage charges regardless of
    whether any Studio apps are running. A domain with no active apps represents
    wasted EFS cost with no current compute value.

    This is a read-only review-candidate rule — not a delete-safe rule.

Exclusions:
    - DomainArn absent (malformed identity)
    - DomainId absent (cannot filter ListApps)
    - Status absent or not "InService"
    - CreationTime absent, naive, or future
    - age_days < idle_days_threshold (too young)
    - any app in InService or Pending status
    - any app entry with unclassifiable Status (absent or undocumented value)
    - DescribeDomain non-permission failure (item-scoped skip)

Detection:
    - InService domain older than idle_days_threshold
    - ListApps fully paginated, zero apps in InService or Pending status

Key rules:
    - Signal: control-plane ListApps state (sole trusted activity source)
    - LastUserActivityTimestamp explicitly excluded (contaminated by health checks)
    - estimated_monthly_cost_usd = None
    - Confidence: HIGH always (direct control-plane state)
    - Risk: HIGH if HomeEfsFileSystemId present; MEDIUM otherwise
    - ListDomains failure → FAIL RULE
    - ListApps failure → FAIL RULE
    - Permission-denied on any required API → FAIL RULE
    - DescribeDomain non-permission failure → SKIP ITEM
    - Unclassifiable app Status → SKIP ITEM (domain not emitted)

APIs:
    - sagemaker:ListDomains
    - sagemaker:DescribeDomain
    - sagemaker:ListApps
"""

from collections import Counter
from datetime import datetime, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

_DEFAULT_IDLE_DAYS_THRESHOLD = 30
_ELIGIBLE_STATUS = "InService"

# Documented App.Status values — anything else is unclassifiable
_KNOWN_APP_STATUSES = {"Deleted", "Deleting", "Failed", "InService", "Pending"}

# App statuses that indicate active compute presence
_BILLABLE_APP_STATUSES = {"InService", "Pending"}

_PERMISSION_ERROR_CODES = ("AccessDenied", "UnauthorizedOperation", "AccessDeniedException")

_FINDING_TITLE = "Idle SageMaker domain review candidate"

_SIGNALS_NOT_CHECKED = (
    "LastUserActivityTimestamp from DescribeApp was not used as evidence because "
    "AWS documents it as updated on health checks, making it unreliable as a "
    "user-activity signal",
    "A user may start a new app shortly after evaluation; this is a point-in-time check",
    "The domain may be intentionally kept active for periodic or scheduled use",
    "Deleting apps may transition back to InService if the deletion fails",
    "EFS storage cost depends on per-user home directory content; this rule does not "
    "inspect directory sizes or file counts",
    "Native idle shutdown configuration (AppLifecycleManagement.IdleSettings) is surfaced "
    "as context but does not affect eligibility",
)

RULE_METADATA = {
    "id": "aws.sagemaker.domain.idle",
    "category": "ai",
    "service": "sagemaker",
    "cost_impact": "high",
}


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _check_idle_shutdown(settings: dict) -> bool:
    """Check if idle shutdown is enabled in JupyterLab or CodeEditor app settings."""
    for app_key in ("JupyterLabAppSettings", "CodeEditorAppSettings"):
        app_settings = settings.get(app_key, {})
        if not isinstance(app_settings, dict):
            continue
        lifecycle = app_settings.get("AppLifecycleManagement", {})
        if not isinstance(lifecycle, dict):
            continue
        idle_settings = lifecycle.get("IdleSettings", {})
        if not isinstance(idle_settings, dict):
            continue
        if idle_settings.get("LifecycleManagement") == "Enabled":
            return True
    return False


def _normalize_domain(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw ListDomains item to the canonical field shape.

    Returns None when required identity/status/timestamp fields are absent or
    invalid — the caller must skip the item.
    """
    if not isinstance(item, dict):
        return None

    # --- Identity (required; absent → skip) ---
    domain_arn = _str(item.get("DomainArn"))
    if domain_arn is None:
        return None

    domain_id = _str(item.get("DomainId"))
    if domain_id is None:
        return None

    # --- Status (required; absent → skip) ---
    normalized_status = _str(item.get("Status"))
    if normalized_status is None:
        return None

    # --- CreationTime (required; absent, naive, future → skip) ---
    raw_ct = item.get("CreationTime")
    if not isinstance(raw_ct, datetime):
        return None
    if raw_ct.tzinfo is None:
        return None
    creation_time_utc = raw_ct.astimezone(timezone.utc)
    if creation_time_utc > now_utc:
        return None

    # --- Derived fields ---
    age_days = int((now_utc - creation_time_utc).total_seconds() // 86400)

    # --- Optional context fields ---
    domain_name = _str(item.get("DomainName"))

    raw_lmt = item.get("LastModifiedTime")
    last_modified_time_utc = None
    if isinstance(raw_lmt, datetime) and raw_lmt.tzinfo is not None:
        lmt = raw_lmt.astimezone(timezone.utc)
        if lmt <= now_utc:
            last_modified_time_utc = lmt

    return {
        "resource_id": domain_arn,
        "domain_arn": domain_arn,
        "domain_id": domain_id,
        "domain_name": domain_name,
        "normalized_status": normalized_status,
        "creation_time_utc": creation_time_utc,
        "last_modified_time_utc": last_modified_time_utc,
        "age_days": age_days,
    }


def _enrich_domain(describe_response: dict) -> dict:
    """Extract enrichment fields from DescribeDomain response."""
    home_efs_id = _str(describe_response.get("HomeEfsFileSystemId"))
    home_efs_creation = _str(describe_response.get("HomeEfsFileSystemCreation"))
    app_network_access_type = _str(describe_response.get("AppNetworkAccessType"))
    auth_mode = _str(describe_response.get("AuthMode"))

    # Check idle shutdown across both DefaultUserSettings and DefaultSpaceSettings
    idle_shutdown = False
    for settings_key in ("DefaultUserSettings", "DefaultSpaceSettings"):
        settings = describe_response.get(settings_key, {})
        if isinstance(settings, dict) and _check_idle_shutdown(settings):
            idle_shutdown = True
            break

    return {
        "home_efs_file_system_id": home_efs_id,
        "home_efs_file_system_creation": home_efs_creation,
        "app_network_access_type": app_network_access_type,
        "auth_mode": auth_mode,
        "idle_shutdown_configured": idle_shutdown,
    }


def find_idle_sagemaker_domains(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    sagemaker = session.client("sagemaker", region_name=region)

    # --- Step 1: Validate permission, then fully paginate ListDomains ---
    # Pre-flight direct call catches AccessDeniedException reliably even if
    # the paginator were to silently return an empty page on permission errors.
    try:
        sagemaker.list_domains(MaxResults=1)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in _PERMISSION_ERROR_CODES:
            raise PermissionError("Missing required IAM permission: sagemaker:ListDomains") from exc
        raise
    except BotoCoreError:
        raise

    try:
        paginator = sagemaker.get_paginator("list_domains")
        pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] in _PERMISSION_ERROR_CODES:
            raise PermissionError("Missing required IAM permission: sagemaker:ListDomains") from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    for page in pages:
        for raw_item in page.get("Domains", []):
            # --- Step 2: Normalize domain summary ---
            n = _normalize_domain(raw_item, now)
            if n is None:
                continue

            # --- Step 3: Exclusion rules ---
            if n["normalized_status"] != _ELIGIBLE_STATUS:
                continue

            if n["age_days"] < idle_days_threshold:
                continue

            # --- Step 4: DescribeDomain enrichment ---
            try:
                describe = sagemaker.describe_domain(DomainId=n["domain_id"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] in _PERMISSION_ERROR_CODES:
                    raise PermissionError(
                        "Missing required IAM permission: sagemaker:DescribeDomain"
                    ) from exc
                continue  # non-permission failure → SKIP ITEM
            except BotoCoreError:
                continue  # transport error → SKIP ITEM

            enrichment = _enrich_domain(describe)
            n.update(enrichment)

            # --- Step 6: ListApps for this domain ---
            try:
                apps_paginator = sagemaker.get_paginator("list_apps")
                apps_pages = list(apps_paginator.paginate(DomainIdEquals=n["domain_id"]))
            except ClientError as exc:
                if exc.response["Error"]["Code"] in _PERMISSION_ERROR_CODES:
                    raise PermissionError(
                        "Missing required IAM permission: sagemaker:ListApps"
                    ) from exc
                raise  # other ListApps failure → FAIL RULE
            except BotoCoreError:
                raise  # transport failure → FAIL RULE

            # --- Step 7-9: Evaluate app statuses ---
            status_counts: Counter = Counter()
            skip_domain = False

            for apps_page in apps_pages:
                for app_entry in apps_page.get("Apps", []):
                    # Non-dict entries have no extractable status →
                    # unclassifiable, handled by the check below.
                    raw_status = (
                        _str(app_entry.get("Status")) if isinstance(app_entry, dict) else None
                    )

                    # Unclassifiable status → SKIP ITEM
                    if raw_status is None or raw_status not in _KNOWN_APP_STATUSES:
                        skip_domain = True
                        break

                    status_counts[raw_status] += 1

                    # Billable app → SKIP ITEM
                    if raw_status in _BILLABLE_APP_STATUSES:
                        skip_domain = True
                        break

                if skip_domain:
                    break

            if skip_domain:
                continue

            # --- Step 10: EMIT ---
            total_apps = sum(status_counts.values())
            apps_by_status = dict(status_counts)

            has_efs = n["home_efs_file_system_id"] is not None
            risk = RiskLevel.HIGH if has_efs else RiskLevel.MEDIUM

            efs_signal = (
                f"EFS file system {n['home_efs_file_system_id']} incurs continuous "
                f"storage charges"
                if has_efs
                else "No HomeEfsFileSystemId was returned by DescribeDomain"
            )

            signals_used = [
                f"Domain status is '{_ELIGIBLE_STATUS}'",
                f"Domain age is {n['age_days']} days, meeting the "
                f"{idle_days_threshold}-day threshold (applied to domain age, "
                f"not measured inactivity duration)",
                "ListApps was fully paginated and found zero apps in InService " "or Pending state",
                efs_signal,
            ]

            domain_display = n["domain_name"] or n["domain_id"]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.sagemaker.domain.idle",
                    resource_type="aws.sagemaker.domain",
                    resource_id=n["domain_arn"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"SageMaker domain {domain_display} is currently InService, "
                        f"{n['age_days']} days old, and has no running apps"
                    ),
                    reason=(
                        f"InService SageMaker domain is {n['age_days']} days old "
                        f"and currently has no InService or Pending apps across "
                        f"all user profiles and spaces"
                    ),
                    risk=risk,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{idle_days_threshold} days",
                    ),
                    details={
                        "evaluation_path": "idle-sagemaker-domain-review-candidate",
                        "domain_arn": n["domain_arn"],
                        "domain_id": n["domain_id"],
                        "domain_name": n["domain_name"],
                        "normalized_status": n["normalized_status"],
                        "creation_time": n["creation_time_utc"].isoformat(),
                        "age_days": n["age_days"],
                        "idle_days_threshold": idle_days_threshold,
                        "home_efs_file_system_id": n["home_efs_file_system_id"],
                        "home_efs_file_system_creation": n["home_efs_file_system_creation"],
                        "app_network_access_type": n["app_network_access_type"],
                        "auth_mode": n["auth_mode"],
                        "idle_shutdown_configured": n["idle_shutdown_configured"],
                        "total_apps_evaluated": total_apps,
                        "apps_by_status": apps_by_status,
                        "inservice_app_count": 0,
                        "pending_app_count": 0,
                    },
                )
            )

    return findings
