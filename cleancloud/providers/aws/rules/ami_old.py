from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# ── Constants ──────────────────────────────────────────────────────────────────
_RECENTLY_ACTIVE_DAYS: int = 30
_DEFAULT_MAX_AGE_DAYS: int = 180
_LT_INDEX_GUARD: int = 1_000
_LC_INDEX_GUARD: int = 5_000

# Rule: aws.ec2.ami.old  (spec — docs/specs/aws/ami_old.md)
#
# Intent:
#   Detect self-owned available AMIs that are likely stale lifecycle candidates.
#
# Signal classes:
#   EXCLUSION   (non-deprecated only): recent launch, active instances
#   SCORING     (non-deprecated only): age >= threshold (+1), stale last launch (+1)
#   CONTEXTUAL  (non-scoring):         LT/LC refs, API visibility gaps, cost metadata
#
# Key rules:
#   - Deprecated AMIs always emit HIGH-confidence findings (no exclusion applies).
#   - Missing lastLaunchedTime is UNKNOWN — not "never launched", not inactive.
#   - Missing active-instance data is UNKNOWN — not "no instances":
#       score == 1 (borderline) + check failed → SKIP (conservative).
#       score == 2 + check failed → emit, apply contextual downgrade.
#   - LT/LC never affect score; max one confidence downgrade across all
#     contextual sources combined.
#   - Cost is informational only (never affects score / confidence / risk).
#
# Blind spots:
#   lastLaunchedTime has ~24h ingestion delay and incomplete historical coverage.
#   LT/LC references do not prove active ASG usage.
#   Snapshot billing differs from AMI metadata volume sizes.
#
# APIs:
#   Required:    ec2:DescribeImages
#   Best-effort: ec2:DescribeImageAttribute, ec2:DescribeInstances,
#                ec2:DescribeLaunchTemplates, ec2:DescribeLaunchTemplateVersions,
#                autoscaling:DescribeLaunchConfigurations


def find_old_amis(
    session: boto3.Session,
    region: str,
    max_age_days: int = _DEFAULT_MAX_AGE_DAYS,
) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)
    autoscaling = session.client("autoscaling", region_name=region)
    now = datetime.now(timezone.utc)

    lt_index, lt_index_failed = _build_lt_index(ec2)
    lc_index, lc_index_failed = _build_lc_index(autoscaling)

    findings: List[Finding] = []

    try:
        paginator = ec2.get_paginator("describe_images")
        for page in paginator.paginate(Owners=["self"]):
            for ami in page.get("Images", []):
                finding = _evaluate_ami(
                    ami=ami,
                    ec2=ec2,
                    now=now,
                    max_age_days=max_age_days,
                    lt_index=lt_index,
                    lt_index_failed=lt_index_failed,
                    lc_index=lc_index,
                    lc_index_failed=lc_index_failed,
                    region=region,
                )
                if finding is not None:
                    findings.append(finding)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError("Missing required IAM permission: ec2:DescribeImages") from exc
        raise

    return findings


# ── Per-AMI evaluation ────────────────────────────────────────────────────────


def _evaluate_ami(
    ami: dict,
    ec2,
    now: datetime,
    max_age_days: int,
    lt_index: Dict[str, List[str]],
    lt_index_failed: bool,
    lc_index: Dict[str, List[str]],
    lc_index_failed: bool,
    region: str,
) -> Optional[Finding]:
    """
    Evaluate one AMI against spec v4. Returns a Finding or None.

    Mandatory evaluation order (spec §6):
      1. Parse + normalize
      2. Check deprecation override
      3. Fetch best-effort signals
      4. EXCLUSION_RULES (non-deprecated only)
      5. SCORING_SIGNALS (non-deprecated only)
      6. CONTEXTUAL_SIGNALS
      7. Assign confidence
      8. Assign risk
      9. Build evidence + finding
    """
    # ── 1. Parse + normalize ──────────────────────────────────────────────────
    ami_id = ami.get("ImageId")
    if not ami_id:
        return None

    ami_state = ami.get("State", "unknown")
    if ami_state != "available":
        return None

    creation_date_str = ami.get("CreationDate")
    if not creation_date_str:
        return None
    try:
        creation_date = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

    age_days = (now - creation_date).days
    ami_name = ami.get("Name", "unnamed")

    # ── 2. Check deprecation override ────────────────────────────────────────
    is_deprecated = False
    deprecation_date: Optional[datetime] = None
    dep_str = ami.get("DeprecationTime")
    if dep_str:
        try:
            dt = datetime.fromisoformat(dep_str.replace("Z", "+00:00"))
            deprecation_date = dt  # always store — future dates are useful context
            if dt <= now:
                is_deprecated = True  # Path A only when already past
            # Future DeprecationTime → treat as Path B (not yet deprecated)
        except (ValueError, TypeError):
            pass  # invalid value → treat as non-deprecated

    # ── 3. Fetch best-effort signals ──────────────────────────────────────────
    last_launched, launched_fetch_failed = _get_last_launched_time(ec2, ami_id)
    days_since_launched: Optional[int] = (
        (now - last_launched).days if last_launched is not None else None
    )

    active_found, instance_check_failed = _check_active_instances(ec2, ami_id)

    # LT/LC refs from pre-built indexes (O(1) per AMI).
    # Always use whatever partial data exists — the failed flag only controls
    # the signals_not_checked note (partial visibility caveat).
    lt_refs = lt_index.get(ami_id, [])
    lc_refs = lc_index.get(ami_id, [])

    # ── Path A: Deprecated override ───────────────────────────────────────────
    if is_deprecated:
        # EXCLUSION_RULES do not apply to deprecated AMIs.
        # Contextual signals do not suppress or modify confidence.
        confidence = ConfidenceLevel.HIGH
        risk = RiskLevel.HIGH if active_found else RiskLevel.MEDIUM
        title = "Deprecated AMI Still In Use" if active_found else "Deprecated AMI"
        evaluation_path = "deprecated"
        score: Optional[int] = None
        stale_last_launch = False
        contextual_downgrade = False

    # ── Path B: Non-deprecated scored ────────────────────────────────────────
    else:
        evaluation_path = "scored"

        # ── 4. EXCLUSION_RULES ────────────────────────────────────────────────
        # Rule: recently launched (lastLaunchedTime must exist and be recent).
        # Missing lastLaunchedTime does NOT trigger exclusion (spec §5.A).
        if days_since_launched is not None and days_since_launched < _RECENTLY_ACTIVE_DAYS:
            return None

        # Rule: active instances exist → skip (hard exclusion).
        if active_found:
            return None

        # ── 5. SCORING_SIGNALS ────────────────────────────────────────────────
        stale_last_launch = days_since_launched is not None and days_since_launched >= max_age_days
        score = 0
        if age_days >= max_age_days:
            score += 1
        if stale_last_launch:
            score += 1

        if score == 0:
            return None

        # Conservative: unknown active-instance state + borderline score → skip.
        # Absence of instance check ≠ absence of instances (spec §13).
        if instance_check_failed and score == 1:
            return None

        # ── 6. CONTEXTUAL_SIGNALS ─────────────────────────────────────────────
        # Triggers (max 1 total downgrade regardless of how many fire):
        # - LT references in $Default or $Latest versions
        # - LC references
        # - Unknown active-instance state (API visibility gap)
        contextual_downgrade = bool(lt_refs or lc_refs or instance_check_failed)

        # ── 7. Confidence ─────────────────────────────────────────────────────
        base = ConfidenceLevel.MEDIUM if score == 2 else ConfidenceLevel.LOW
        confidence = (
            ConfidenceLevel.LOW
            if (contextual_downgrade and base == ConfidenceLevel.MEDIUM)
            else base
        )

        # ── 8. Risk ───────────────────────────────────────────────────────────
        # MEDIUM: non-deprecated + BOTH signals (score 2).
        # Guardrail: score 2 → risk MUST be >= MEDIUM (spec §9).
        risk = RiskLevel.MEDIUM if score == 2 else RiskLevel.LOW

        # Title (spec §16 + §13):
        # - Never label "Unused" if active instances exist.
        # - Never label "Unused" if active-instance state is UNKNOWN (check failed) —
        #   missing visibility ≠ "no instances" ≠ "unused".
        title = (
            "Unused AMI"
            if stale_last_launch and not instance_check_failed
            else f"AMI Older Than {max_age_days} Days"
        )

    # ── 9. Build evidence + finding ───────────────────────────────────────────
    snapshot_ids: List[str] = []
    declared_gb: int = 0
    for bd in ami.get("BlockDeviceMappings", []):
        ebs = bd.get("Ebs", {})
        if ebs.get("SnapshotId"):
            snapshot_ids.append(ebs["SnapshotId"])
            size = ebs.get("VolumeSize")
            if isinstance(size, (int, float)):
                declared_gb += int(size)

    cost_usd: Optional[float] = round(declared_gb * 0.05, 2) if declared_gb > 0 else None

    evidence = _build_evidence(
        evaluation_path=evaluation_path,
        is_deprecated=is_deprecated,
        age_days=age_days,
        max_age_days=max_age_days,
        ami_state=ami_state,
        deprecation_date=deprecation_date,
        last_launched=last_launched,
        days_since_launched=days_since_launched,
        launched_fetch_failed=launched_fetch_failed,
        active_found=active_found,
        instance_check_failed=instance_check_failed,
        lt_refs=lt_refs,
        lt_index_failed=lt_index_failed,
        lc_refs=lc_refs,
        lc_index_failed=lc_index_failed,
        snapshot_ids=snapshot_ids,
        declared_gb=declared_gb,
        cost_usd=cost_usd,
        contextual_downgrade=contextual_downgrade,
    )

    summary = (
        f"AMI '{ami_name}' ({ami_id}) is {age_days} days old"
        + (" and explicitly deprecated" if is_deprecated else "")
        + (
            f", last launched {days_since_launched} days ago"
            if days_since_launched is not None
            else ""
        )
        + "."
    )

    if is_deprecated and active_found:
        reason = (
            f"AMI deprecated ({deprecation_date.strftime('%Y-%m-%d')}) "
            "with active running instances — migration required"
        )
    elif is_deprecated:
        reason = (
            f"AMI deprecated ({deprecation_date.strftime('%Y-%m-%d')}), " f"{age_days} days old"
        )
    elif stale_last_launch:
        reason = f"AMI not launched in {days_since_launched} days " f"(age: {age_days} days)"
    else:
        reason = f"AMI is {age_days} days old (threshold: {max_age_days} days)"

    return Finding(
        provider="aws",
        rule_id="aws.ec2.ami.old",
        resource_type="aws.ec2.ami",
        resource_id=ami_id,
        region=region,
        estimated_monthly_cost_usd=cost_usd,
        title=title,
        summary=summary,
        reason=reason,
        risk=risk,
        confidence=confidence,
        detected_at=now,
        evidence=evidence,
        details={
            "ami_name": ami_name,
            "creation_date": creation_date.isoformat(),
            "age_days": age_days,
            "state": ami_state,
            "platform": ami.get("PlatformDetails", "Linux/UNIX"),
            "architecture": ami.get("Architecture", "x86_64"),
            "root_device_type": ami.get("RootDeviceType", "ebs"),
            "is_deprecated": is_deprecated,
            "deprecation_time": (deprecation_date.isoformat() if deprecation_date else None),
            "last_launched_time": (last_launched.isoformat() if last_launched else None),
            "days_since_last_launch": days_since_launched,
            "active_instances_found": None if instance_check_failed else active_found,
            "instance_check_failed": instance_check_failed,
            "launch_template_refs": lt_refs,
            "launch_config_refs": lc_refs,
            "snapshot_ids": snapshot_ids,
            "declared_volume_size_gb": declared_gb,
            "estimated_monthly_cost": (
                f"≤~${cost_usd}/month (upper bound — AMI metadata ≠ actual snapshot "
                f"billing; ~$0.05/GB-month, varies by region)"
                if cost_usd
                else None
            ),
            "tags": {t["Key"]: t["Value"] for t in ami.get("Tags", [])},
        },
    )


# ── Evidence builder ──────────────────────────────────────────────────────────


def _build_evidence(  # noqa: PLR0913
    *,
    evaluation_path: str,
    is_deprecated: bool,
    age_days: int,
    max_age_days: int,
    ami_state: str,
    deprecation_date: Optional[datetime],
    last_launched: Optional[datetime],
    days_since_launched: Optional[int],
    launched_fetch_failed: bool,
    active_found: bool,
    instance_check_failed: bool,
    lt_refs: List[str],
    lt_index_failed: bool,
    lc_refs: List[str],
    lc_index_failed: bool,
    snapshot_ids: List[str],
    declared_gb: int,
    cost_usd: Optional[float],
    contextual_downgrade: bool,
) -> Evidence:
    """
    Build Evidence per spec §15.
    All fields must exist; null is allowed but fields must not be omitted.
    Evaluation path must be exactly "deprecated" or "scored" (spec §17).
    signals_not_checked: permission/visibility gaps first, then conceptual blind spots.
    """
    signals: List[str] = []
    not_checked: List[str] = []

    # evaluation_path (spec §17)
    signals.append(f"evaluation_path: {evaluation_path}")

    # age + state
    signals.append(f"age: {age_days}d (threshold: {max_age_days}d) | state: {ami_state}")

    # deprecation status
    if is_deprecated:
        signals.append(f"deprecated: true ({deprecation_date.strftime('%Y-%m-%d')} — past)")
    elif deprecation_date is not None:
        signals.append(
            f"deprecated: false (DeprecationTime {deprecation_date.strftime('%Y-%m-%d')} — future)"
        )
    else:
        signals.append("deprecated: false (DeprecationTime not set)")

    # last launch status (null allowed, never omitted)
    if launched_fetch_failed:
        not_checked.append(
            "lastLaunchedTime — ec2:DescribeImageAttribute unavailable "
            "(~24h delay; partial coverage since April 2017)"
        )
        signals.append("last_launched: null (fetch failed — see signals_not_checked)")
    elif last_launched is not None:
        stale = days_since_launched is not None and days_since_launched >= max_age_days
        label = "stale" if stale else "recent"
        signals.append(
            f"last_launched: {last_launched.strftime('%Y-%m-%d')} "
            f"({days_since_launched}d ago) — {label} "
            f"(partial signal: ~24h delay, coverage from April 2017 only)"
        )
    else:
        signals.append(
            "last_launched: null (no record since April 2017 — "
            "unknown; absence of record ≠ proof of non-use)"
        )

    # active instance status (null allowed, never omitted)
    if instance_check_failed:
        not_checked.append(
            "active instances — ec2:DescribeInstances unavailable "
            "(absence of check ≠ no instances)"
        )
        signals.append(
            "active_instances: unknown (check failed — "
            "absence of check ≠ proof of absence; see signals_not_checked)"
        )
    elif active_found:
        signals.append(
            "active_instances: found (running/pending) — "
            "deregistering does not terminate running instances"
        )
    else:
        signals.append("active_instances: none found (existence check, MaxResults=5)")

    # LT refs (null allowed, never omitted)
    if lt_index_failed:
        not_checked.append(
            "launch template references — ec2:DescribeLaunchTemplates or "
            "ec2:DescribeLaunchTemplateVersions unavailable"
        )
        signals.append("lt_refs: null (fetch failed — see signals_not_checked)")
    elif lt_refs:
        ids_str = ", ".join(lt_refs[:5]) + ("..." if len(lt_refs) > 5 else "")
        signals.append(
            f"lt_refs: {len(lt_refs)} template(s) ({ids_str}) — "
            "$Default + $Latest versions checked; verify before deregistering"
        )
    else:
        signals.append("lt_refs: none ($Default + $Latest versions checked)")

    # LC refs (null allowed, never omitted)
    if lc_index_failed:
        not_checked.append(
            "launch configuration references — "
            "autoscaling:DescribeLaunchConfigurations unavailable"
        )
        signals.append("lc_refs: null (fetch failed — see signals_not_checked)")
    elif lc_refs:
        names_str = ", ".join(lc_refs[:5]) + ("..." if len(lc_refs) > 5 else "")
        signals.append(
            f"lc_refs: {len(lc_refs)} config(s) ({names_str}) — " "verify before deregistering"
        )
    else:
        signals.append("lc_refs: none")

    # snapshot/volume metadata (null allowed, never omitted)
    if snapshot_ids:
        cost_note = f"≤~${cost_usd}/month" if cost_usd else "unknown"
        signals.append(
            f"snapshots: {len(snapshot_ids)} EBS snapshot(s), {declared_gb} GB declared — "
            f"estimated {cost_note} (upper bound; AMI metadata ≠ actual billing; "
            f"~$0.05/GB-month, varies by region)"
        )
    else:
        signals.append("snapshots: none")

    # Contextual downgrade note (only in Path B)
    if contextual_downgrade:
        signals.append(
            "contextual_downgrade: applied (max 1 level total) — "
            "confidence reduced due to LT/LC refs or unknown active-instance state"
        )

    # Permanent conceptual blind spots (always appended after permission gaps)
    not_checked.extend(
        [
            "LT/LC reference does not prove active ASG usage",
            "compliance and audit retention requirements",
            "golden image or disaster recovery intent",
        ]
    )

    return Evidence(
        signals_used=signals,
        signals_not_checked=not_checked,
        time_window=f"{max_age_days} days",
    )


# ── AWS API helpers ───────────────────────────────────────────────────────────


def _get_last_launched_time(ec2, ami_id: str) -> Tuple[Optional[datetime], bool]:
    """
    Fetch LastLaunchedTime via DescribeImageAttribute.
    Returns (last_launched, fetch_failed).
    AWS note: tracked since April 2017 only; ~24h ingestion delay.
    """
    try:
        resp = ec2.describe_image_attribute(ImageId=ami_id, Attribute="lastLaunchedTime")
        value = resp.get("LastLaunchedTime", {}).get("Value")
        if not isinstance(value, str) or not value:
            return None, False
        return datetime.fromisoformat(value.replace("Z", "+00:00")), False
    except Exception:
        return None, True


def _check_active_instances(ec2, ami_id: str) -> Tuple[bool, bool]:
    """
    Return (instances_found, check_failed).
    Existence check — MaxResults=5, EC2 filters server-side.
    CRITICAL (spec §13): check_failed ≠ "no instances" — treat result as UNKNOWN.
    """
    try:
        resp = ec2.describe_instances(
            Filters=[
                {"Name": "image-id", "Values": [ami_id]},
                {"Name": "instance-state-name", "Values": ["running", "pending"]},
            ],
            MaxResults=5,
        )
        found = any(r.get("Instances") for r in resp.get("Reservations", []))
        return found, False
    except Exception:
        return False, True


def _build_lt_index(ec2) -> Tuple[Dict[str, List[str]], bool]:
    """
    Build {ami_id: [lt_ids]} by checking $Default + $Latest versions of each LT.
    Per spec §11: "prefer $Default + $Latest; full traversal optional."

    Phase 1: list all LT IDs (with guard at _LT_INDEX_GUARD).
    Phase 2: per-LT, query $Default + $Latest versions only (no pagination needed).

    Returns (index, is_partial_or_failed).
    """
    try:
        lt_ids: List[str] = []
        lt_truncated = False
        kwargs: Dict = {}
        while True:
            resp = ec2.describe_launch_templates(**kwargs)
            for lt in resp.get("LaunchTemplates", []):
                lt_id = lt.get("LaunchTemplateId")
                if lt_id:
                    lt_ids.append(lt_id)
            if len(lt_ids) > _LT_INDEX_GUARD:
                lt_ids = lt_ids[:_LT_INDEX_GUARD]
                lt_truncated = True
                break
            nxt = resp.get("NextToken")
            if not isinstance(nxt, str) or not nxt:
                break
            kwargs["NextToken"] = nxt

        index: Dict[str, set] = {}
        for lt_id in lt_ids:
            try:
                resp = ec2.describe_launch_template_versions(
                    LaunchTemplateId=lt_id,
                    Versions=["$Default", "$Latest"],
                )
                for v in resp.get("LaunchTemplateVersions", []):
                    image_id = v.get("LaunchTemplateData", {}).get("ImageId")
                    v_lt_id = v.get("LaunchTemplateId")
                    if image_id and v_lt_id:
                        index.setdefault(image_id, set()).add(v_lt_id)
            except Exception:
                continue  # best-effort per LT

        return {k: sorted(v) for k, v in index.items()}, lt_truncated
    except Exception:
        return {}, True


def _build_lc_index(autoscaling) -> Tuple[Dict[str, List[str]], bool]:
    """
    Build {ami_id: [lc_names]} across all launch configurations.
    DescribeLaunchConfigurations has no ImageId filter — full scan required.
    Guard: stops at _LC_INDEX_GUARD configs and returns partial index.
    Returns (index, is_partial_or_failed).
    """
    try:
        index: Dict[str, set] = {}
        lc_count = 0
        lc_truncated = False
        kwargs: Dict = {}
        while True:
            resp = autoscaling.describe_launch_configurations(**kwargs)
            for lc in resp.get("LaunchConfigurations", []):
                ami = lc.get("ImageId")
                lc_name = lc.get("LaunchConfigurationName")
                if ami and lc_name:
                    index.setdefault(ami, set()).add(lc_name)
                lc_count += 1
                if lc_count >= _LC_INDEX_GUARD:
                    lc_truncated = True
                    break
            if lc_truncated:
                break
            nxt = resp.get("NextToken")
            if not isinstance(nxt, str) or not nxt:
                break
            kwargs["NextToken"] = nxt
        return {k: sorted(v) for k, v in index.items()}, lc_truncated
    except Exception:
        return {}, True
