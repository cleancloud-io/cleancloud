import re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Matches all known stop-reason formats that include a timestamp:
#   "User initiated (YYYY-MM-DD HH:MM:SS UTC)"      — manual stop via console/CLI
#   "Instance initiated (YYYY-MM-DD HH:MM:SS UTC)"  — OS-initiated shutdown
#   "Server.ScheduledStop (YYYY-MM-DD HH:MM:SS UTC)"— AWS scheduled maintenance
# If AWS adds a new format, stop_time will be None → instance flagged at MEDIUM confidence,
# not missed. Unrecognised formats are under-confident, not false negatives.
_STATE_TRANSITION_RE = re.compile(
    r"(?:User initiated|Instance initiated|Server\.ScheduledStop)"
    r" \((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC\)"
)

# ~$0.10/GB-month (gp2/gp3 average, us-east-1)
_EBS_COST_PER_GB = 0.10


def find_stopped_ec2_instances(
    session: boto3.Session,
    region: str,
    max_age_days: int = 30,
) -> List[Finding]:
    """
    Find EC2 instances in 'stopped' state for 30+ days.

    Stopped instances do not incur compute charges, but every attached EBS
    volume continues to accrue storage costs every hour — silently, month
    after month. A stopped instance sitting forgotten for 30+ days is the
    clearest signal of abandoned infrastructure: the test box that was never
    terminated, the migration source that never got cleaned up, the dev
    server that outlasted the project.

    Detection logic:
    - Instance state is 'stopped'
    - StateTransitionReason parses to a recognised stop pattern ≥ max_age_days days ago
    - Recognised patterns: User initiated, Instance initiated, Server.ScheduledStop
    - If stop time is unparseable, instance is still flagged at MEDIUM confidence
      (stop duration unknown — may be recent or very old)

    Cost impact:
    - Attached EBS volumes charge ~$0.10/GB-month regardless of instance state

    IAM permissions:
    - ec2:DescribeInstances
    - ec2:DescribeVolumes
    """
    ec2 = session.client("ec2", region_name=region)
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=max_age_days)
    findings: List[Finding] = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        pages = paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}])

        # Collect stopped instances and their attached volume IDs.
        # stop_time=None means the timestamp was unparseable — these are still
        # included but emitted at MEDIUM confidence.
        stopped_instances = []
        all_volume_ids: List[str] = []

        for page in pages:
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    state_reason = instance.get("StateTransitionReason", "")
                    stop_time = _parse_stop_time(state_reason)

                    # If stop time is known, apply the threshold filter
                    if stop_time is not None and stop_time > threshold:
                        continue

                    # Empty reason almost always means a very recent state change
                    # (AWS hasn't populated the field yet) — skip to avoid false positives.
                    # A non-empty but unparseable reason is older/unusual and worth flagging.
                    if stop_time is None and not state_reason:
                        continue

                    volume_ids = [
                        bdm["Ebs"]["VolumeId"]
                        for bdm in instance.get("BlockDeviceMappings", [])
                        if "Ebs" in bdm
                    ]
                    all_volume_ids.extend(volume_ids)
                    stopped_instances.append((instance, stop_time, volume_ids))

        if not stopped_instances:
            return []

        # Batch-fetch volume sizes for cost estimation
        volume_sizes = _get_volume_sizes(ec2, all_volume_ids)

        for instance, stop_time, volume_ids in stopped_instances:
            instance_id = instance["InstanceId"]
            instance_type = instance.get("InstanceType", "unknown")
            tags = instance.get("Tags", [])
            az = instance.get("Placement", {}).get("AvailabilityZone", "")

            stop_time_known = stop_time is not None
            days_stopped_actual: Optional[int] = (
                int((now - stop_time).total_seconds() // 86400) if stop_time_known else None
            )

            total_ebs_gb = sum(volume_sizes.get(vid, 0) for vid in volume_ids)
            cost_usd: Optional[float] = (
                round(total_ebs_gb * _EBS_COST_PER_GB, 2) if total_ebs_gb > 0 else None
            )

            if stop_time_known:
                signals = [
                    f"Instance has been in 'stopped' state for {days_stopped_actual} days",
                    f"Stopped at: {stop_time.strftime('%Y-%m-%d %H:%M UTC')}",
                    f"Instance type: {instance_type}",
                ]
            else:
                signals = [
                    "Instance is in 'stopped' state",
                    "Stop duration unknown — may be recent or long-lived",
                    f"Instance type: {instance_type}",
                ]

            if total_ebs_gb > 0:
                vol_count = len(volume_ids)
                signals.append(
                    f"{vol_count} attached EBS volume{'s' if vol_count != 1 else ''} "
                    f"({total_ebs_gb} GB total) — accruing ~${cost_usd}/month in storage charges"
                )
                signals.append(
                    "EBS cost estimate uses average pricing (~$0.10/GB-month across gp2/gp3)"
                )
            else:
                signals.append("No attached EBS volumes detected")

            evidence = Evidence(
                signals_used=signals,
                signals_not_checked=[
                    "Planned reactivation or standby use",
                    "Disaster recovery intent",
                    "Pending migration or handoff",
                    "Associated Elastic IPs (checked separately by elastic_ip rule)",
                ],
                time_window=(f"{days_stopped_actual} days" if stop_time_known else "unknown"),
            )

            # Confidence: HIGH when stop time is known (precise duration over threshold).
            # MEDIUM when stop time is unavailable — instance is stopped but we cannot
            # confirm it has been idle for the full threshold period.
            confidence = ConfidenceLevel.HIGH if stop_time_known else ConfidenceLevel.MEDIUM

            if stop_time_known:
                title = f"Stopped EC2 Instance ({days_stopped_actual} Days)"
                reason = f"Instance has been in 'stopped' state for {days_stopped_actual}+ days"
                summary = (
                    f"EC2 instance '{instance_id}' ({instance_type}) has been stopped for "
                    f"{days_stopped_actual} days. Attached EBS volumes continue to accrue "
                    f"storage charges even while the instance is off."
                )
            else:
                title = "Stopped EC2 Instance (Duration Unknown)"
                reason = "Instance is in 'stopped' state — stop duration could not be determined"
                summary = (
                    f"EC2 instance '{instance_id}' ({instance_type}) is stopped with no "
                    f"parseable stop time. Attached EBS volumes may be accruing storage charges."
                )

            details: dict = {
                "instance_type": instance_type,
                "availability_zone": az,
                "total_ebs_gb": total_ebs_gb,
                "attached_volume_ids": volume_ids,
                "days_stopped_threshold": max_age_days,
            }
            if stop_time_known:
                details["stop_time"] = stop_time.isoformat()
                details["days_stopped"] = days_stopped_actual
            if tags:
                details["tags"] = {t["Key"]: t["Value"] for t in tags}

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.ec2.instance.stopped",
                    resource_type="aws.ec2.instance",
                    resource_id=instance_id,
                    region=region,
                    title=title,
                    summary=summary,
                    reason=reason,
                    risk=RiskLevel.MEDIUM,
                    confidence=confidence,
                    detected_at=now,
                    evidence=evidence,
                    details=details,
                    estimated_monthly_cost_usd=cost_usd,
                )
            )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError("Missing required IAM permission: ec2:DescribeInstances") from e
        raise

    return findings


def _parse_stop_time(reason: str) -> Optional[datetime]:
    """
    Parse the stop timestamp from StateTransitionReason.

    Recognised formats:
      "User initiated (YYYY-MM-DD HH:MM:SS UTC)"       — console/CLI stop
      "Instance initiated (YYYY-MM-DD HH:MM:SS UTC)"   — OS-level shutdown
      "Server.ScheduledStop (YYYY-MM-DD HH:MM:SS UTC)" — AWS scheduled maintenance

    Returns None if no recognised format is found.
    """
    m = _STATE_TRANSITION_RE.search(reason)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _get_volume_sizes(ec2, volume_ids: List[str]) -> Dict[str, int]:
    """Return a mapping of volume_id -> size_gb for the given volume IDs."""
    if not volume_ids:
        return {}

    sizes: Dict[str, int] = {}
    unique_ids = list(dict.fromkeys(volume_ids))
    chunk_size = 200

    try:
        for i in range(0, len(unique_ids), chunk_size):
            chunk = unique_ids[i : i + chunk_size]
            resp = ec2.describe_volumes(VolumeIds=chunk)
            for vol in resp.get("Volumes", []):
                sizes[vol["VolumeId"]] = vol["Size"]
    except ClientError:
        # Best-effort: cost estimate will be 0 if volumes are inaccessible
        pass

    return sizes
