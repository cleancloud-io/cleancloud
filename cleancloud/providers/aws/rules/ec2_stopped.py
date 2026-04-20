"""
Rule: aws.ec2.instance.stopped

    (spec — docs/specs/aws/ec2_stopped.md)

Intent:
    Detect EC2 instances that are currently stopped and have trusted CloudTrail
    audit evidence that they have been stopped for at least the configured threshold.

Exclusions:
    - instance_id absent (malformed)
    - normalized_state absent (malformed)
    - normalized_state != "stopped"
    - trusted_stop_time absent (NO_TRUSTED_STOP_TIMESTAMP_SOURCE)
    - stopped_age_days < stopped_age_threshold_days

Detection:
    - normalized_state == "stopped"
    - trusted_stop_timestamp_source == "cloudtrail"
    - stopped_age_days >= stopped_age_threshold_days

Key rules:
    - This is a review-candidate rule, not a delete-safe rule.
    - CloudTrail LookupEvents eventTime is the sole trusted stop-time source.
    - StateTransitionReason and StateReason are diagnostic context only.
    - No MEDIUM/LOW fallback findings — HIGH confidence only when CloudTrail-backed.
    - Restart cycles handled: use latest StopInstances after most recent StartInstances.
    - CloudTrail pagination must be exhausted; no early exit after partial matches.
    - Do not use flat blended EBS storage pricing for cost estimation.

Blind spots:
    - planned reactivation or warm-standby intent not known
    - DR or migration intent not known
    - AWS control-plane dependencies outside current instance state
    - EIP costs handled by another rule
    - EC2/CloudTrail eventual-consistency windows after recent state changes

APIs:
    - ec2:DescribeInstances
    - cloudtrail:LookupEvents
    - ec2:DescribeVolumes (optional enrichment)
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_DEFAULT_STOPPED_AGE_THRESHOLD_DAYS: int = 30
_DEFAULT_CLOUDTRAIL_LOOKUP_DAYS: int = 90


def _normalize_instance(instance: dict) -> Optional[dict]:
    """Normalize a raw SDK instance dict to the canonical field shape.

    Returns None when required fields are absent and the item must be skipped.
    All rule logic must operate only on the returned normalized dict.
    """
    # Required identity
    instance_id = instance.get("InstanceId") or instance.get("instanceId")
    if not instance_id:
        return None

    # Required state — nested under State.Name or instanceState.name
    state_obj = instance.get("State") or instance.get("instanceState") or {}
    normalized_state = None
    if isinstance(state_obj, dict):
        normalized_state = state_obj.get("Name") or state_obj.get("name")
    if not normalized_state:
        return None

    # Contextual: instance type
    instance_type: Optional[str] = (
        instance.get("InstanceType") or instance.get("instanceType") or None
    )

    # Contextual: AZ
    placement = instance.get("Placement") or instance.get("placement") or {}
    availability_zone: Optional[str] = None
    if isinstance(placement, dict):
        availability_zone = (
            placement.get("AvailabilityZone") or placement.get("availabilityZone") or None
        )

    # Contextual: root device type
    root_device_type: Optional[str] = (
        instance.get("RootDeviceType") or instance.get("rootDeviceType") or None
    )

    # Diagnostic context: stop reason text (StateTransitionReason preferred)
    stop_reason_text: str = ""
    str_raw = instance.get("StateTransitionReason")
    if isinstance(str_raw, str) and str_raw:
        stop_reason_text = str_raw
    else:
        sr = instance.get("StateReason") or instance.get("stateReason") or {}
        if isinstance(sr, dict):
            msg = sr.get("Message") or sr.get("message") or ""
            stop_reason_text = msg if isinstance(msg, str) else ""

    # Diagnostic context: stop reason code
    stop_reason_code: Optional[str] = None
    sr_obj = instance.get("StateReason") or instance.get("stateReason") or {}
    if isinstance(sr_obj, dict):
        code = sr_obj.get("Code") or sr_obj.get("code")
        if isinstance(code, str) and code:
            stop_reason_code = code

    # Contextual: hibernation
    hibernation_configured: Optional[bool] = None
    hib = instance.get("HibernationOptions") or instance.get("hibernationOptions") or {}
    if isinstance(hib, dict):
        configured = hib.get("Configured")
        if configured is None:
            configured = hib.get("configured")
        if isinstance(configured, bool):
            hibernation_configured = configured

    # Attached EBS volume IDs — from block device mappings only
    attached_volume_ids: List[str] = []
    for bdm in instance.get("BlockDeviceMappings", []) or []:
        if not isinstance(bdm, dict):
            continue
        ebs = bdm.get("Ebs") or bdm.get("ebs")
        if not isinstance(ebs, dict):
            continue
        vid = ebs.get("VolumeId") or ebs.get("volumeId")
        if vid and isinstance(vid, str):
            attached_volume_ids.append(vid)

    # Tags
    tags_raw = instance.get("Tags") or instance.get("tags") or []
    tags: dict = {}
    if isinstance(tags_raw, list):
        for tag in tags_raw:
            if isinstance(tag, dict):
                k = tag.get("Key") or tag.get("key")
                v = tag.get("Value") or tag.get("value")
                if k:
                    tags[k] = v

    return {
        "instance_id": instance_id,
        "normalized_state": normalized_state,
        "instance_type": instance_type,
        "availability_zone": availability_zone,
        "root_device_type": root_device_type,
        "stop_reason_text": stop_reason_text,
        "stop_reason_code": stop_reason_code,
        "hibernation_configured": hibernation_configured,
        "attached_volume_ids": attached_volume_ids,
        "attached_volume_count": len(attached_volume_ids),
        "tags": tags,
    }


def _build_cloudtrail_stop_index(
    cloudtrail,
    region: str,
    now_utc: datetime,
    lookup_days: int,
    scanned_account_id: Optional[str] = None,
) -> Dict[str, dict]:
    """Build instance_id → latest qualifying StopInstances event record.

    Exhausts CloudTrail LookupEvents pagination for both StopInstances and
    StartInstances events. Applies restart-cycle filtering and deduplicates by
    eventId before selecting the latest qualifying stop event per instance.

    scanned_account_id: when provided, events whose recipientAccountId is present
    but does not match are rejected (cross-account guard).

    Raises PermissionError on authorization failure.
    Raises ClientError/BotoCoreError on other API or pagination failure (FAIL RULE).
    """
    start_time = now_utc - timedelta(days=lookup_days)

    # instance_id → {"stop": [event_record, ...], "start": [event_record, ...]}
    instance_events: Dict[str, Dict[str, list]] = {}
    seen_event_ids: Set[str] = set()

    for event_name in ("StopInstances", "StartInstances"):
        try:
            paginator = cloudtrail.get_paginator("lookup_events")
            pages = paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=start_time,
                EndTime=now_utc,
            )
            for page in pages:
                for event in page.get("Events", []):
                    event_id = event.get("EventId")
                    if not event_id or event_id in seen_event_ids:
                        continue

                    # Parse CloudTrailEvent JSON
                    ct_raw = event.get("CloudTrailEvent")
                    if not ct_raw:
                        continue
                    try:
                        ct_event = json.loads(ct_raw)
                    except (json.JSONDecodeError, TypeError, ValueError):
                        continue
                    if not isinstance(ct_event, dict):
                        continue

                    # Validate parsed eventName matches the lookup filter — reject
                    # mismatched or missing eventName in the payload.
                    if ct_event.get("eventName") != event_name:
                        continue

                    # Region must match exactly
                    if ct_event.get("awsRegion") != region:
                        continue

                    # Account enforcement — when scanned account is known, reject
                    # events whose recipientAccountId is present but doesn't match.
                    if scanned_account_id is not None:
                        recipient_id = ct_event.get("recipientAccountId")
                        if recipient_id is not None and recipient_id != scanned_account_id:
                            continue

                    # Parse and validate eventTime — must have timezone, must not be future
                    event_time_str = ct_event.get("eventTime")
                    if not isinstance(event_time_str, str) or not event_time_str:
                        continue
                    try:
                        event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        continue
                    if event_time.tzinfo is None:
                        continue  # reject timestamps without explicit timezone
                    event_time = event_time.astimezone(timezone.utc)
                    if event_time > now_utc:
                        continue  # reject future events

                    # Extract instance IDs from requestParameters.instancesSet.items
                    req_params = ct_event.get("requestParameters")
                    if not isinstance(req_params, dict):
                        continue
                    instances_set = req_params.get("instancesSet")
                    if not isinstance(instances_set, dict):
                        continue
                    items = instances_set.get("items")
                    if not isinstance(items, list):
                        continue

                    seen_event_ids.add(event_id)

                    event_record = {
                        "eventId": event_id,
                        "eventTime": event_time,
                        "eventName": event_name,
                        "awsRegion": ct_event.get("awsRegion"),
                        "recipientAccountId": ct_event.get("recipientAccountId"),
                    }

                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        iid = item.get("instanceId")
                        if not iid or not isinstance(iid, str):
                            continue
                        if iid not in instance_events:
                            instance_events[iid] = {"stop": [], "start": []}
                        if event_name == "StopInstances":
                            instance_events[iid]["stop"].append(event_record)
                        else:
                            instance_events[iid]["start"].append(event_record)

        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("UnauthorizedOperation", "AccessDenied"):
                raise PermissionError(
                    "Missing required IAM permission: cloudtrail:LookupEvents"
                ) from exc
            raise
        except BotoCoreError:
            raise

    # Build final stop_index: latest qualifying StopInstances event per instance
    stop_index: Dict[str, dict] = {}
    for iid, events in instance_events.items():
        stop_events = events["stop"]
        start_events = events["start"]

        if not stop_events:
            continue

        # Latest StartInstances event time (None if no start events)
        latest_start_time: Optional[datetime] = (
            max(e["eventTime"] for e in start_events) if start_events else None
        )

        # Discard stop events that predate the most recent start — stale lifecycle
        qualifying_stops = (
            [e for e in stop_events if e["eventTime"] > latest_start_time]
            if latest_start_time is not None
            else stop_events
        )

        if not qualifying_stops:
            continue

        # Select the latest qualifying stop event
        stop_index[iid] = max(qualifying_stops, key=lambda e: e["eventTime"])

    return stop_index


def _get_volume_sizes(ec2, volume_ids: List[str]) -> Dict[str, int]:
    """Best-effort EBS size enrichment. Never fails the rule."""
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
                vid = vol.get("VolumeId")
                size = vol.get("Size")
                if vid and size is not None:
                    sizes[vid] = size
    except Exception:
        pass
    return sizes


def find_stopped_ec2_instances(
    session: boto3.Session,
    region: str,
    stopped_age_threshold_days: int = _DEFAULT_STOPPED_AGE_THRESHOLD_DAYS,
    cloudtrail_lookup_days: int = _DEFAULT_CLOUDTRAIL_LOOKUP_DAYS,
) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)
    cloudtrail = session.client("cloudtrail", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    # Guard: lookup window must cover at least the threshold (spec §4).
    # A shorter window cannot prove the required stopped duration.
    if cloudtrail_lookup_days < stopped_age_threshold_days:
        return findings

    # Resolve scanned account ID for recipientAccountId enforcement (best-effort).
    # STS is not a required API; failure here does not fail the rule.
    scanned_account_id: Optional[str] = None
    try:
        sts = session.client("sts", region_name=region)
        scanned_account_id = sts.get_caller_identity()["Account"]
    except (ClientError, BotoCoreError, Exception):
        pass

    # --- Step 1: Retrieve stopped instances ---
    try:
        paginator = ec2.get_paginator("describe_instances")
        pages = list(
            paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}])
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError("Missing required IAM permission: ec2:DescribeInstances") from exc
        raise
    except BotoCoreError:
        raise

    # --- Step 2: Normalize EC2 state fields ---
    normalized_instances: List[dict] = []
    for page in pages:
        for reservation in page.get("Reservations", []):
            for raw_instance in reservation.get("Instances", []):
                v = _normalize_instance(raw_instance)
                if v is None:
                    continue
                if v["normalized_state"] != "stopped":
                    continue
                normalized_instances.append(v)

    if not normalized_instances:
        return []

    # --- Step 3: Retrieve trusted CloudTrail stop events ---
    stop_index = _build_cloudtrail_stop_index(
        cloudtrail, region, now, cloudtrail_lookup_days, scanned_account_id
    )

    # --- Step 4: Optional EBS size enrichment (best-effort) ---
    all_volume_ids: List[str] = []
    for v in normalized_instances:
        all_volume_ids.extend(v["attached_volume_ids"])
    volume_sizes = _get_volume_sizes(ec2, all_volume_ids)

    # --- Steps 5-6: Apply exclusion rules and emit findings ---
    for v in normalized_instances:
        instance_id = v["instance_id"]

        # EXCLUSION: no trusted stop time
        stop_event = stop_index.get(instance_id)
        if stop_event is None:
            continue  # NO_TRUSTED_STOP_TIMESTAMP_SOURCE

        trusted_stop_time: datetime = stop_event["eventTime"]
        stopped_age_days = int((now - trusted_stop_time).total_seconds() // 86400)

        # EXCLUSION: below threshold
        if stopped_age_days < stopped_age_threshold_days:
            continue

        # Optional EBS size context
        total_ebs_gib: Optional[int] = None
        if v["attached_volume_count"] > 0:
            total_ebs_gib = sum(volume_sizes.get(vid, 0) for vid in v["attached_volume_ids"])

        signals_used = [
            "Instance is currently in 'stopped' state",
            (
                f"Trusted stop time from CloudTrail audit: "
                f"{trusted_stop_time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
                f"(source: cloudtrail_lookup, event: {stop_event['eventName']})"
            ),
            (
                f"Stopped age is {stopped_age_days} days, meeting or exceeding "
                f"threshold of {stopped_age_threshold_days} days"
            ),
        ]
        if v["attached_volume_count"] > 0:
            signals_used.append(
                f"{v['attached_volume_count']} attached EBS volume(s) persist and "
                "may continue to incur storage charges while the instance is stopped"
            )
        else:
            signals_used.append("No attached EBS volumes detected")

        evidence = Evidence(
            signals_used=signals_used,
            signals_not_checked=[
                "Planned reactivation or warm-standby intent not known",
                "DR or migration intent not known",
                "AWS control-plane dependencies outside current instance state not checked",
                "Elastic IP costs are handled by a separate rule",
                "EC2/CloudTrail eventual-consistency windows after recent state changes "
                "(including CloudTrail delivery delay)",
            ],
            time_window=f"{stopped_age_days} days",
        )

        details: dict = {
            "evaluation_path": "stopped-instance-review-candidate",
            "instance_id": instance_id,
            "normalized_state": "stopped",
            "trusted_stop_timestamp_source": "cloudtrail",
            "trusted_stop_event_time_source": "cloudtrail_lookup",
            "trusted_stop_time": trusted_stop_time.isoformat(),
            "trusted_stop_event_name": stop_event["eventName"],
            "trusted_stop_event_id": stop_event["eventId"],
            "trusted_stop_event_account_id": stop_event.get("recipientAccountId"),
            "stopped_age_days": stopped_age_days,
            "stopped_age_threshold_days": stopped_age_threshold_days,
            "instance_type": v["instance_type"],
            "availability_zone": v["availability_zone"],
            "attached_volume_ids": v["attached_volume_ids"],
            "attached_volume_count": v["attached_volume_count"],
        }
        if v["root_device_type"] is not None:
            details["root_device_type"] = v["root_device_type"]
        if v["stop_reason_code"] is not None:
            details["stop_reason_code"] = v["stop_reason_code"]
        if v["stop_reason_text"]:
            details["stop_reason_text"] = v["stop_reason_text"]
        if v["hibernation_configured"] is not None:
            details["hibernation_configured"] = v["hibernation_configured"]
        if v["tags"]:
            details["tags"] = v["tags"]
        if total_ebs_gib is not None:
            details["total_ebs_gib"] = total_ebs_gib
        details["cloudtrail_lookup_window_days"] = cloudtrail_lookup_days

        findings.append(
            Finding(
                provider="aws",
                rule_id="aws.ec2.instance.stopped",
                resource_type="aws.ec2.instance",
                resource_id=instance_id,
                region=region,
                title="Stopped EC2 instance review candidate",
                summary=(
                    f"EC2 instance {instance_id}"
                    + (f" ({v['instance_type']})" if v["instance_type"] else "")
                    + f" has been stopped for {stopped_age_days} days"
                    + " per trusted CloudTrail audit evidence"
                    + f" (threshold: {stopped_age_threshold_days} days)"
                    + "; review as cleanup candidate"
                ),
                reason=(
                    f"Instance has been in 'stopped' state for {stopped_age_days} days "
                    f"per trusted CloudTrail stop event "
                    f"(threshold: {stopped_age_threshold_days} days)"
                ),
                risk=RiskLevel.MEDIUM,
                confidence=ConfidenceLevel.HIGH,
                detected_at=now,
                evidence=evidence,
                details=details,
                estimated_monthly_cost_usd=None,
            )
        )

    return findings
