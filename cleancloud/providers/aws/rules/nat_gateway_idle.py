"""
Rule: aws.ec2.nat_gateway.idle

    (spec — docs/specs/aws/nat_gateway_idle.md)

Intent:
    Detect NAT Gateways that are currently available, old enough to evaluate,
    and show no trusted CloudWatch traffic/activity evidence during the
    configured observation window, so they can be reviewed as possible cleanup
    candidates.

Exclusions:
    - nat_gateway_id absent (malformed identity)
    - normalized_state absent (missing current-state signal)
    - normalized_state != "available"
    - create_time_utc absent, naive, or in the future
    - age_days < idle_days_threshold (too new to evaluate)
    - any required CloudWatch metric has no datapoints (insufficient evidence)
    - any required metric shows activity > 0

Detection:
    - nat_gateway_id present, normalized_state == "available"
    - age_days >= idle_days_threshold
    - all 5 required CloudWatch metrics return datapoints and are all zero

Key rules:
    - Missing CloudWatch datapoints → SKIP ITEM (not zero).
    - CloudWatch API failure → FAIL RULE (not LOW-confidence finding).
    - 5 required metrics: BytesOutToDestination, BytesInFromSource,
      BytesInFromDestination, BytesOutToSource (Sum), ActiveConnectionCount (Maximum).
    - Route-table context is contextual only; absence does not substitute
      for CloudWatch evidence.
    - Naive CreateTime → SKIP ITEM.
    - estimated_monthly_cost_usd = None.
    - Confidence: HIGH (no route ref confirmed) or MEDIUM (route ref or unavailable).
    - Risk: MEDIUM.

Blind spots:
    - planned future usage or DR/failover intent
    - seasonal or cyclical usage outside the observation window
    - organizational ownership or business intent
    - exact region-specific pricing impact

APIs:
    - ec2:DescribeNatGateways
    - cloudwatch:GetMetricStatistics
    - ec2:DescribeRouteTables (contextual)
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# --- Module-level constants ---

_DEFAULT_IDLE_DAYS_THRESHOLD = 14
_ELIGIBLE_STATE = "available"
_CW_NAMESPACE = "AWS/NATGateway"
_CW_DIM = "NatGatewayId"

# Required metrics in evaluation order: (metric_name, statistic, detail_key)
_REQUIRED_METRICS: Tuple = (
    ("BytesOutToDestination", "Sum", "bytes_out_to_destination"),
    ("BytesInFromSource", "Sum", "bytes_in_from_source"),
    ("BytesInFromDestination", "Sum", "bytes_in_from_destination"),
    ("BytesOutToSource", "Sum", "bytes_out_to_source"),
    ("ActiveConnectionCount", "Maximum", "active_connection_count_max"),
)

_FINDING_TITLE = "Idle NAT Gateway review candidate"

_SIGNALS_NOT_CHECKED = (
    "Planned future usage or infrastructure pre-warming intent",
    "Disaster recovery or failover intent — zero traffic may be intentional",
    "Seasonal or cyclical usage patterns outside the observation window",
    "Organizational ownership or business intent",
    "Exact region-specific pricing impact",
)


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _choose_period(idle_days: int) -> int:
    """Return a deterministic Period compliant with CloudWatch retention rules.

    idle_days * 86400 is a multiple of 60, 300, and 3600, satisfying all three
    CloudWatch retention constraints for the chosen lookback window.
    """
    return idle_days * 86400


def _normalize_nat_gw(item: object, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw DescribeNatGateways item to the canonical field shape.

    Returns None when the item is not a dict or required identity/state/age fields
    are absent or invalid — the caller must skip the item.
    All rule logic must operate only on the returned normalized dict.
    """
    if not isinstance(item, dict):
        return None

    # --- Identity fields (required; absent → skip) ---
    nat_gateway_id = _str(item.get("NatGatewayId"))
    if nat_gateway_id is None:
        return None

    # --- State fields (required; absent → skip) ---
    normalized_state = _str(item.get("State"))
    if normalized_state is None:
        return None

    # --- CreateTime (required; absent, naive, or future → skip) ---
    raw_ct = item.get("CreateTime")
    if not isinstance(raw_ct, datetime):
        return None
    if raw_ct.tzinfo is None:
        # Naive datetime — cannot safely compare to UTC; treat as absent → skip.
        return None
    create_time_utc = raw_ct.astimezone(timezone.utc)
    if create_time_utc > now_utc:
        # Future CreateTime is invalid → skip.
        return None
    age_days = int((now_utc - create_time_utc).total_seconds() // 86400)

    # --- Core context fields (optional → null / []) ---
    connectivity_type = _str(item.get("ConnectivityType"))
    availability_mode = _str(item.get("AvailabilityMode"))
    vpc_id = _str(item.get("VpcId"))
    subnet_id = _str(item.get("SubnetId"))

    raw_addresses = item.get("NatGatewayAddresses")
    nat_gateway_addresses = raw_addresses if isinstance(raw_addresses, list) else []

    raw_appliances = item.get("AttachedAppliances")
    attached_appliances = raw_appliances if isinstance(raw_appliances, list) else []

    raw_tags = item.get("Tags")
    tag_set: list = raw_tags if isinstance(raw_tags, list) else []

    return {
        "resource_id": nat_gateway_id,
        "nat_gateway_id": nat_gateway_id,
        "normalized_state": normalized_state,
        "create_time_utc": create_time_utc,
        "age_days": age_days,
        "connectivity_type": connectivity_type,
        "availability_mode": availability_mode,
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "nat_gateway_addresses": nat_gateway_addresses,
        "attached_appliances": attached_appliances,
        "auto_scaling_ips": _str(item.get("AutoScalingIps")),
        "auto_provision_zones": _str(item.get("AutoProvisionZones")),
        "tag_set": tag_set,
    }


def _get_metric_value(
    cloudwatch,
    nat_gw_id: str,
    metric_name: str,
    statistic: str,
    start_time: datetime,
    end_time: datetime,
    period: int,
) -> Optional[float]:
    """Fetch a single metric over the observation window.

    Returns None if no datapoints (insufficient evidence → caller must SKIP ITEM).
    Returns the aggregated value (>= 0.0) if datapoints are present.
    Raises ClientError / BotoCoreError / PermissionError on API failure (caller → FAIL RULE).
    """
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace=_CW_NAMESPACE,
            MetricName=metric_name,
            Dimensions=[{"Name": _CW_DIM, "Value": nat_gw_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=[statistic],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permission: cloudwatch:GetMetricStatistics"
            ) from exc
        raise
    except BotoCoreError:
        raise

    datapoints = resp.get("Datapoints", [])
    if not datapoints:
        return None  # No datapoints → insufficient evidence → SKIP ITEM

    if statistic == "Sum":
        return sum(dp.get("Sum", 0.0) for dp in datapoints)
    if statistic == "Maximum":
        return max(dp.get("Maximum", 0.0) for dp in datapoints)
    # Fallback for any other statistic (not expected in this rule)
    return sum(dp.get(statistic, 0.0) for dp in datapoints)


def _check_route_table_references(ec2, nat_gw_id: str) -> Tuple[Optional[bool], bool]:
    """Check whether any VPC route table references this NAT Gateway.

    Returns (route_table_referenced, check_succeeded):
    - (False, True)  — no route table references found
    - (True, True)   — at least one route table references the NAT Gateway
    - (None, False)  — DescribeRouteTables failed; context unavailable
    """
    try:
        response = ec2.describe_route_tables(
            Filters=[{"Name": "route.nat-gateway-id", "Values": [nat_gw_id]}]
        )
        return len(response.get("RouteTables", [])) > 0, True
    except Exception:
        return None, False


def find_idle_nat_gateways(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    ec2 = session.client("ec2", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)

    try:
        paginator = ec2.get_paginator("describe_nat_gateways")
        pages = list(paginator.paginate())
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permission: ec2:DescribeNatGateways"
            ) from exc
        raise
    except BotoCoreError:
        raise

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=idle_days_threshold * 86400)
    period = _choose_period(idle_days_threshold)
    findings: List[Finding] = []

    for page in pages:
        for raw_item in page.get("NatGateways", []):
            # --- Step 1: Normalize ---
            n = _normalize_nat_gw(raw_item, now)
            if n is None:
                continue

            # --- Step 2: EXCLUSION RULES ---

            # EXCLUSION: state must be available
            if n["normalized_state"] != _ELIGIBLE_STATE:
                continue

            # EXCLUSION: too young to evaluate
            if n["age_days"] < idle_days_threshold:
                continue

            # --- Step 3: CloudWatch metrics (FAIL RULE on error; SKIP ITEM if no data) ---
            metric_values: dict = {}
            skip_insufficient = False

            for metric_name, statistic, detail_key in _REQUIRED_METRICS:
                value = _get_metric_value(
                    cloudwatch,
                    n["nat_gateway_id"],
                    metric_name,
                    statistic,
                    window_start,
                    now,
                    period,
                )
                if value is None:
                    # No datapoints for this metric → insufficient evidence → SKIP ITEM
                    skip_insufficient = True
                    break
                metric_values[detail_key] = value

            if skip_insufficient:
                continue

            # EXCLUSION: any metric shows activity
            if any(v > 0 for v in metric_values.values()):
                continue

            # --- Step 4: Route-table context (optional; failure degrades context only) ---
            route_table_referenced, rt_check_ok = _check_route_table_references(
                ec2, n["nat_gateway_id"]
            )

            # --- Step 5: Confidence ---
            if rt_check_ok and route_table_referenced is False:
                confidence = ConfidenceLevel.HIGH
                rt_signal = "No VPC route table references this NAT Gateway"
            elif rt_check_ok and route_table_referenced is True:
                confidence = ConfidenceLevel.MEDIUM
                rt_signal = "At least one VPC route table still references this NAT Gateway"
            else:
                confidence = ConfidenceLevel.MEDIUM
                rt_signal = "Route-table context unavailable (DescribeRouteTables failed)"

            reason = (
                f"NAT Gateway has no trusted CloudWatch traffic signal "
                f"in the last {idle_days_threshold} days"
            )

            signals_used = [
                f"NAT Gateway State is '{_ELIGIBLE_STATE}' (able to process traffic)",
                f"Age is {n['age_days']} days, meeting the {idle_days_threshold}-day threshold",
                "All 5 required CloudWatch activity metrics returned datapoints and are zero "
                f"for the {idle_days_threshold}-day observation window "
                "(CleanCloud-derived idle heuristic)",
                rt_signal,
            ]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.ec2.nat_gateway.idle",
                    resource_type="aws.ec2.nat_gateway",
                    resource_id=n["nat_gateway_id"],
                    region=region,
                    estimated_monthly_cost_usd=None,
                    title=_FINDING_TITLE,
                    summary=(
                        f"NAT Gateway {n['nat_gateway_id']} has no trusted CloudWatch "
                        f"traffic signal in the last {idle_days_threshold} days"
                    ),
                    reason=reason,
                    risk=RiskLevel.MEDIUM,
                    confidence=confidence,
                    detected_at=now,
                    evidence=Evidence(
                        signals_used=signals_used,
                        signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                        time_window=f"{idle_days_threshold} days",
                    ),
                    details={
                        "evaluation_path": "idle-nat-gateway-review-candidate",
                        "nat_gateway_id": n["nat_gateway_id"],
                        "normalized_state": n["normalized_state"],
                        "create_time": n["create_time_utc"].isoformat(),
                        "age_days": n["age_days"],
                        "idle_days_threshold": idle_days_threshold,
                        "connectivity_type": n["connectivity_type"],
                        "availability_mode": n["availability_mode"],
                        "vpc_id": n["vpc_id"],
                        "subnet_id": n["subnet_id"],
                        "bytes_out_to_destination": metric_values["bytes_out_to_destination"],
                        "bytes_in_from_source": metric_values["bytes_in_from_source"],
                        "bytes_in_from_destination": metric_values["bytes_in_from_destination"],
                        "bytes_out_to_source": metric_values["bytes_out_to_source"],
                        "active_connection_count_max": metric_values["active_connection_count_max"],
                        "route_table_referenced": route_table_referenced,
                        "nat_gateway_addresses": n["nat_gateway_addresses"],
                        "attached_appliances": n["attached_appliances"],
                        "auto_scaling_ips": n["auto_scaling_ips"],
                        "auto_provision_zones": n["auto_provision_zones"],
                        "tag_set": n["tag_set"],
                    },
                )
            )

    return findings
