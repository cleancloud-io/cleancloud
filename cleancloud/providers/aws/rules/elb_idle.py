"""
Rule: aws.elbv2.alb.idle
Rule: aws.elbv2.nlb.idle
Rule: aws.elb.clb.idle

    (spec — docs/specs/aws/elb_idle.md)

Intent:
    Detect ALB, NLB, and CLB load balancers that are at least
    idle_days_threshold days old and show no trusted CloudWatch evidence of
    client traffic during the full lookback window, so they can be reviewed
    as potential cleanup candidates.

Exclusions:
    - resource_id absent (malformed identity)
    - lb_family == "unsupported" (gateway LB or unknown type)
    - created_time absent or not safely comparable
    - age_days < idle_days_threshold (too new to evaluate)
    - ELBv2 state_code not "active" or "active_impaired"
    - trusted traffic present (any CloudWatch signal > 0)
    - ELBv2 ARN dimension unparsable

Detection:
    - resource_id present, lb_family in {"alb","nlb","clb"}
    - age_days >= idle_days_threshold
    - ELBv2: state_code "active" or "active_impaired"
    - all traffic signals absent during full lookback window

Key rules:
    - ALB: RequestCount Sum>0, ProcessedBytes Sum>0, or ActiveConnectionCount Sum>0
    - NLB: NewFlowCount Sum>0, ProcessedBytes Sum>0, or ActiveFlowCount Maximum>0
    - NLB: missing datapoints over full window = FAIL RULE (not zero)
    - CLB: RequestCount Sum>0 or EstimatedProcessedBytes Sum>0
    - Any metric read failure = FAIL RULE; no LOW-confidence path
    - ELBv2 dimension strictly from ARN suffix after loadbalancer/; unparsable = SKIP ITEM
    - Backend registration is contextual only
    - estimated_monthly_cost_usd = None

Blind spots:
    - planned future usage or blue/green staging
    - seasonal traffic patterns outside the current lookback window
    - DNS / allowlist / manual failover dependencies
    - NLB traffic rejected by security groups (not in CloudWatch)

APIs:
    - elbv2:DescribeLoadBalancers
    - elb:DescribeLoadBalancers
    - cloudwatch:GetMetricStatistics
    - elbv2:DescribeTargetGroups (contextual)
    - elbv2:DescribeTargetHealth (contextual)
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

_DEFAULT_IDLE_DAYS_THRESHOLD = 14


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def _str(value) -> Optional[str]:
    """Return value if it is a non-empty string, else None."""
    return value if isinstance(value, str) and value else None


def _normalize_elbv2(lb: dict, idle_days_threshold: int, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw ELBv2 SDK dict to canonical fields.

    Returns None when the item must be skipped (non-dict, absent identity).
    All rule logic must operate only on the returned dict.
    """
    if not isinstance(lb, dict):
        return None

    arn = _str(lb.get("LoadBalancerArn"))
    if not arn:
        return None  # SKIP: no stable identity

    lb_type = _str(lb.get("Type"))
    if lb_type == "application":
        lb_family = "alb"
    elif lb_type == "network":
        lb_family = "nlb"
    else:
        lb_family = "unsupported"  # gateway or unknown

    name = _str(lb.get("LoadBalancerName"))

    # created_time — must be timezone-aware for age calculation.
    # Naive datetimes are not safely comparable and must not be coerced; leave absent.
    created_time_raw = lb.get("CreatedTime")
    created_time: Optional[datetime] = None
    if isinstance(created_time_raw, datetime) and created_time_raw.tzinfo is not None:
        created_time = created_time_raw.astimezone(timezone.utc)

    age_days: Optional[int] = None
    if created_time is not None:
        age_days = int((now_utc - created_time).total_seconds() // 86400)

    # state_code from nested State dict
    state_raw = lb.get("State")
    state_code: Optional[str] = None
    if isinstance(state_raw, dict):
        state_code = _str(state_raw.get("Code"))

    scheme = _str(lb.get("Scheme"))
    dns_name = _str(lb.get("DNSName"))
    vpc_id = _str(lb.get("VpcId"))

    return {
        "resource_id": arn,
        "lb_family": lb_family,
        "load_balancer_name": name,
        "load_balancer_arn": arn,
        "created_time": created_time,
        "age_days": age_days,
        "scheme": scheme,
        "dns_name": dns_name,
        "vpc_id": vpc_id,
        "state_code": state_code,
        "idle_days_threshold": idle_days_threshold,
    }


def _normalize_clb(lb: dict, idle_days_threshold: int, now_utc: datetime) -> Optional[dict]:
    """Normalize a raw CLB SDK dict to canonical fields.

    Returns None when the item must be skipped (non-dict, absent identity).
    """
    if not isinstance(lb, dict):
        return None

    name = _str(lb.get("LoadBalancerName"))
    if not name:
        return None  # SKIP: no stable identity

    # Naive datetimes are not safely comparable and must not be coerced; leave absent.
    created_time_raw = lb.get("CreatedTime")
    created_time: Optional[datetime] = None
    if isinstance(created_time_raw, datetime) and created_time_raw.tzinfo is not None:
        created_time = created_time_raw.astimezone(timezone.utc)

    age_days: Optional[int] = None
    if created_time is not None:
        age_days = int((now_utc - created_time).total_seconds() // 86400)

    scheme = _str(lb.get("Scheme"))
    dns_name = _str(lb.get("DNSName"))
    # CLB uses VPCId (capital VPC), not VpcId
    vpc_id = _str(lb.get("VPCId"))

    instances_raw = lb.get("Instances")
    instances: list = instances_raw if isinstance(instances_raw, list) else []

    return {
        "resource_id": name,
        "lb_family": "clb",
        "load_balancer_name": name,
        "load_balancer_arn": None,
        "created_time": created_time,
        "age_days": age_days,
        "scheme": scheme,
        "dns_name": dns_name,
        "vpc_id": vpc_id,
        "state_code": None,
        "idle_days_threshold": idle_days_threshold,
        "instances": instances,
    }


# ---------------------------------------------------------------------------
# CloudWatch dimension extraction
# ---------------------------------------------------------------------------


def _extract_elbv2_dimension(lb_arn: str) -> Optional[str]:
    """Extract the CloudWatch LoadBalancer dimension value from an ELBv2 ARN.

    Strictly uses the suffix after 'loadbalancer/'. Returns None if
    the suffix cannot be reliably extracted — caller must SKIP the item.

    ARN format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
    Dimension:  app/name/id
    """
    parts = lb_arn.split("loadbalancer/", 1)
    if len(parts) == 2 and parts[1]:
        return parts[1]
    return None


# ---------------------------------------------------------------------------
# CloudWatch metric fetching
# ---------------------------------------------------------------------------


def _get_metric_datapoints(
    cloudwatch,
    namespace: str,
    metric_name: str,
    statistic: str,
    dimension_name: str,
    dimension_value: str,
    start_time: datetime,
    end_time: datetime,
) -> List[dict]:
    """Fetch CloudWatch metric datapoints.

    Returns the raw list of datapoints (may be empty for ALB/CLB; see NLB caller).
    Raises PermissionError on permission errors, re-raises ClientError/BotoCoreError
    for all other failures — caller treats these as FAIL RULE.
    """
    try:
        response = cloudwatch.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": dimension_name, "Value": dimension_value}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,
            Statistics=[statistic],
        )
        return response.get("Datapoints", [])
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permission: cloudwatch:GetMetricStatistics"
            ) from exc
        raise
    except BotoCoreError:
        raise


def _check_alb_traffic(
    cloudwatch,
    dimension_value: str,
    start_time: datetime,
    end_time: datetime,
) -> bool:
    """Return True if ALB has trusted traffic over the window, False if confirmed zero.

    Checks: RequestCount Sum, ProcessedBytes Sum, ActiveConnectionCount Sum.
    Missing datapoints treated as zero (ALB only reports when traffic is present).
    Raises on metric read failure → FAIL RULE.
    """
    namespace = "AWS/ApplicationELB"
    dim = "LoadBalancer"

    for metric_name in ("RequestCount", "ProcessedBytes", "ActiveConnectionCount"):
        dps = _get_metric_datapoints(
            cloudwatch, namespace, metric_name, "Sum", dim, dimension_value, start_time, end_time
        )
        if any(dp.get("Sum", 0) > 0 for dp in dps):
            return True

    return False


def _check_nlb_traffic(
    cloudwatch,
    dimension_value: str,
    start_time: datetime,
    end_time: datetime,
    expected_days: int,
) -> bool:
    """Return True if NLB has trusted traffic over the window, False if confirmed zero.

    Checks: NewFlowCount Sum, ProcessedBytes Sum, ActiveFlowCount Maximum.
    NLB metrics are documented as always reported; incomplete coverage (fewer
    datapoints than the full window warrants) means the zero-traffic claim is
    not trustworthy → raise RuntimeError (FAIL RULE).
    Raises on metric read failure → FAIL RULE.
    """
    namespace = "AWS/NetworkELB"
    dim = "LoadBalancer"
    # Spec requires full-window coverage with no gaps; no tolerance applied.
    min_datapoints = expected_days

    for metric_name in ("NewFlowCount", "ProcessedBytes"):
        dps = _get_metric_datapoints(
            cloudwatch, namespace, metric_name, "Sum", dim, dimension_value, start_time, end_time
        )
        if len(dps) < min_datapoints:
            raise RuntimeError(
                f"NLB {metric_name} metric returned {len(dps)} datapoint(s) for a "
                f"{expected_days}-day window — coverage is incomplete, "
                "cannot confirm zero traffic"
            )
        if any(dp.get("Sum", 0) > 0 for dp in dps):
            return True

    dps = _get_metric_datapoints(
        cloudwatch,
        namespace,
        "ActiveFlowCount",
        "Maximum",
        dim,
        dimension_value,
        start_time,
        end_time,
    )
    if len(dps) < min_datapoints:
        raise RuntimeError(
            f"NLB ActiveFlowCount metric returned {len(dps)} datapoint(s) for a "
            f"{expected_days}-day window — coverage is incomplete, "
            "cannot confirm zero traffic"
        )
    if any(dp.get("Maximum", 0) > 0 for dp in dps):
        return True

    return False


def _check_clb_traffic(
    cloudwatch,
    lb_name: str,
    start_time: datetime,
    end_time: datetime,
) -> bool:
    """Return True if CLB has trusted traffic over the window, False if confirmed zero.

    Checks: RequestCount Sum, EstimatedProcessedBytes Sum.
    Missing datapoints treated as zero (CLB only reports when traffic is present).
    Raises on metric read failure → FAIL RULE.
    """
    namespace = "AWS/ELB"
    dim = "LoadBalancerName"

    for metric_name in ("RequestCount", "EstimatedProcessedBytes"):
        dps = _get_metric_datapoints(
            cloudwatch, namespace, metric_name, "Sum", dim, lb_name, start_time, end_time
        )
        if any(dp.get("Sum", 0) > 0 for dp in dps):
            return True

    return False


# ---------------------------------------------------------------------------
# Backend registration context (best-effort; failure degrades context not rule)
# ---------------------------------------------------------------------------


def _get_elbv2_backend_context(elbv2, lb_arn: str) -> tuple:
    """Return (registered_target_count, target_group_count, enrichment_succeeded).

    On any error returns (0, 0, False) — caller sets has_registered_targets = None.
    Pagination of target groups is exhausted; target health is retrieved per group.
    """
    try:
        paginator = elbv2.get_paginator("describe_target_groups")
        target_groups = []
        for page in paginator.paginate(LoadBalancerArn=lb_arn):
            target_groups.extend(page.get("TargetGroups", []))

        tg_count = len(target_groups)
        total_targets = 0
        for tg in target_groups:
            tg_arn = _str(tg.get("TargetGroupArn"))
            if not tg_arn:
                continue
            health_resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
            total_targets += len(health_resp.get("TargetHealthDescriptions", []))
        return total_targets, tg_count, True
    except (ClientError, BotoCoreError, Exception):
        return 0, 0, False


# ---------------------------------------------------------------------------
# ELBv2 (ALB + NLB) scanner
# ---------------------------------------------------------------------------


def _scan_elbv2(
    session: boto3.Session,
    region: str,
    cloudwatch,
    now_utc: datetime,
    idle_days_threshold: int,
) -> List[Finding]:
    elbv2 = session.client("elbv2", region_name=region)
    findings: List[Finding] = []
    start_time = now_utc - timedelta(days=max(idle_days_threshold, 1))

    try:
        paginator = elbv2.get_paginator("describe_load_balancers")
        pages = list(paginator.paginate())
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permission: elbv2:DescribeLoadBalancers"
            ) from exc
        raise
    except BotoCoreError:
        raise

    for page in pages:
        for raw_lb in page.get("LoadBalancers", []):
            lb = _normalize_elbv2(raw_lb, idle_days_threshold, now_utc)
            if lb is None:
                continue  # SKIP: non-dict or absent identity

            # EXCLUSION: unsupported family (gateway or unknown)
            if lb["lb_family"] == "unsupported":
                continue

            # EXCLUSION: unusable created_time
            if lb["created_time"] is None or lb["age_days"] is None:
                continue

            # EXCLUSION: too new
            if lb["age_days"] < idle_days_threshold:
                continue

            # EXCLUSION: unsupported ELBv2 state
            if lb["state_code"] not in ("active", "active_impaired"):
                continue

            # Derive CloudWatch dimension — SKIP ITEM if unparsable
            dimension_value = _extract_elbv2_dimension(lb["load_balancer_arn"])
            if dimension_value is None:
                continue  # SKIP: ARN dimension unparsable

            # --- Traffic check (raises → FAIL RULE) ---
            if lb["lb_family"] == "alb":
                has_traffic = _check_alb_traffic(cloudwatch, dimension_value, start_time, now_utc)
                traffic_signals_checked = [
                    "RequestCount:Sum",
                    "ProcessedBytes:Sum",
                    "ActiveConnectionCount:Sum",
                ]
                rule_id = "aws.elbv2.alb.idle"
                label = "ALB"
                resource_type = "aws.elbv2.load_balancer"
            else:
                has_traffic = _check_nlb_traffic(
                    cloudwatch, dimension_value, start_time, now_utc, idle_days_threshold
                )
                traffic_signals_checked = [
                    "NewFlowCount:Sum",
                    "ProcessedBytes:Sum",
                    "ActiveFlowCount:Maximum",
                ]
                rule_id = "aws.elbv2.nlb.idle"
                label = "NLB"
                resource_type = "aws.elbv2.load_balancer"

            if has_traffic:
                continue  # SKIP: trusted traffic present

            # --- Backend context (best-effort) ---
            target_count, tg_count, enrichment_ok = _get_elbv2_backend_context(
                elbv2, lb["load_balancer_arn"]
            )
            if enrichment_ok:
                has_registered_targets: Optional[bool] = target_count > 0
                details_target_count: Optional[int] = target_count
                details_tg_count: Optional[int] = tg_count
            else:
                # Enrichment failed — context unknown; do not fabricate zero counts
                has_registered_targets = None
                details_target_count = None
                details_tg_count = None

            # --- Confidence ---
            if has_registered_targets is False:
                confidence = ConfidenceLevel.HIGH
            else:
                # has targets OR unknown → MEDIUM
                confidence = ConfidenceLevel.MEDIUM

            created_time_str = lb["created_time"].isoformat() if lb["created_time"] else None

            evidence = Evidence(
                signals_used=[
                    f"Load balancer has been running for {lb['age_days']} days, "
                    f"exceeding the {idle_days_threshold}-day idle evaluation threshold",
                    f"No trusted CloudWatch traffic signal observed over the "
                    f"{idle_days_threshold}-day lookback window",
                    *(
                        ["No registered targets found"]
                        if has_registered_targets is False
                        else (
                            [f"{target_count} registered target(s) still present"]
                            if has_registered_targets
                            else []
                        )
                    ),
                ],
                signals_not_checked=[
                    "Planned future usage or blue/green staging",
                    "Seasonal traffic patterns outside the current lookback window",
                    "DNS / allowlist / manual failover dependencies still pointing at the load balancer",
                    "NLB traffic rejected by security groups, which is not captured in CloudWatch",
                ],
                time_window=f"{idle_days_threshold} days",
            )

            details = {
                "evaluation_path": "idle-load-balancer-review-candidate",
                "lb_family": lb["lb_family"],
                "resource_id": lb["resource_id"],
                "load_balancer_name": lb["load_balancer_name"],
                "load_balancer_arn": lb["load_balancer_arn"],
                "scheme": lb["scheme"],
                "dns_name": lb["dns_name"],
                "vpc_id": lb["vpc_id"],
                "created_time": created_time_str,
                "age_days": lb["age_days"],
                "idle_days_threshold": idle_days_threshold,
                "traffic_window_days": idle_days_threshold,
                "traffic_signals_checked": traffic_signals_checked,
                "traffic_detected": False,
                "state_code": lb["state_code"],
                "has_registered_targets": has_registered_targets,
                "registered_target_count": details_target_count,
                "target_group_count": details_tg_count,
            }

            findings.append(
                Finding(
                    provider="aws",
                    rule_id=rule_id,
                    resource_type=resource_type,
                    resource_id=lb["resource_id"],
                    region=region,
                    title=f"Idle {label} review candidate",
                    summary=(
                        f"{label} '{lb['load_balancer_name']}' has had no trusted CloudWatch "
                        f"traffic signal over the last {idle_days_threshold} days; "
                        "review for possible cleanup"
                    ),
                    reason=(
                        f"{label} has no trusted CloudWatch traffic signal in the last "
                        f"{idle_days_threshold} days"
                    ),
                    risk=RiskLevel.MEDIUM,
                    confidence=confidence,
                    detected_at=now_utc,
                    evidence=evidence,
                    details=details,
                    estimated_monthly_cost_usd=None,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# CLB scanner
# ---------------------------------------------------------------------------


def _scan_clb(
    session: boto3.Session,
    region: str,
    cloudwatch,
    now_utc: datetime,
    idle_days_threshold: int,
) -> List[Finding]:
    elb = session.client("elb", region_name=region)
    findings: List[Finding] = []
    start_time = now_utc - timedelta(days=max(idle_days_threshold, 1))

    try:
        paginator = elb.get_paginator("describe_load_balancers")
        pages = list(paginator.paginate())
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permission: elb:DescribeLoadBalancers"
            ) from exc
        raise
    except BotoCoreError:
        raise

    for page in pages:
        for raw_lb in page.get("LoadBalancerDescriptions", []):
            lb = _normalize_clb(raw_lb, idle_days_threshold, now_utc)
            if lb is None:
                continue  # SKIP: non-dict or absent identity

            # EXCLUSION: unusable created_time
            if lb["created_time"] is None or lb["age_days"] is None:
                continue

            # EXCLUSION: too new
            if lb["age_days"] < idle_days_threshold:
                continue

            # --- Traffic check (raises → FAIL RULE) ---
            has_traffic = _check_clb_traffic(
                cloudwatch, lb["load_balancer_name"], start_time, now_utc
            )
            if has_traffic:
                continue  # SKIP: trusted traffic present

            # --- Backend context from normalized item ---
            instances = lb["instances"]
            registered_instance_count = len(instances)
            has_registered_instances = registered_instance_count > 0

            # --- Confidence ---
            confidence = (
                ConfidenceLevel.HIGH if not has_registered_instances else ConfidenceLevel.MEDIUM
            )

            created_time_str = lb["created_time"].isoformat() if lb["created_time"] else None

            evidence = Evidence(
                signals_used=[
                    f"Load balancer has been running for {lb['age_days']} days, "
                    f"exceeding the {idle_days_threshold}-day idle evaluation threshold",
                    f"No trusted CloudWatch traffic signal observed over the "
                    f"{idle_days_threshold}-day lookback window",
                    *(
                        ["No registered instances found"]
                        if not has_registered_instances
                        else [f"{registered_instance_count} registered instance(s) still present"]
                    ),
                ],
                signals_not_checked=[
                    "Planned future usage or blue/green staging",
                    "Seasonal traffic patterns outside the current lookback window",
                    "DNS / allowlist / manual failover dependencies still pointing at the load balancer",
                ],
                time_window=f"{idle_days_threshold} days",
            )

            details = {
                "evaluation_path": "idle-load-balancer-review-candidate",
                "lb_family": "clb",
                "resource_id": lb["resource_id"],
                "load_balancer_name": lb["load_balancer_name"],
                "load_balancer_arn": None,
                "scheme": lb["scheme"],
                "dns_name": lb["dns_name"],
                "vpc_id": lb["vpc_id"],
                "created_time": created_time_str,
                "age_days": lb["age_days"],
                "idle_days_threshold": idle_days_threshold,
                "traffic_window_days": idle_days_threshold,
                "traffic_signals_checked": ["RequestCount:Sum", "EstimatedProcessedBytes:Sum"],
                "traffic_detected": False,
                "has_registered_instances": has_registered_instances,
                "registered_instance_count": registered_instance_count,
            }

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.elb.clb.idle",
                    resource_type="aws.elb.load_balancer",
                    resource_id=lb["resource_id"],
                    region=region,
                    title="Idle CLB review candidate",
                    summary=(
                        f"CLB '{lb['load_balancer_name']}' has had no trusted CloudWatch "
                        f"traffic signal over the last {idle_days_threshold} days; "
                        "review for possible cleanup"
                    ),
                    reason=(
                        f"CLB has no trusted CloudWatch traffic signal in the last "
                        f"{idle_days_threshold} days"
                    ),
                    risk=RiskLevel.MEDIUM,
                    confidence=confidence,
                    detected_at=now_utc,
                    evidence=evidence,
                    details=details,
                    estimated_monthly_cost_usd=None,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def find_idle_load_balancers(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    """Find idle ALB, NLB, and CLB load balancers with no trusted CloudWatch traffic.

    Each branch (ELBv2 and CLB) is evaluated independently.  A failure in one
    branch does not prevent the other from running.  If either branch fails the
    exception is re-raised after both have been attempted.
    """
    cloudwatch = session.client("cloudwatch", region_name=region)
    now_utc = datetime.now(timezone.utc)
    findings: List[Finding] = []
    first_exc: Optional[BaseException] = None

    try:
        findings.extend(_scan_elbv2(session, region, cloudwatch, now_utc, idle_days_threshold))
    except Exception as exc:
        first_exc = exc

    try:
        findings.extend(_scan_clb(session, region, cloudwatch, now_utc, idle_days_threshold))
    except Exception as exc:
        if first_exc is None:
            first_exc = exc

    if first_exc is not None:
        raise first_exc

    return findings
