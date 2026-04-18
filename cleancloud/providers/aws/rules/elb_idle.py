from datetime import datetime, timedelta, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_idle_load_balancers(
    session: boto3.Session,
    region: str,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find idle Elastic Load Balancers (ALB, NLB, CLB) with no traffic.

    ELBs have a base hourly charge regardless of usage (~$16-22/month).
    Idle load balancers with no traffic are a clear cost optimization signal.

    Detection logic:
    - LB is older than `idle_days` days
    - Zero traffic over the `idle_days` period (CloudWatch metrics)
    - No registered targets (ALB/NLB) or no registered instances (CLB)

    Confidence:
    - HIGH: Zero traffic AND no targets/instances
    - MEDIUM: Zero traffic only

    IAM permissions:
    - elasticloadbalancing:DescribeLoadBalancers
    - elasticloadbalancing:DescribeTargetGroups
    - elasticloadbalancing:DescribeTargetHealth
    - cloudwatch:GetMetricStatistics
    """
    cloudwatch = session.client("cloudwatch", region_name=region)
    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    # Scan ALB/NLB via elbv2
    findings.extend(_scan_elbv2(session, region, cloudwatch, now, idle_days))

    # Scan CLB via elb
    findings.extend(_scan_clb(session, region, cloudwatch, now, idle_days))

    return findings


def _scan_elbv2(
    session: boto3.Session,
    region: str,
    cloudwatch,
    now: datetime,
    idle_days: int,
) -> List[Finding]:
    """Scan ALB and NLB load balancers for idle resources."""
    elbv2 = session.client("elbv2", region_name=region)
    findings: List[Finding] = []

    try:
        paginator = elbv2.get_paginator("describe_load_balancers")

        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                lb_arn = lb["LoadBalancerArn"]
                lb_name = lb.get("LoadBalancerName", lb_arn)
                lb_type = lb.get("Type", "application")  # application or network

                # Calculate age
                create_time = lb.get("CreatedTime")
                age_days = 0
                if create_time:
                    try:
                        age_days = (now - create_time).days
                    except TypeError:
                        pass

                # Skip if younger than threshold
                if age_days < idle_days:
                    continue

                # Check traffic via CloudWatch
                has_traffic, traffic_fetch_failed = _check_elbv2_traffic(
                    cloudwatch, lb_arn, lb_type, idle_days
                )
                # has_traffic=True with fetch_failed=False → confirmed traffic, skip.
                # has_traffic=True with fetch_failed=True → metric unreadable; create LOW-confidence
                # finding so the operator knows to verify manually rather than silently suppress.
                if has_traffic and not traffic_fetch_failed:
                    continue

                # Check registered targets
                has_targets = _check_elbv2_targets(elbv2, lb_arn)

                # Determine confidence
                if traffic_fetch_failed:
                    # Metric read failed — traffic status unknown; operator must verify
                    confidence = ConfidenceLevel.LOW
                elif not has_targets:
                    confidence = ConfidenceLevel.HIGH
                else:
                    confidence = ConfidenceLevel.MEDIUM

                type_label = "ALB" if lb_type == "application" else "NLB"
                rule_id = "aws.elbv2.alb.idle" if lb_type == "application" else "aws.elbv2.nlb.idle"
                primary_metric = "RequestCount" if lb_type == "application" else "NewFlowCount"
                scheme = lb.get("Scheme", "unknown")

                signals = [
                    f"Load balancer type: {type_label}",
                    f"Scheme: {scheme}",
                    f"State: {lb.get('State', {}).get('Code', 'unknown')}",
                ]
                if not traffic_fetch_failed:
                    signals.insert(
                        0,
                        f"Zero {primary_metric} and ProcessedBytes for {idle_days} days (CloudWatch)",
                    )

                if not has_targets:
                    signals.append("No registered targets")
                if age_days > 0:
                    signals.append(f"Load balancer is {age_days} days old")

                signals_not_checked = [
                    "Planned future usage",
                    "Blue/green deployment scenarios",
                    "Seasonal traffic patterns",
                    "Internal health-check-only usage",
                ]
                if traffic_fetch_failed:
                    signals_not_checked.insert(
                        0,
                        f"Traffic metrics ({primary_metric}, ProcessedBytes) — CloudWatch fetch "
                        "failed (transient/throttle error); traffic status unverified",
                    )

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=signals_not_checked,
                    time_window=f"{idle_days} days",
                )

                if traffic_fetch_failed:
                    title = f"{type_label} Requires Traffic Verification"
                    summary = (
                        f"{type_label} '{lb_name}' could not be verified as idle — "
                        f"CloudWatch traffic metrics were unreadable (transient/throttle error)."
                    )
                    reason = f"{type_label} traffic metrics could not be fetched; idle status is unconfirmed"
                else:
                    title = f"Idle {type_label} (No Traffic for {idle_days}+ Days)"
                    summary = (
                        f"{type_label} '{lb_name}' has had zero traffic for "
                        f"{idle_days}+ days and is incurring base charges."
                    )
                    reason = f"{type_label} has zero traffic for {idle_days}+ days"

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id=rule_id,
                        resource_type="aws.elbv2.load_balancer",
                        resource_id=lb_arn,
                        region=region,
                        estimated_monthly_cost_usd=18.0,
                        title=title,
                        summary=summary,
                        reason=reason,
                        risk=RiskLevel.MEDIUM,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "name": lb_name,
                            "type": lb_type,
                            "scheme": scheme,
                            "state": lb.get("State", {}).get("Code", "unknown"),
                            "dns_name": lb.get("DNSName"),
                            "vpc_id": lb.get("VpcId"),
                            "age_days": age_days,
                            "has_targets": has_targets,
                            "idle_days_threshold": idle_days,
                            "estimated_monthly_cost": (
                                "~$16-22/month base cost (us-east-1 on-demand; "
                                "region-dependent; excludes LCU/NLCU usage charges)"
                            ),
                        },
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError(
                "Missing required IAM permissions: "
                "elasticloadbalancing:DescribeLoadBalancers, "
                "elasticloadbalancing:DescribeTargetGroups, "
                "elasticloadbalancing:DescribeTargetHealth, "
                "cloudwatch:GetMetricStatistics"
            ) from e
        raise

    return findings


def _scan_clb(
    session: boto3.Session,
    region: str,
    cloudwatch,
    now: datetime,
    idle_days: int,
) -> List[Finding]:
    """Scan Classic Load Balancers for idle resources."""
    elb = session.client("elb", region_name=region)
    findings: List[Finding] = []

    try:
        paginator = elb.get_paginator("describe_load_balancers")

        for page in paginator.paginate():
            for lb in page.get("LoadBalancerDescriptions", []):
                lb_name = lb["LoadBalancerName"]

                # Calculate age
                create_time = lb.get("CreatedTime")
                age_days = 0
                if create_time:
                    try:
                        age_days = (now - create_time).days
                    except TypeError:
                        pass

                # Skip if younger than threshold
                if age_days < idle_days:
                    continue

                # Check traffic via CloudWatch
                has_traffic, traffic_fetch_failed = _check_clb_traffic(
                    cloudwatch, lb_name, idle_days
                )
                # has_traffic=True with fetch_failed=False → confirmed traffic, skip.
                # has_traffic=True with fetch_failed=True → metric unreadable; create LOW-confidence
                # finding so the operator knows to verify manually rather than silently suppress.
                if has_traffic and not traffic_fetch_failed:
                    continue

                # Check registered instances
                instances = lb.get("Instances", [])
                has_instances = len(instances) > 0
                scheme = lb.get("Scheme", "unknown")

                # Determine confidence
                if traffic_fetch_failed:
                    confidence = ConfidenceLevel.LOW
                elif not has_instances:
                    confidence = ConfidenceLevel.HIGH
                else:
                    confidence = ConfidenceLevel.MEDIUM

                signals = [
                    "Load balancer type: CLB",
                    f"Scheme: {scheme}",
                ]
                if not traffic_fetch_failed:
                    signals.insert(
                        0,
                        f"Zero RequestCount and EstimatedProcessedBytes for {idle_days} days (CloudWatch)",
                    )

                if not has_instances:
                    signals.append("No registered instances")
                else:
                    signals.append(f"{len(instances)} registered instance(s)")
                if age_days > 0:
                    signals.append(f"Load balancer is {age_days} days old")

                signals_not_checked = [
                    "Planned future usage",
                    "Blue/green deployment scenarios",
                    "Seasonal traffic patterns",
                    "Internal health-check-only usage",
                ]
                if traffic_fetch_failed:
                    signals_not_checked.insert(
                        0,
                        "Traffic metrics (RequestCount, EstimatedProcessedBytes) — CloudWatch fetch "
                        "failed (transient/throttle error); traffic status unverified",
                    )

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=signals_not_checked,
                    time_window=f"{idle_days} days",
                )

                if traffic_fetch_failed:
                    title = "CLB Requires Traffic Verification"
                    summary = (
                        f"CLB '{lb_name}' could not be verified as idle — "
                        "CloudWatch traffic metrics were unreadable (transient/throttle error)."
                    )
                    reason = "CLB traffic metrics could not be fetched; idle status is unconfirmed"
                else:
                    title = f"Idle CLB (No Traffic for {idle_days}+ Days)"
                    summary = (
                        f"CLB '{lb_name}' has had zero traffic for "
                        f"{idle_days}+ days and is incurring base charges."
                    )
                    reason = f"CLB has zero traffic for {idle_days}+ days"

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.elb.clb.idle",
                        resource_type="aws.elb.load_balancer",
                        resource_id=lb_name,
                        region=region,
                        estimated_monthly_cost_usd=18.0,
                        title=title,
                        summary=summary,
                        reason=reason,
                        risk=RiskLevel.MEDIUM,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "name": lb_name,
                            "type": "classic",
                            "scheme": scheme,
                            "dns_name": lb.get("DNSName"),
                            "vpc_id": lb.get("VPCId"),
                            "age_days": age_days,
                            "has_instances": has_instances,
                            "instance_count": len(instances),
                            "idle_days_threshold": idle_days,
                            "estimated_monthly_cost": (
                                "~$16-22/month base cost (us-east-1 on-demand; "
                                "region-dependent; excludes LCU usage charges)"
                            ),
                        },
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError(
                "Missing required IAM permissions: "
                "elasticloadbalancing:DescribeLoadBalancers, "
                "cloudwatch:GetMetricStatistics"
            ) from e
        raise

    return findings


def _check_elbv2_traffic(cloudwatch, lb_arn: str, lb_type: str, days: int) -> tuple:
    """Check if an ALB/NLB has had any traffic in the past `days` days.

    ALB: checks both RequestCount and ProcessedBytes.
    - RequestCount only increments when a target is chosen — fixed-response, redirect,
      and pre-routing-rejection actions leave it at zero even with real traffic.
    - ProcessedBytes captures all bytes processed by the ALB regardless of routing outcome.

    NLB: checks both NewFlowCount and ProcessedBytes.
    - NewFlowCount only counts flows successfully established to targets — traffic that
      hits the NLB listener but doesn't reach a target (e.g. health check gaps) is missed.
    - ProcessedBytes always reflects total bytes received/sent by the NLB.

    Either metric > 0 is treated as traffic (OR logic, conservative for false-positive avoidance).

    Returns (has_traffic: bool, fetch_failed: bool).
    fetch_failed is True when a transient/throttle error prevented a clean metric read.
    """
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=max(days, 1))
    dimension_value = _extract_elbv2_dimension(lb_arn)

    if lb_type == "application":
        namespace = "AWS/ApplicationELB"
        primary_metric = "RequestCount"
    else:
        namespace = "AWS/NetworkELB"
        primary_metric = "NewFlowCount"

    def _fetch(metric_name: str) -> tuple:
        return _get_metric_sum(
            cloudwatch, namespace, metric_name, "LoadBalancer", dimension_value, start_time, now
        )

    primary_val, primary_err = _fetch(primary_metric)
    if primary_val > 0:
        return True, primary_err

    processed_val, processed_err = _fetch("ProcessedBytes")
    if processed_val > 0:
        return True, processed_err

    return False, (primary_err or processed_err)


def _check_clb_traffic(cloudwatch, lb_name: str, days: int) -> tuple:
    """Check if a CLB has had any traffic in the past `days` days.

    Checks both RequestCount (HTTP/HTTPS listeners) and EstimatedProcessedBytes
    (all protocols including TCP/SSL). A CLB with only TCP/SSL listeners will
    always report zero RequestCount, so checking only that metric would produce
    false positives for any active TCP CLB.

    Returns (has_traffic: bool, fetch_failed: bool).
    fetch_failed is True when a transient/throttle error prevented a clean metric read.
    """
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=max(days, 1))

    # HTTP/HTTPS traffic
    request_count, req_err = _get_metric_sum(
        cloudwatch,
        "AWS/ELB",
        "RequestCount",
        "LoadBalancerName",
        lb_name,
        start_time,
        now,
    )
    if request_count > 0:
        return True, req_err

    # TCP/SSL traffic (covers all protocols including HTTP/HTTPS)
    processed_bytes, proc_err = _get_metric_sum(
        cloudwatch,
        "AWS/ELB",
        "EstimatedProcessedBytes",
        "LoadBalancerName",
        lb_name,
        start_time,
        now,
    )
    return processed_bytes > 0, (req_err or proc_err)


def _check_elbv2_targets(elbv2, lb_arn: str) -> bool:
    """Check if an ALB/NLB has any registered targets.

    describe_target_health only returns targets that ARE registered in the target
    group — unregistered targets are simply absent from the response. Therefore
    any non-empty TargetHealthDescriptions list means there are registered targets,
    regardless of their health state (healthy/unhealthy/draining/unused all count).
    """
    try:
        tg_resp = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)
        for tg in tg_resp.get("TargetGroups", []):
            tg_arn = tg["TargetGroupArn"]
            health_resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
            if health_resp.get("TargetHealthDescriptions"):
                return True
    except ClientError:
        # If we can't check targets, assume they exist to avoid false positives
        return True
    return False


def _extract_elbv2_dimension(lb_arn: str) -> str:
    """
    Extract the CloudWatch dimension value from an ELBv2 ARN.

    ARN format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
    Dimension value: app/name/id (or net/name/id for NLB)
    """
    parts = lb_arn.split("loadbalancer/", 1)
    if len(parts) == 2:
        return parts[1]
    return lb_arn


def _get_metric_sum(
    cloudwatch,
    namespace: str,
    metric_name: str,
    dimension_name: str,
    dimension_value: str,
    start_time: datetime,
    end_time: datetime,
) -> tuple:
    """Get sum of a CloudWatch metric over the time period.

    Returns (has_traffic: int, fetch_error: bool).
    - has_traffic: 1 if any datapoint had Sum > 0, else 0.
    - fetch_error: True if a non-permission error occurred (throttle, transient, etc.).
      When fetch_error is True, has_traffic is 1 (conservative — avoids false positives),
      but the caller should surface this to the operator via signals_not_checked.
    """
    try:
        response = cloudwatch.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[
                {
                    "Name": dimension_name,
                    "Value": dimension_value,
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400,  # 1 day in seconds
            Statistics=["Sum"],
        )

        datapoints = response.get("Datapoints", [])
        if any(dp.get("Sum", 0) > 0 for dp in datapoints):
            return 1, False
        return 0, False

    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permissions: cloudwatch:GetMetricStatistics"
            ) from e
        # Other errors (throttle, transient): assume traffic to avoid false positives,
        # but flag the error so the caller can surface it.
        return 1, True
