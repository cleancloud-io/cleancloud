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
    days_idle: int = 14,
) -> List[Finding]:
    """
    Find idle Elastic Load Balancers (ALB, NLB, CLB) with no traffic.

    ELBs have a base hourly charge regardless of usage (~$16-22/month).
    Idle load balancers with no traffic are a clear cost optimization signal.

    Detection logic:
    - LB is older than `days_idle` days
    - Zero traffic over the `days_idle` period (CloudWatch metrics)
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
    findings.extend(_scan_elbv2(session, region, cloudwatch, now, days_idle))

    # Scan CLB via elb
    findings.extend(_scan_clb(session, region, cloudwatch, now, days_idle))

    return findings


def _scan_elbv2(
    session: boto3.Session,
    region: str,
    cloudwatch,
    now: datetime,
    days_idle: int,
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
                if age_days < days_idle:
                    continue

                # Check traffic via CloudWatch
                has_traffic = _check_elbv2_traffic(cloudwatch, lb_arn, lb_type, days_idle)
                if has_traffic:
                    continue

                # Check registered targets
                has_targets = _check_elbv2_targets(elbv2, lb_arn)

                # Determine confidence
                if not has_targets:
                    confidence = ConfidenceLevel.HIGH
                else:
                    confidence = ConfidenceLevel.MEDIUM

                type_label = "ALB" if lb_type == "application" else "NLB"
                rule_id = "aws.elbv2.alb.idle" if lb_type == "application" else "aws.elbv2.nlb.idle"
                metric_name = "RequestCount" if lb_type == "application" else "NewFlowCount"

                signals = [
                    f"Zero {metric_name} for {days_idle} days (CloudWatch metrics)",
                    f"Load balancer type: {type_label}",
                    f"State: {lb.get('State', {}).get('Code', 'unknown')}",
                ]

                if not has_targets:
                    signals.append("No healthy registered targets")
                if age_days > 0:
                    signals.append(f"Load balancer is {age_days} days old")

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=[
                        "Planned future usage",
                        "Blue/green deployment scenarios",
                        "Seasonal traffic patterns",
                        "Internal health-check-only usage",
                    ],
                    time_window=f"{days_idle} days",
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id=rule_id,
                        resource_type="aws.elbv2.load_balancer",
                        resource_id=lb_arn,
                        region=region,
                        estimated_monthly_cost_usd=18.0,
                        title=f"Idle {type_label} (No Traffic for {days_idle}+ Days)",
                        summary=(
                            f"{type_label} '{lb_name}' has had zero traffic for "
                            f"{days_idle}+ days and is incurring base charges."
                        ),
                        reason=f"{type_label} has zero traffic for {days_idle}+ days",
                        risk=RiskLevel.MEDIUM,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "name": lb_name,
                            "type": lb_type,
                            "state": lb.get("State", {}).get("Code", "unknown"),
                            "dns_name": lb.get("DNSName"),
                            "vpc_id": lb.get("VpcId"),
                            "age_days": age_days,
                            "has_targets": has_targets,
                            "idle_days_threshold": days_idle,
                            "estimated_monthly_cost": "~$16-22/month (region dependent)",
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
    days_idle: int,
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
                if age_days < days_idle:
                    continue

                # Check traffic via CloudWatch
                has_traffic = _check_clb_traffic(cloudwatch, lb_name, days_idle)
                if has_traffic:
                    continue

                # Check registered instances
                instances = lb.get("Instances", [])
                has_instances = len(instances) > 0

                # Determine confidence
                if not has_instances:
                    confidence = ConfidenceLevel.HIGH
                else:
                    confidence = ConfidenceLevel.MEDIUM

                signals = [
                    f"Zero RequestCount for {days_idle} days (CloudWatch metrics)",
                    "Load balancer type: CLB",
                ]

                if not has_instances:
                    signals.append("No registered instances")
                else:
                    signals.append(f"{len(instances)} registered instance(s)")
                if age_days > 0:
                    signals.append(f"Load balancer is {age_days} days old")

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=[
                        "Planned future usage",
                        "Blue/green deployment scenarios",
                        "Seasonal traffic patterns",
                        "Internal health-check-only usage",
                    ],
                    time_window=f"{days_idle} days",
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.elb.clb.idle",
                        resource_type="aws.elb.load_balancer",
                        resource_id=lb_name,
                        region=region,
                        estimated_monthly_cost_usd=18.0,
                        title=f"Idle CLB (No Traffic for {days_idle}+ Days)",
                        summary=(
                            f"CLB '{lb_name}' has had zero traffic for "
                            f"{days_idle}+ days and is incurring base charges."
                        ),
                        reason=f"CLB has zero traffic for {days_idle}+ days",
                        risk=RiskLevel.MEDIUM,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "name": lb_name,
                            "type": "classic",
                            "dns_name": lb.get("DNSName"),
                            "vpc_id": lb.get("VPCId"),
                            "age_days": age_days,
                            "has_instances": has_instances,
                            "instance_count": len(instances),
                            "idle_days_threshold": days_idle,
                            "estimated_monthly_cost": "~$16-22/month (region dependent)",
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


def _check_elbv2_traffic(cloudwatch, lb_arn: str, lb_type: str, days: int) -> bool:
    """Check if an ALB/NLB has had any traffic in the past `days` days."""
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=max(days, 1))

    if lb_type == "application":
        # ALB: Use RequestCount in AWS/ApplicationELB
        # Dimension value is the ARN suffix after "app/..."
        dimension_value = _extract_elbv2_dimension(lb_arn)
        traffic = _get_metric_sum(
            cloudwatch,
            "AWS/ApplicationELB",
            "RequestCount",
            "LoadBalancer",
            dimension_value,
            start_time,
            now,
        )
    else:
        # NLB: Use NewFlowCount in AWS/NetworkELB
        dimension_value = _extract_elbv2_dimension(lb_arn)
        traffic = _get_metric_sum(
            cloudwatch,
            "AWS/NetworkELB",
            "NewFlowCount",
            "LoadBalancer",
            dimension_value,
            start_time,
            now,
        )

    return traffic > 0


def _check_clb_traffic(cloudwatch, lb_name: str, days: int) -> bool:
    """Check if a CLB has had any traffic in the past `days` days."""
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=max(days, 1))

    traffic = _get_metric_sum(
        cloudwatch,
        "AWS/ELB",
        "RequestCount",
        "LoadBalancerName",
        lb_name,
        start_time,
        now,
    )
    return traffic > 0


def _check_elbv2_targets(elbv2, lb_arn: str) -> bool:
    """Check if an ALB/NLB has any healthy registered targets."""
    try:
        tg_resp = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)
        for tg in tg_resp.get("TargetGroups", []):
            tg_arn = tg["TargetGroupArn"]
            health_resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
            if any(
                d.get("TargetHealth", {}).get("State") == "healthy"
                for d in health_resp.get("TargetHealthDescriptions", [])
            ):
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
) -> int:
    """Get sum of a CloudWatch metric over the time period."""
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
            return 1
        return 0

    except ClientError:
        # If we can't get metrics, assume there might be traffic
        # to avoid false positives
        return 1
