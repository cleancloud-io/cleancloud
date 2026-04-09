from datetime import datetime, timedelta, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_idle_nat_gateways(
    session: boto3.Session,
    region: str,
    idle_days: int = 14,
) -> List[Finding]:
    """
    Find NAT Gateways with no traffic for `idle_days` days.

    NAT Gateways incur hourly charges (~$0.045/hour = ~$32.40/month)
    plus data processing fees ($0.045/GB). Idle gateways waste money.

    Detection logic:
    - NAT Gateway state is 'available'
    - CloudWatch metrics show zero bytes transferred for `idle_days` period
    - Uses BytesOutToDestination + BytesInFromSource metrics

    Conservative approach:
    - Default 14-day idle period (short enough to catch waste, long enough to avoid false positives)
    - Confidence MEDIUM (metrics could miss edge cases)
    - Risk MEDIUM (significant monthly cost)

    IAM permissions:
    - ec2:DescribeNatGateways
    - cloudwatch:GetMetricStatistics
    """
    ec2 = session.client("ec2", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)

    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        paginator = ec2.get_paginator("describe_nat_gateways")

        for page in paginator.paginate():
            for nat_gw in page.get("NatGateways", []):
                # Only check available gateways
                state = nat_gw.get("State")
                if state != "available":
                    continue

                nat_gw_id = nat_gw["NatGatewayId"]

                # Calculate age
                create_time = nat_gw.get("CreateTime")
                age_days = 0
                if create_time:
                    try:
                        age_days = (now - create_time).days
                    except TypeError:
                        pass

                # Skip if NAT Gateway is younger than the idle threshold
                if age_days < idle_days:
                    continue

                # Check CloudWatch metrics for traffic
                has_traffic, total_bytes_out, total_bytes_in = _check_nat_gateway_traffic(
                    cloudwatch, nat_gw_id, idle_days
                )

                if has_traffic:
                    continue

                # Get VPC and subnet info
                vpc_id = nat_gw.get("VpcId")
                subnet_id = nat_gw.get("SubnetId")

                # Get Elastic IP info
                addresses = nat_gw.get("NatGatewayAddresses", [])
                eip_info = []
                for addr in addresses:
                    eip_info.append(
                        {
                            "allocation_id": addr.get("AllocationId"),
                            "public_ip": addr.get("PublicIp"),
                            "private_ip": addr.get("PrivateIp"),
                        }
                    )

                signals = [
                    f"No traffic detected for {idle_days} days (CloudWatch metrics)",
                    f"BytesOutToDestination: {total_bytes_out} bytes",
                    f"BytesInFromSource: {total_bytes_in} bytes",
                    f"NAT Gateway state is '{state}'",
                ]

                if age_days > 0:
                    signals.append(f"NAT Gateway is {age_days} days old")

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=[
                        "Planned future usage",
                        "Disaster recovery intent",
                        "Blue/green deployment scenarios",
                        "Seasonal traffic patterns",
                        "Development/staging environment cycles",
                    ],
                    time_window=f"{idle_days} days",
                )

                # Monthly cost estimate (region dependent)
                estimated_monthly_cost = "~$32/month base cost (region dependent)"

                tags = nat_gw.get("Tags", [])
                name_tag = next((t["Value"] for t in tags if t.get("Key") == "Name"), None)

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.ec2.nat_gateway.idle",
                        resource_type="aws.ec2.nat_gateway",
                        resource_id=nat_gw_id,
                        region=region,
                        estimated_monthly_cost_usd=32.40,
                        title=f"Idle NAT Gateway (No Traffic for {idle_days}+ Days)",
                        summary=(
                            f"NAT Gateway '{name_tag or nat_gw_id}' has had no traffic for "
                            f"{idle_days}+ days and is incurring ~$32/month in base charges."
                        ),
                        reason=f"NAT Gateway has zero traffic for {idle_days}+ days",
                        risk=RiskLevel.MEDIUM,
                        confidence=ConfidenceLevel.MEDIUM,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "name": name_tag,
                            "state": state,
                            "age_days": age_days,
                            "create_time": create_time.isoformat() if create_time else None,
                            "vpc_id": vpc_id,
                            "subnet_id": subnet_id,
                            "elastic_ips": eip_info,
                            "bytes_out_total": total_bytes_out,
                            "bytes_in_total": total_bytes_in,
                            "idle_days_threshold": idle_days,
                            "estimated_monthly_cost": estimated_monthly_cost,
                            "tags": tags,
                        },
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError(
                "Missing required IAM permissions: "
                "ec2:DescribeNatGateways, cloudwatch:GetMetricStatistics"
            ) from e
        raise

    return findings


def _check_nat_gateway_traffic(
    cloudwatch,
    nat_gw_id: str,
    days: int,
) -> tuple[bool, int, int]:
    """
    Check if NAT Gateway has had any traffic in the past `days` days.

    Returns (has_traffic, total_bytes_out, total_bytes_in).
    """
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=days)

    # Check BytesOutToDestination (outbound traffic from private subnets)
    bytes_out = _get_metric_sum(
        cloudwatch,
        "AWS/NATGateway",
        "BytesOutToDestination",
        "NatGatewayId",
        nat_gw_id,
        start_time,
        now,
    )

    # Check BytesInFromSource (inbound traffic to private subnets)
    bytes_in = _get_metric_sum(
        cloudwatch,
        "AWS/NATGateway",
        "BytesInFromSource",
        "NatGatewayId",
        nat_gw_id,
        start_time,
        now,
    )

    has_traffic = (bytes_out > 0) or (bytes_in > 0)
    return has_traffic, bytes_out, bytes_in


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
        total = sum(dp.get("Sum", 0) for dp in datapoints)
        return int(total)

    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permissions: cloudwatch:GetMetricStatistics"
            ) from e
        # Other errors (throttle, transient): assume traffic to avoid false positives
        return 1
