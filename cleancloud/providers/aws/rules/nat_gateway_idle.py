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

    NAT Gateways incur a fixed hourly charge (~$0.045/hr ≈ $32.85/month) regardless of
    connectivity type (public or private), plus per-GB data processing fees
    ($0.045/GB for public, $0.01/GB for private). The hourly cost alone makes idle
    gateways a meaningful waste.

    Detection logic:
    - NAT Gateway state is 'available'
    - Older than `idle_days` (noise-reduction heuristic — new gateways may not have had
      time for operators to configure routing; this is NOT an AWS-defined grace period)
    - All four CloudWatch byte metrics are zero over `idle_days`
    - Not referenced by any VPC route table (corroborating idle signal)

    Notes on accuracy:
    - CloudWatch NAT Gateway metrics are eventually consistent and can lag by minutes
      to hours. More importantly, datapoints can be absent entirely for periods of low
      activity — CloudWatch omits zero-value datapoints rather than publishing them.
      Missing datapoints are treated as zero by this rule, which means low-but-nonzero
      traffic could be missed if it falls within a gap in metric publication.
    - Daily (86400s) granularity is used; within-day bursts contribute to that day's Sum,
      but a burst that happens to fall in a metric-publication gap may not appear.
    - Zero traffic may be intentional: DR/failover, pre-warmed infrastructure, or
      seasonal traffic patterns. Always review before acting.
    - Elastic IPs associated with a public NAT Gateway may incur idle charges even
      after the gateway is deleted; check and release them separately.
    - Route table references are a corroborating signal only — a referenced route table
      does not prove the gateway is actively used; it only means it is reachable.

    IAM permissions:
    - ec2:DescribeNatGateways
    - ec2:DescribeRouteTables
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
                connectivity_type = nat_gw.get("ConnectivityType", "public")

                # Calculate age
                create_time = nat_gw.get("CreateTime")
                age_days = 0
                if create_time:
                    try:
                        age_days = (now - create_time).days
                    except TypeError:
                        pass

                # Noise-reduction heuristic: skip recently created gateways.
                # New gateways may not have had time for route tables to be configured.
                # This is NOT an AWS-defined grace period — adjust idle_days as needed.
                if age_days < idle_days:
                    continue

                # Check CloudWatch metrics for traffic — all 4 direction metrics
                (
                    has_traffic,
                    fetch_failed,
                    bytes_out_dest,
                    bytes_in_src,
                    bytes_in_dest,
                    bytes_out_src,
                ) = _check_nat_gateway_traffic(cloudwatch, nat_gw_id, idle_days)

                # has_traffic=True with fetch_failed=False → confirmed traffic, skip.
                # has_traffic=True with fetch_failed=True → metric unreadable; create a
                # LOW-confidence finding so the operator knows to verify manually.
                if has_traffic and not fetch_failed:
                    continue

                # Check route table associations — a NAT GW not referenced by any route
                # table is not reachable from any subnet (strong corroborating idle signal).
                in_route_tables, route_table_check_failed = _check_route_table_references(
                    ec2, nat_gw_id
                )

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

                if fetch_failed:
                    confidence = ConfidenceLevel.LOW
                    risk = RiskLevel.MEDIUM
                    title = "NAT Gateway Requires Traffic Verification"
                    summary = (
                        f"NAT Gateway '{nat_gw_id}' could not be verified as idle — "
                        "CloudWatch traffic metrics were unreadable (transient/throttle error)."
                    )
                    reason = "NAT Gateway traffic metrics could not be fetched; idle status is unconfirmed"
                elif not in_route_tables and not route_table_check_failed:
                    # Zero traffic confirmed AND no route table references the gateway —
                    # two independent signals agree; HIGH confidence and risk warranted.
                    confidence = ConfidenceLevel.HIGH
                    risk = RiskLevel.HIGH
                    title = f"Idle NAT Gateway (No Traffic for {idle_days}+ Days, Not Routed)"
                    summary = (
                        f"NAT Gateway '{nat_gw_id}' has had no traffic for {idle_days}+ days "
                        "and is not referenced by any route table — it is unreachable and billing."
                    )
                    reason = (
                        f"NAT Gateway has zero traffic for {idle_days}+ days "
                        "and is not referenced by any VPC route table"
                    )
                else:
                    confidence = ConfidenceLevel.MEDIUM
                    risk = RiskLevel.MEDIUM
                    title = f"Idle NAT Gateway (No Traffic for {idle_days}+ Days)"
                    summary = (
                        f"NAT Gateway '{nat_gw_id}' has had no traffic for "
                        f"{idle_days}+ days and is incurring ~$32.85/month in base charges."
                    )
                    reason = f"NAT Gateway has zero traffic for {idle_days}+ days"

                signals = []
                if fetch_failed:
                    signals.append(
                        "CloudWatch traffic metrics unreadable (transient/throttle error) — "
                        "traffic status unverified"
                    )
                else:
                    signals.append(
                        f"No traffic detected for {idle_days} days (all 4 CloudWatch direction metrics; "
                        "note: metrics are eventually consistent and may lag by minutes to hours)"
                    )
                    signals.append(f"BytesOutToDestination: {bytes_out_dest} bytes")
                    signals.append(f"BytesInFromSource: {bytes_in_src} bytes")
                    signals.append(f"BytesInFromDestination: {bytes_in_dest} bytes")
                    signals.append(f"BytesOutToSource: {bytes_out_src} bytes")

                signals.append(f"NAT Gateway state is '{state}'")
                signals.append(f"Connectivity type: {connectivity_type}")

                if not in_route_tables and not route_table_check_failed:
                    signals.append(
                        "Not referenced by any VPC route table — gateway is unreachable from all subnets"
                    )
                elif in_route_tables:
                    signals.append("Referenced by at least one VPC route table")

                if age_days > 0:
                    signals.append(f"NAT Gateway is {age_days} days old")

                signals_not_checked = [
                    "Planned future usage",
                    "Disaster recovery or failover intent — zero traffic may be intentional for DR standby",
                    "Blue/green deployment scenarios",
                    "Seasonal traffic patterns",
                    "Development/staging environment cycles",
                ]
                if fetch_failed:
                    signals_not_checked.insert(
                        0,
                        "Traffic metrics (BytesOutToDestination, BytesInFromSource, "
                        "BytesInFromDestination, BytesOutToSource) — CloudWatch fetch failed; "
                        "traffic status unverified",
                    )
                if route_table_check_failed:
                    signals_not_checked.append(
                        "Route table associations — DescribeRouteTables failed; "
                        "could not confirm whether gateway is referenced"
                    )
                if connectivity_type == "public" and eip_info:
                    signals_not_checked.append(
                        "Elastic IP idle charges — associated EIPs may incur additional cost "
                        "even after the NAT Gateway is deleted; release them separately"
                    )

                evidence = Evidence(
                    signals_used=signals,
                    signals_not_checked=signals_not_checked,
                    time_window=f"{idle_days} days",
                )

                data_processing_note = (
                    "$0.045/GB for public, $0.01/GB for private"
                    if connectivity_type == "public"
                    else "$0.01/GB (private NAT Gateway)"
                )
                tags = nat_gw.get("Tags", [])
                name_tag = next((t["Value"] for t in tags if t.get("Key") == "Name"), None)

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.ec2.nat_gateway.idle",
                        resource_type="aws.ec2.nat_gateway",
                        resource_id=nat_gw_id,
                        region=region,
                        estimated_monthly_cost_usd=32.85,
                        title=title,
                        summary=summary,
                        reason=reason,
                        risk=risk,
                        confidence=confidence,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "name": name_tag,
                            "connectivity_type": connectivity_type,
                            "state": state,
                            "age_days": age_days,
                            "create_time": (create_time.isoformat() if create_time else None),
                            "vpc_id": vpc_id,
                            "subnet_id": subnet_id,
                            "elastic_ips": eip_info,
                            "in_route_tables": in_route_tables,
                            "bytes_out_to_destination": bytes_out_dest,
                            "bytes_in_from_source": bytes_in_src,
                            "bytes_in_from_destination": bytes_in_dest,
                            "bytes_out_to_source": bytes_out_src,
                            "idle_days_threshold": idle_days,
                            "estimated_monthly_cost": (
                                f"~$32.85/month base hourly cost (us-east-1 on-demand; "
                                f"region-dependent; excludes data processing charges: "
                                f"{data_processing_note})"
                            ),
                            "tags": tags,
                        },
                    )
                )

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            raise PermissionError(
                "Missing required IAM permissions: "
                "ec2:DescribeNatGateways, ec2:DescribeRouteTables, cloudwatch:GetMetricStatistics"
            ) from e
        raise

    return findings


def _check_route_table_references(ec2, nat_gw_id: str) -> tuple:
    """Check whether any VPC route table has a route pointing to this NAT Gateway.

    A NAT Gateway not referenced by any route table is unreachable from all subnets
    and is therefore a strong corroborating idle signal.

    Returns (in_route_tables: bool, check_failed: bool).
    check_failed is True if DescribeRouteTables raised a non-permission error.
    """
    try:
        response = ec2.describe_route_tables(
            Filters=[{"Name": "route.nat-gateway-id", "Values": [nat_gw_id]}]
        )
        return len(response.get("RouteTables", [])) > 0, False
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "UnauthorizedOperation"):
            # Surface as a check failure rather than raising — missing this permission
            # degrades the signal but should not abort the scan.
            return False, True
        return False, True


def _check_nat_gateway_traffic(
    cloudwatch,
    nat_gw_id: str,
    days: int,
) -> tuple:
    """
    Check if NAT Gateway has had any traffic in the past `days` days.

    AWS publishes four directional metrics for NAT Gateways:
    - BytesOutToDestination: private subnet → internet (outbound requests)
    - BytesInFromSource: private subnet → NAT GW (client-side inbound)
    - BytesInFromDestination: internet → NAT GW (return traffic)
    - BytesOutToSource: NAT GW → private subnet (return traffic to client)

    All four are checked to avoid missing asymmetric or long-lived connections
    where only return-path traffic falls within the observation window.

    Returns (has_traffic, fetch_failed, bytes_out_dest, bytes_in_src, bytes_in_dest, bytes_out_src).
    fetch_failed is True if any metric fetch encountered a transient/throttle error.
    When fetch_failed is True, has_traffic is True (conservative) — but the caller
    should surface this uncertainty rather than silently treating the gateway as active.
    """
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=days)

    def _fetch(metric_name: str) -> tuple:
        return _get_metric_sum(
            cloudwatch, "AWS/NATGateway", metric_name, "NatGatewayId", nat_gw_id, start_time, now
        )

    out_dest, err1 = _fetch("BytesOutToDestination")
    in_src, err2 = _fetch("BytesInFromSource")
    in_dest, err3 = _fetch("BytesInFromDestination")
    out_src, err4 = _fetch("BytesOutToSource")

    fetch_failed = err1 or err2 or err3 or err4
    has_traffic = (out_dest > 0) or (in_src > 0) or (in_dest > 0) or (out_src > 0)
    return has_traffic, fetch_failed, out_dest, in_src, in_dest, out_src


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

    Returns (value: int, fetch_error: bool).
    - value: total bytes summed across all datapoints (0 if no data).
    - fetch_error: True if a non-permission error occurred (throttle, transient, etc.).
      When fetch_error is True, value is 1 (conservative — avoids false positives),
      but the caller should surface this to the operator via evidence.
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
        total = sum(dp.get("Sum", 0) for dp in datapoints)
        return int(total), False

    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDenied", "UnauthorizedOperation"):
            raise PermissionError(
                "Missing required IAM permissions: cloudwatch:GetMetricStatistics"
            ) from e
        # Other errors (throttle, transient): assume traffic to avoid false positives,
        # but flag the error so the caller can surface it.
        return 1, True
