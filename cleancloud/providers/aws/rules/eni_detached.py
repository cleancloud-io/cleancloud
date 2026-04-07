from datetime import datetime, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_detached_enis(
    session: boto3.Session,
    region: str,
    max_age_days: int = 60,
) -> List[Finding]:
    """
    Find Elastic Network Interfaces (ENIs) currently detached and 60+ days old.

    Detached ENIs incur small hourly charges and are often forgotten
    after failed deployments or when infrastructure is torn down incompletely.

    IMPORTANT: AWS does not expose "detached since" timestamp, so we use ENI
    creation age as a proxy. This is conservative - an ENI created 60 days ago
    and currently detached is worth reviewing even if it was recently detached.

    SAFE RULE (review-only):
    - ENI Status == 'available' (not attached)
    - ENI creation age >= max_age_days threshold (NOT detached duration)
    - Excludes AWS infrastructure ENIs (NAT Gateway, Load Balancers, VPC Endpoints)
    - INCLUDES requester-managed ENIs (Lambda, ECS, RDS) - these are user resources!

    IAM permissions:
    - ec2:DescribeNetworkInterfaces
    """
    ec2 = session.client("ec2", region_name=region)

    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        # Note: describe_network_interfaces supports pagination
        paginator = ec2.get_paginator("describe_network_interfaces")

        for page in paginator.paginate():
            for eni in page.get("NetworkInterfaces", []):
                # Only consider detached ENIs
                if eni.get("Status") != "available":
                    continue

                # Exclude AWS infrastructure ENIs using InterfaceType
                # These are ENIs for AWS infrastructure that users don't manage
                interface_type = eni.get("InterfaceType", "interface")
                if interface_type in [
                    "nat_gateway",  # NAT Gateway ENI (AWS infrastructure)
                    "load_balancer",  # ELB/ALB/NLB ENI (AWS infrastructure)
                    "gateway_load_balancer",  # Gateway Load Balancer
                    "gateway_load_balancer_endpoint",  # GWLB endpoint
                    "vpc_endpoint",  # VPC endpoint interface (AWS infrastructure)
                ]:
                    continue

                # Note: We DO want to flag RequesterManaged ENIs with InterfaceType="interface"
                # These are user resources created by Lambda, ECS, RDS, etc. - common waste!

                # Calculate age since creation
                create_time = eni.get("CreateTime")
                if create_time is None:
                    age_days = 0
                else:
                    try:
                        age_days = (now - create_time).days
                    except TypeError:
                        age_days = 0

                # Apply age threshold (skip if too young)
                if age_days < max_age_days:
                    continue

                # Build evidence (be honest about what we're measuring)
                signals_used = [
                    "ENI status is 'available' (currently detached)",
                    f"ENI was created {age_days} days ago and is currently detached",
                ]

                # Note: We cannot measure "detached duration" because AWS doesn't expose DetachTime
                # We use creation age as a conservative proxy

                if eni.get("RequesterManaged"):
                    signals_used.append(
                        "ENI is requester-managed (created by AWS service such as Lambda/ECS)"
                    )

                # Check if ENI has any tags
                tags = eni.get("TagSet", [])
                if not tags:
                    signals_used.append("ENI has no tags (ownership unclear)")

                evidence = Evidence(
                    signals_used=signals_used,
                    signals_not_checked=[
                        "Detached duration (AWS does not expose DetachTime)",
                        "Previous attachment history",
                        "AWS Hyperplane ENI reuse behavior (undocumented retention)",
                        "Future planned attachments",
                        "Application-level usage",
                        "Manual operational workflows",
                    ],
                    time_window=f"{max_age_days} days since creation",
                )

                # Build details
                details = {
                    "status": eni.get("Status"),
                    "age_days": age_days,
                    "create_time": create_time.isoformat() if create_time else None,
                    "interface_type": interface_type,
                    "requester_managed": eni.get("RequesterManaged", False),
                    "vpc_id": eni.get("VpcId"),
                    "subnet_id": eni.get("SubnetId"),
                    "availability_zone": eni.get("AvailabilityZone"),
                }

                description = eni.get("Description", "")
                if description:
                    details["description"] = description

                if tags:
                    details["tags"] = tags

                # Include private IP if present
                private_ips = eni.get("PrivateIpAddresses", [])
                if private_ips:
                    details["private_ip"] = private_ips[0].get("PrivateIpAddress")

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.ec2.eni.detached",
                        resource_type="aws.ec2.network_interface",
                        resource_id=eni["NetworkInterfaceId"],
                        region=region,
                        title="Detached Network Interface (Review Recommended)",
                        summary=f"ENI created {age_days} days ago and currently detached (incurs small hourly charges)",
                        reason=f"ENI is {age_days} days old and currently in detached state, incurring charges",
                        risk=RiskLevel.LOW,
                        confidence=ConfidenceLevel.MEDIUM,  # Medium because we can't measure detached duration
                        detected_at=now,
                        evidence=evidence,
                        details=details,
                    )
                )

    except ClientError as e:
        if e.response["Error"]["Code"] == "UnauthorizedOperation":
            raise PermissionError(
                "Missing required IAM permission: ec2:DescribeNetworkInterfaces"
            ) from e
        raise

    return findings
