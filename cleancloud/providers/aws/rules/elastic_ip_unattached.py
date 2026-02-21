from datetime import datetime, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_unattached_elastic_ips(
    session: boto3.Session,
    region: str,
    days_unattached: int = 30,
) -> List[Finding]:
    """
    Find Elastic IPs allocated 30+ days ago and currently unattached.

    Unattached Elastic IPs incur small hourly charges when not associated.

    IMPORTANT: AWS does not expose "unattached since" timestamp, so we use
    allocation age as a proxy. An EIP allocated 30+ days ago and currently
    unattached is worth reviewing.

    SAFE RULE (review-only):
    - EIP does not have AssociationId (not attached)
    - EIP allocation age >= days_unattached threshold (NOT unattached duration)
    - Classic EIPs without AllocationTime are flagged immediately (conservative)

    IAM permissions:
    - ec2:DescribeAddresses
    """
    ec2 = session.client("ec2", region_name=region)

    now = datetime.now(timezone.utc)
    findings: List[Finding] = []

    try:
        # DescribeAddresses is non-paginated by AWS (no paginator exists).
        # Returns all Elastic IPs in a single call.
        response = ec2.describe_addresses()
        for eip in response.get("Addresses", []):
            # Skip if attached to an instance or network interface
            if "AssociationId" in eip:
                continue

            # Calculate age since allocation
            allocation_time = eip.get("AllocationTime")
            domain = eip.get("Domain", "vpc")
            is_classic = domain == "standard"

            if not allocation_time:
                if is_classic:
                    # Genuine EC2-Classic EIP without AllocationTime — flag conservatively
                    age_days = None
                else:
                    # VPC EIP without AllocationTime — cannot determine age, skip
                    continue
            else:
                age_days = (now - allocation_time).days

            # Apply age threshold (skip if too young)
            if age_days is not None and age_days < days_unattached:
                continue

            # Build evidence
            signals_used = ["Elastic IP is not associated with any instance or network interface"]
            if age_days is not None:
                signals_used.append(
                    f"Elastic IP was allocated {age_days} days ago and is currently unattached"
                )
            if is_classic:
                signals_used.append(
                    "Classic EIP without AllocationTime (age unknown, flagged conservatively)"
                )
                signals_used.append(
                    "EC2-Classic is deprecated; unattached Classic EIPs are almost always legacy leftovers"
                )

            evidence = Evidence(
                signals_used=signals_used,
                signals_not_checked=[
                    "Unattached duration (AWS does not expose detach timestamp)",
                    "Previous attachment history",
                    "Application-level usage",
                    "Manual operational workflows",
                    "Future planned attachments",
                    "Disaster recovery intent",
                ],
                time_window=(
                    f"{days_unattached} days since allocation"
                    if age_days is not None
                    else "Unknown (Classic EIP, no AllocationTime)"
                ),
            )

            # Build details
            details = {
                "public_ip": eip.get("PublicIp"),
                "domain": eip.get("Domain", "vpc"),
                "is_classic": is_classic,
            }

            if age_days is not None:
                details["age_days"] = age_days
                details["allocation_time"] = allocation_time.isoformat()

            if "Tags" in eip:
                details["tags"] = eip["Tags"]

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.ec2.elastic_ip.unattached",
                    resource_type="aws.ec2.elastic_ip",
                    resource_id=eip.get("AllocationId") or eip.get("PublicIp"),
                    region=region,
                    estimated_monthly_cost_usd=3.75,
                    title="Unattached Elastic IP (Review Recommended)",
                    summary=(
                        f"Elastic IP allocated {age_days} days ago and currently unattached (incurs hourly charges)"
                        if age_days is not None
                        else "Classic Elastic IP currently unattached (incurs hourly charges, allocation age unknown)"
                    ),
                    reason=(
                        f"Elastic IP is {age_days} days old and currently unattached, incurring charges"
                        if age_days is not None
                        else "Classic Elastic IP currently unattached, incurring charges (allocation age unknown)"
                    ),
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.HIGH,  # Deterministic state: no AssociationId
                    detected_at=now,
                    evidence=evidence,
                    details=details,
                )
            )

    except ClientError as e:
        if e.response["Error"]["Code"] == "UnauthorizedOperation":
            raise PermissionError("Missing required IAM permission: ec2:DescribeAddresses") from e
        raise

    return findings
