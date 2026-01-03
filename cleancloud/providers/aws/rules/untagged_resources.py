from datetime import datetime, timezone
from typing import List, Optional

import boto3

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_untagged_resources(
    session: boto3.Session,
    region: Optional[str] = None,
) -> List[Finding]:
    """
    Detect untagged AWS resources:
    - EBS volumes
    - S3 buckets
    - CloudWatch log groups

    Conservative rule (review-only):
    - We do not infer intended usage of resources
    - Some untagged resources may be intentional

    IAM permissions:
    - ec2:DescribeVolumes
    - s3:ListAllMyBuckets
    - s3:GetBucketTagging
    - logs:DescribeLogGroups
    """
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    # --- EBS Volumes ---
    ec2 = session.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_volumes").paginate():
        for vol in page.get("Volumes", []):
            if not vol.get("Tags"):
                evidence = Evidence(
                    signals_used=["Volume has no tags attached"],
                    signals_not_checked=[
                        "Application-level usage",
                        "IaC-managed intent",
                        "Disaster recovery purpose",
                        "Future planned usage",
                    ],
                    time_window=None,
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.resource.untagged",
                        resource_type="aws.ebs.volume",
                        resource_id=vol["VolumeId"],
                        region=region,
                        title="Untagged EBS volume",
                        summary="EBS volume has no tags",
                        reason="No tags found on resource",
                        risk=RiskLevel.LOW,
                        confidence=ConfidenceLevel.MEDIUM,
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "availability_zone": vol["AvailabilityZone"],
                            "size_gb": vol["Size"],
                        },
                    )
                )

    # --- S3 Buckets (global) ---
    s3 = session.client("s3")
    for bucket in s3.list_buckets().get("Buckets", []):
        bucket_name = bucket["Name"]
        try:
            tag_set = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
        except s3.exceptions.ClientError:
            tag_set = []

        if not tag_set:
            evidence = Evidence(
                signals_used=["Bucket has no tags attached"],
                signals_not_checked=[
                    "Application-level usage",
                    "IaC-managed intent",
                    "Disaster recovery purpose",
                    "Future planned usage",
                ],
                time_window=None,
            )

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.resource.untagged",
                    resource_type="aws.s3.bucket",
                    resource_id=bucket_name,
                    region=None,
                    title="Untagged S3 bucket",
                    summary="S3 bucket has no tags",
                    reason="No tags found on resource",
                    risk=RiskLevel.LOW,
                    confidence=ConfidenceLevel.MEDIUM,
                    detected_at=now,
                    evidence=evidence,
                    details={},
                )
            )

    # --- CloudWatch Log Groups ---
    logs = session.client("logs", region_name=region)
    for page in logs.get_paginator("describe_log_groups").paginate():
        for lg in page.get("logGroups", []):
            if not lg.get("tags"):
                evidence = Evidence(
                    signals_used=["Log group has no tags attached"],
                    signals_not_checked=[
                        "Application-level usage",
                        "IaC-managed intent",
                        "Disaster recovery purpose",
                        "Future planned usage",
                    ],
                    time_window=None,
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.resource.untagged",
                        resource_type="aws.cloudwatch.log_group",
                        resource_id=lg["logGroupName"],
                        region=region,
                        title="Untagged CloudWatch log group",
                        summary="Log group has no tags",
                        reason="No tags found on resource",
                        risk=RiskLevel.LOW,
                        confidence=ConfidenceLevel.MEDIUM,
                        detected_at=now,
                        evidence=evidence,
                        details={},
                    )
                )

    return findings
