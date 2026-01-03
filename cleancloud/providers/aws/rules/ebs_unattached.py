from datetime import datetime, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_unattached_ebs_volumes(
    session: boto3.Session,
    region: str,
) -> List[Finding]:
    """
    Find EBS volumes that are not attached to any EC2 instance.

    SAFE RULE (review-only):
    - volume.state != 'in-use'

    IAM permissions:
    - ec2:DescribeVolumes
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_volumes")

    findings: List[Finding] = []

    try:
        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                if volume["State"] == "in-use":
                    continue

                evidence = Evidence(
                    signals_used=[
                        "Volume state is not 'in-use' (not attached to any EC2 instance)"
                    ],
                    signals_not_checked=[
                        "Application-level usage",
                        "Disaster recovery intent",
                        "Manual operational workflows",
                        "Future planned attachments",
                    ],
                    time_window=None,
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.ebs.unattached",
                        resource_type="aws.ebs.volume",
                        resource_id=volume["VolumeId"],
                        region=region,
                        title="Unattached EBS volume",
                        summary="EBS volume is not attached to any EC2 instance",
                        reason="Volume is not currently attached at the provider level",
                        risk=RiskLevel.LOW,
                        confidence=ConfidenceLevel.MEDIUM,  # important correction
                        detected_at=datetime.now(timezone.utc),
                        evidence=evidence,
                        details={
                            "size_gb": volume["Size"],
                            "availability_zone": volume["AvailabilityZone"],
                            "state": volume["State"],
                            "create_time": volume["CreateTime"].isoformat(),
                            "tags": volume.get("Tags", []),
                        },
                    )
                )

    except ClientError as e:
        if e.response["Error"]["Code"] == "UnauthorizedOperation":
            raise PermissionError("Missing required IAM permission: ec2:DescribeVolumes") from e
        raise

    return findings
