from __future__ import annotations

from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError


def find_unattached_ebs_volumes(
        session: boto3.Session,
        region: str,
) -> List[Dict[str, Any]]:
    """
    Find EBS volumes that are not attached to any EC2 instance.

    SAFE RULE:
    - volume.state != 'in-use'

    Requires IAM permission:
    - ec2:DescribeVolumes
    """
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_volumes")

    findings: List[Dict[str, Any]] = []

    try:
        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                if volume["State"] != "in-use":
                    findings.append(
                        {
                            "provider": "aws",
                            "resource_type": "ebs_volume",
                            "resource_id": volume["VolumeId"],
                            "state": volume["State"],
                            "size_gb": volume["Size"],
                            "availability_zone": volume["AvailabilityZone"],
                            "create_time": volume["CreateTime"].isoformat(),
                            "attachments": volume.get("Attachments", []),
                            "tags": volume.get("Tags", []),
                            "confidence": "HIGH",
                            "risk": "Low",
                            "rule": "ebs_unattached",
                            "reason": "Volume is not attached to any EC2 instance",
                        }
                    )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "UnauthorizedOperation":
            raise PermissionError(
                "Missing required IAM permission: ec2:DescribeVolumes"
            ) from e

        # re-raise unexpected AWS errors
        raise

    return findings
