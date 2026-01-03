from datetime import datetime, timezone
from typing import List

import boto3

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel


def find_inactive_cloudwatch_logs(
    session: boto3.Session,
    region: str,
) -> List[Finding]:
    """
    Find CloudWatch log groups with:
    - Infinite retention (never expire)

    Conservative rule:
    - Ingestion activity is NOT inferred in MVP
    - Review-only, read-only outputs

    IAM permissions:
    - logs:DescribeLogGroups
    """
    logs = session.client("logs", region_name=region)
    paginator = logs.get_paginator("describe_log_groups")

    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    for page in paginator.paginate():
        for lg in page.get("logGroups", []):
            retention_days = lg.get("retentionInDays")  # None = never expire

            if retention_days is None:
                evidence = Evidence(
                    signals_used=["Log group has no retention policy configured (never expires)"],
                    signals_not_checked=[
                        "Recent ingestion activity",
                        "Application-level usage",
                        "Compliance retention requirements",
                        "Future expected logs",
                    ],
                    time_window=None,
                )

                findings.append(
                    Finding(
                        provider="aws",
                        rule_id="aws.cloudwatch.logs.infinite_retention",
                        resource_type="aws.cloudwatch.log_group",
                        resource_id=lg["logGroupName"],
                        region=region,
                        title="CloudWatch log group with infinite retention",
                        summary="Log group has no retention policy configured",
                        reason="Retention is not set (logs never expire)",
                        risk=RiskLevel.LOW,
                        confidence=ConfidenceLevel.MEDIUM,  # conservative
                        detected_at=now,
                        evidence=evidence,
                        details={
                            "stored_bytes": lg.get("storedBytes"),
                            "retention_days": retention_days,
                        },
                    )
                )

    return findings
