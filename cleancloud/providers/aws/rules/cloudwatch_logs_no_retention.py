from datetime import datetime, timezone
from typing import List, Optional

import boto3

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Log groups newer than this are skipped — noise-reduction heuristic, not an AWS rule.
# New groups may not have had time for an operator to review and configure retention.
_MIN_AGE_DAYS = 7

# Approximate CloudWatch Logs storage cost per GB-month.
# This is the us-east-1 rate as of 2024; actual cost varies by region.
# Use only as an order-of-magnitude estimate, not a billing figure.
_STORAGE_COST_PER_GB_APPROX = 0.03

# Risk thresholds by stored size
_HIGH_RISK_GB = 1.0  # ≥ 1 GB stored → HIGH (significant cost + compliance exposure)
# < 1 GB stored → MEDIUM; 0 bytes stored → LOW (no current cost, but policy gap still flagged)


def find_cloudwatch_logs_no_retention(
    session: boto3.Session,
    region: str,
) -> List[Finding]:
    """
    Find CloudWatch log groups with no retention policy (logs never expire).

    This is a hygiene rule, not an idle/activity rule. It flags log groups where
    retentionInDays is unset, meaning logs accumulate indefinitely and storage costs
    grow without bound.

    Notes on accuracy:
    - storedBytes is eventually consistent and may lag actual ingestion by hours.
      The cost estimate is therefore approximate and should not be used for billing.
    - Log groups newer than 7 days are skipped as a noise-reduction heuristic.
    - Infinite retention may be intentional for audit/security/compliance logs —
      always review before acting on findings from this rule.
    - Zero storedBytes does not mean no future cost risk; active log groups can
      grow rapidly once ingestion begins.

    Risk is dynamic based on stored data size:
    - HIGH:   ≥ 1 GB stored (significant ongoing cost + likely compliance exposure)
    - MEDIUM: > 0 bytes but < 1 GB (growing cost, policy gap)
    - LOW:    0 bytes stored (no current cost, but hygiene issue)

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

            if retention_days is not None:
                continue

            # Noise-reduction heuristic: skip recently created log groups.
            # This is NOT an AWS-defined behavior — new groups may simply not have
            # been reviewed yet. Adjust _MIN_AGE_DAYS if this produces too much noise.
            creation_time_ms = lg.get("creationTime")
            if creation_time_ms:
                creation_time = datetime.fromtimestamp(creation_time_ms / 1000, tz=timezone.utc)
                age_days = (now - creation_time).days
                if age_days < _MIN_AGE_DAYS:
                    continue
            else:
                age_days = None

            stored_bytes = lg.get("storedBytes") or 0
            stored_gb = stored_bytes / (1024**3)

            # storedBytes is eventually consistent — cost estimate may lag reality.
            monthly_storage_cost: Optional[float] = (
                round(stored_gb * _STORAGE_COST_PER_GB_APPROX, 2) if stored_bytes > 0 else None
            )

            # Risk is proportional to stored size
            if stored_gb >= _HIGH_RISK_GB:
                risk = RiskLevel.HIGH
            elif stored_bytes > 0:
                risk = RiskLevel.MEDIUM
            else:
                risk = RiskLevel.LOW

            signals_used = [
                "Log group has no retention policy configured (logs never expire)",
            ]
            if age_days is not None:
                signals_used.append(f"Log group is {age_days} days old")
            if stored_bytes > 0:
                signals_used.append(
                    f"Stored data: {stored_gb:.2f} GB "
                    f"(~${monthly_storage_cost:.2f}/month at ~${_STORAGE_COST_PER_GB_APPROX}/GB — "
                    f"region-dependent estimate; storedBytes may lag actual ingestion)"
                )
            else:
                signals_used.append(
                    "Stored data: 0 bytes (storedBytes may lag; active groups can grow rapidly)"
                )

            evidence = Evidence(
                signals_used=signals_used,
                signals_not_checked=[
                    "Recent ingestion activity (not checked — this is a hygiene rule)",
                    "Intentional retention for audit, security, or compliance logs",
                    "Application-level usage",
                    "Future ingestion volume",
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
                    estimated_monthly_cost_usd=monthly_storage_cost,
                    title="CloudWatch log group with infinite retention",
                    summary=(
                        "Log group has no retention policy — logs accumulate indefinitely"
                        + (f" ({stored_gb:.2f} GB stored)" if stored_bytes > 0 else "")
                    ),
                    reason="Retention is not set (logs never expire)",
                    risk=risk,
                    confidence=ConfidenceLevel.MEDIUM,  # conservative — no activity check
                    detected_at=now,
                    evidence=evidence,
                    details={
                        "stored_bytes": stored_bytes,
                        "stored_gb": round(stored_gb, 4),
                        "stored_bytes_note": "eventually consistent — may lag actual ingestion",
                        "retention_days": retention_days,
                        "age_days": age_days,
                        "age_gate_note": f"groups < {_MIN_AGE_DAYS} days old are skipped (noise-reduction heuristic)",
                        "estimated_monthly_storage_cost": (
                            f"~${monthly_storage_cost:.2f}/month (approx, region-dependent)"
                            if monthly_storage_cost
                            else "negligible now — active groups can grow rapidly"
                        ),
                    },
                )
            )

    return findings
