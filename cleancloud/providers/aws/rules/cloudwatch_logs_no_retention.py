"""
Rule: aws.cloudwatch.logs.infinite_retention

    (spec — docs/specs/aws/cloudwatch_logs_no_retention.md)

Intent:
    Detect eligible CloudWatch log groups with no retention policy configured.

Exclusions:
    - retentionInDays is set
    - DELIVERY class log groups

Detection:
    - retentionInDays key not present on STANDARD or INFREQUENT_ACCESS log groups

Key rules:
    - This is a hygiene/configuration rule, not an idle rule.
    - Missing retention is a direct AWS-observed configuration fact.
    - storedBytes must not be used as an activity signal.
    - storedBytes is a non-billing storage metric.
    - DELIVERY class must be excluded because its retention is service-managed.

Blind spots:
    - intent for compliance/audit/security retention is not known
    - ingestion/activity is not checked
    - future log growth is not known

API:
    - logs:DescribeLogGroups
"""

from datetime import datetime, timezone
from typing import List, Optional

import boto3

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel

# Approximate CloudWatch Logs storage cost per GB-month (us-east-1, 2024).
# Informational only — must NOT influence detection or confidence (spec 9).
_STORAGE_COST_PER_GB_APPROX = 0.03

# Risk thresholds by stored size (spec 8)
_HIGH_RISK_GB = 1.0  # ≥ 1 GB → HIGH; < 1 GB → MEDIUM; 0 bytes → LOW

# Only these classes are eligible (spec 2). Allowlist — unknown/missing class is NOT in scope.
_ELIGIBLE_CLASSES = {"STANDARD", "INFREQUENT_ACCESS"}


def find_cloudwatch_logs_no_retention(
    session: boto3.Session,
    region: str,
) -> List[Finding]:
    logs = session.client("logs", region_name=region)
    paginator = logs.get_paginator("describe_log_groups")

    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    for page in paginator.paginate():
        for lg in page.get("logGroups", []):
            # EXCLUSION: malformed record (spec 2)
            if not lg.get("logGroupName"):
                continue

            # EXCLUSION: only STANDARD and INFREQUENT_ACCESS are in scope (spec 2, 4A).
            # DELIVERY is service-managed; unknown/missing class is not eligible.
            if lg.get("logGroupClass") not in _ELIGIBLE_CLASSES:
                continue

            # EXCLUSION: retention policy is set — key presence check, not value check (spec 4A).
            # "retentionInDays is not present in the returned log group object" means
            # key absent, not value null. An explicit null would still mean the key was
            # returned and should be treated as set.
            if "retentionInDays" in lg:
                continue

            # --- Detection path: no-retention ---

            log_group_name = lg["logGroupName"]
            log_group_class = lg.get("logGroupClass")

            creation_time_ms = lg.get("creationTime")
            if creation_time_ms is not None:
                creation_time = datetime.fromtimestamp(creation_time_ms / 1000, tz=timezone.utc)
                age_days: Optional[int] = (now - creation_time).days
            else:
                creation_time = None
                age_days = None

            # storedBytes is a non-billing, eventually-consistent storage metric (spec 3, 9).
            # It must NOT be used as an activity signal.
            stored_bytes: Optional[int] = lg.get("storedBytes")
            stored_gb: Optional[float] = (
                (stored_bytes / (1024**3)) if stored_bytes is not None else None
            )

            # Risk is proportional to stored size as a proxy for current storage exposure (spec 8)
            if stored_gb is not None and stored_gb >= _HIGH_RISK_GB:
                risk = RiskLevel.HIGH
            elif stored_bytes is not None and stored_bytes > 0:
                risk = RiskLevel.MEDIUM
            else:
                risk = RiskLevel.LOW

            # Cost estimate — informational only (spec 9)
            monthly_storage_cost: Optional[float] = None
            if stored_bytes is not None and stored_bytes > 0 and stored_gb is not None:
                monthly_storage_cost = round(stored_gb * _STORAGE_COST_PER_GB_APPROX, 2)

            signals_used = ["retentionInDays is not set (logs do not expire)"]
            if age_days is not None:
                signals_used.append(f"log group age: {age_days} days")
            if stored_bytes is not None:
                if stored_bytes > 0 and stored_gb is not None:
                    signals_used.append(f"stored data: {stored_gb:.2f} GB")
                else:
                    signals_used.append("stored data: 0 bytes")

            evidence = Evidence(
                signals_used=signals_used,
                signals_not_checked=[
                    "intentional compliance/audit/security retention is not known",
                    "recent ingestion activity (not checked — this is a hygiene rule)",
                    "application-level usage context",
                    "future ingestion volume",
                    "cross-account linked log groups are out of scope unless includeLinkedAccounts is explicitly enabled",
                    "DELIVERY class log groups are excluded (retention is service-managed)",
                ],
                time_window=None,
            )

            findings.append(
                Finding(
                    provider="aws",
                    rule_id="aws.cloudwatch.logs.infinite_retention",
                    resource_type="aws.cloudwatch.log_group",
                    resource_id=log_group_name,
                    region=region,
                    estimated_monthly_cost_usd=monthly_storage_cost,
                    title="CloudWatch log group with no retention policy",
                    summary=(
                        "Retention is not configured; log events do not expire"
                        + (
                            f" ({stored_gb:.2f} GB stored)"
                            if stored_bytes is not None
                            and stored_bytes > 0
                            and stored_gb is not None
                            else ""
                        )
                    ),
                    reason="Retention is not configured; log events do not expire",
                    risk=risk,
                    confidence=ConfidenceLevel.HIGH,
                    detected_at=now,
                    evidence=evidence,
                    details={
                        "evaluation_path": "no-retention",
                        "log_group_name": log_group_name,
                        "log_group_class": log_group_class,
                        "retention_state": "not set (logs do not expire)",
                        "creation_time": (
                            creation_time.isoformat() if creation_time is not None else None
                        ),
                        "age_days": age_days,
                        "stored_bytes": stored_bytes,
                        "stored_gb": round(stored_gb, 4) if stored_gb is not None else None,
                        "estimated_monthly_storage_cost_usd": monthly_storage_cost,
                        "cost_note": (
                            "approximate, region-dependent; "
                            "storedBytes is a non-billing point-in-time storage metric"
                        ),
                    },
                )
            )

    return findings
