"""
Rule: aws.opensearch.domain.idle

    (spec => docs/specs/aws/opensearch_domain_idle.md)

Intent:
    Detect provisioned OpenSearch Service domains that are active but have had
    zero search and indexing activity over the configured idle window, so they
    can be reviewed as candidates for deletion or downsizing.

    This is a CleanCloud-derived idle heuristic based on OpenSearch domain
    metadata and CloudWatch activity metrics. It is a read-only
    review-candidate rule — not a delete-safe rule.

Exclusions:
    - domain_name or arn absent (malformed inventory item)
    - domain_processing_status absent or not "Active"
    - created != true or deleted == true
    - CloudWatch returned no datapoints for OpenSearchRequests
    - coverage_ratio < 0.95 (insufficient evidence)
    - OpenSearchRequests Sum > 0 in any hourly period

Detection:
    - DomainProcessingStatus == "Active", Created == true, Deleted != true
    - OpenSearchRequests Sum == 0 across all hourly periods with >= 95% coverage

Key rules:
    - OpenSearchRequests Sum (hourly) is the sole required activity metric.
    - Coverage requirement: actual_datapoints / expected_datapoints >= 0.95.
    - Missing CloudWatch datapoints => SKIP ITEM (not zero).
    - CloudWatch API failure => FAIL RULE.
    - SearchRate / IndexingRate are best-effort secondary signals for confidence.
    - estimated_monthly_cost_usd = None.
    - Confidence: HIGH when primary + secondary all zero; MEDIUM otherwise.
    - Risk: HIGH when instance_count >= 3 or warm/dedicated masters enabled;
      MEDIUM otherwise.
    - OpenSearch Serverless is out of scope (separate API).

Blind spots:
    - Business value or planned future use
    - Whether deleting the domain is safe
    - Compliance log retention purpose
    - Exact price impact or savings impact
    - Whether domain data has been backed up

APIs:
    - es:ListDomainNames
    - es:DescribeDomain
    - cloudwatch:GetMetricStatistics
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.finding import Finding
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.errors import is_permission_error

# --- Module-level constants ---

_DEFAULT_IDLE_DAYS_THRESHOLD = 14
_ELIGIBLE_STATUS = "Active"
_CW_NAMESPACE = "AWS/ES"
_COVERAGE_THRESHOLD = 0.95

_FINDING_TITLE = "Idle OpenSearch domain review candidate"
_FINDING_REASON = "Active OpenSearch domain has had zero requests over the configured idle window"

_SIGNALS_NOT_CHECKED = (
    "Business value or planned future use",
    "Whether deleting the domain is safe",
    "Compliance log retention purpose",
    "Exact price impact or savings impact",
    "Whether domain data has been backed up",
)

RULE_METADATA = {
    "id": "aws.opensearch.domain.idle",
    "category": "hygiene",
    "service": "opensearch",
    "cost_impact": "high",
}


def _str(value: object) -> Optional[str]:
    """Return value as str only when it is a non-empty string; else None."""
    return value if isinstance(value, str) and value else None


def _bool(value: object) -> Optional[bool]:
    """Return value as bool only when it is a boolean; else None."""
    return value if isinstance(value, bool) else None


def _int(value: object) -> Optional[int]:
    """Return value as int only when it is an int (not bool); else None."""
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _extract_account_id_from_arn(arn: str) -> Optional[str]:
    """Extract the AWS account ID from an OpenSearch domain ARN.

    ARN format: arn:aws:es:<region>:<account-id>:domain/<name>
    """
    parts = arn.split(":")
    if len(parts) >= 5:
        account_id = parts[4]
        if account_id and account_id.isdigit():
            return account_id
    return None


def _normalize_domain(domain_status: object) -> Optional[dict]:
    """Normalize a raw DescribeDomain DomainStatus to canonical fields.

    Returns None when required fields are absent or invalid — caller must skip.
    """
    if not isinstance(domain_status, dict):
        return None

    # --- Identity (required) ---
    domain_name = _str(domain_status.get("DomainName"))
    if domain_name is None:
        return None

    arn = _str(domain_status.get("ARN"))
    if arn is None:
        return None

    # --- Lifecycle status (required) ---
    domain_processing_status = _str(domain_status.get("DomainProcessingStatus"))
    if domain_processing_status is None:
        return None

    created = _bool(domain_status.get("Created"))
    if created is None:
        return None

    deleted = _bool(domain_status.get("Deleted"))
    if deleted is None:
        deleted = False

    processing = _bool(domain_status.get("Processing"))
    if processing is None:
        processing = False

    # --- Optional fields ---
    domain_id = _str(domain_status.get("DomainId"))
    engine_version = _str(domain_status.get("EngineVersion"))

    # ClusterConfig
    cluster_config = domain_status.get("ClusterConfig")
    if not isinstance(cluster_config, dict):
        cluster_config = {}

    instance_type = _str(cluster_config.get("InstanceType"))
    instance_count = _int(cluster_config.get("InstanceCount"))
    dedicated_master_enabled = cluster_config.get("DedicatedMasterEnabled")
    if not isinstance(dedicated_master_enabled, bool):
        dedicated_master_enabled = False
    dedicated_master_type = _str(cluster_config.get("DedicatedMasterType"))
    dedicated_master_count = _int(cluster_config.get("DedicatedMasterCount"))
    warm_enabled = cluster_config.get("WarmEnabled")
    if not isinstance(warm_enabled, bool):
        warm_enabled = False
    warm_type = _str(cluster_config.get("WarmType"))
    warm_count = _int(cluster_config.get("WarmCount"))

    # EBSOptions
    ebs_options = domain_status.get("EBSOptions")
    if not isinstance(ebs_options, dict):
        ebs_options = {}

    ebs_enabled = ebs_options.get("EBSEnabled")
    if not isinstance(ebs_enabled, bool):
        ebs_enabled = False
    ebs_volume_type = _str(ebs_options.get("VolumeType"))
    ebs_volume_size_gb = _int(ebs_options.get("VolumeSize"))

    # Endpoints
    endpoint = _str(domain_status.get("Endpoint"))
    raw_endpoints = domain_status.get("Endpoints")
    endpoints = raw_endpoints if isinstance(raw_endpoints, dict) else None

    return {
        "domain_name": domain_name,
        "domain_id": domain_id,
        "arn": arn,
        "engine_version": engine_version,
        "domain_processing_status": domain_processing_status,
        "created": created,
        "deleted": deleted,
        "processing": processing,
        "instance_type": instance_type,
        "instance_count": instance_count,
        "dedicated_master_enabled": dedicated_master_enabled,
        "dedicated_master_type": dedicated_master_type,
        "dedicated_master_count": dedicated_master_count,
        "warm_enabled": warm_enabled,
        "warm_type": warm_type,
        "warm_count": warm_count,
        "ebs_enabled": ebs_enabled,
        "ebs_volume_type": ebs_volume_type,
        "ebs_volume_size_gb": ebs_volume_size_gb,
        "endpoint": endpoint,
        "endpoints": endpoints,
        "resource_id": arn,
    }


def _get_cw_hourly(
    cloudwatch,
    metric_name: str,
    client_id: str,
    domain_name: str,
    start_time: datetime,
    end_time: datetime,
) -> Optional[list]:
    """Fetch hourly CloudWatch datapoints for an OpenSearch domain.

    Returns None on no datapoints (insufficient evidence).
    Returns the list of datapoints on success.
    Raises on API failure (caller => FAIL RULE).
    """
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace=_CW_NAMESPACE,
            MetricName=metric_name,
            Dimensions=[
                {"Name": "ClientId", "Value": client_id},
                {"Name": "DomainName", "Value": domain_name},
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=["Sum"],
        )
    except ClientError as exc:
        if is_permission_error(exc):
            raise PermissionError(
                "Missing required IAM permission: cloudwatch:GetMetricStatistics"
            ) from exc
        raise
    except BotoCoreError:
        raise

    datapoints = resp.get("Datapoints", [])
    if not datapoints:
        return None

    return datapoints


def _get_secondary_sum(
    cloudwatch,
    metric_name: str,
    client_id: str,
    domain_name: str,
    start_time: datetime,
    end_time: datetime,
    idle_window_seconds: int,
) -> Optional[float]:
    """Best-effort fetch of a secondary metric as a single full-window aggregate.

    Returns None on any failure.
    """
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace=_CW_NAMESPACE,
            MetricName=metric_name,
            Dimensions=[
                {"Name": "ClientId", "Value": client_id},
                {"Name": "DomainName", "Value": domain_name},
            ],
            StartTime=start_time,
            EndTime=end_time,
            Period=idle_window_seconds,
            Statistics=["Sum"],
        )
        datapoints = resp.get("Datapoints", [])
        if not datapoints:
            return None
        return sum(dp.get("Sum", 0.0) for dp in datapoints)
    except Exception:
        return None


def find_idle_opensearch_domains(
    session: boto3.Session,
    region: str,
    idle_days_threshold: int = _DEFAULT_IDLE_DAYS_THRESHOLD,
) -> List[Finding]:
    opensearch = session.client("opensearch", region_name=region)
    cloudwatch = session.client("cloudwatch", region_name=region)

    # Spec 8.1: ListDomainNames (single call, no pagination).
    try:
        list_resp = opensearch.list_domain_names()
    except ClientError as exc:
        if is_permission_error(exc):
            raise PermissionError("Missing required IAM permission: es:ListDomainNames") from exc
        raise
    except BotoCoreError:
        raise

    domain_names = [
        d["DomainName"]
        for d in list_resp.get("DomainNames", [])
        if isinstance(d, dict) and _str(d.get("DomainName"))
    ]

    if not domain_names:
        return []

    now = datetime.now(timezone.utc)
    idle_window_seconds = idle_days_threshold * 86400
    window_start = now - timedelta(seconds=idle_window_seconds)
    expected_datapoints = idle_days_threshold * 24
    findings: List[Finding] = []

    # Spec 8.2: DescribeDomain for each domain.
    for dname in domain_names:
        try:
            desc_resp = opensearch.describe_domain(DomainName=dname)
        except ClientError as exc:
            if is_permission_error(exc):
                raise PermissionError("Missing required IAM permission: es:DescribeDomain") from exc
            # Narrow race: domain deleted between list and describe
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("ResourceNotFoundException", "ValidationException"):
                continue
            raise
        except BotoCoreError:
            raise

        raw_status = desc_resp.get("DomainStatus")
        if raw_status is None:
            continue

        # --- Step 1: Normalize ---
        n = _normalize_domain(raw_status)
        if n is None:
            continue

        # --- Step 2: Exclusion rules ---
        if n["domain_processing_status"] != _ELIGIBLE_STATUS:
            continue
        if n["created"] is not True:
            continue
        if n["deleted"] is True:
            continue

        # Extract account ID from domain ARN for CloudWatch ClientId dimension.
        # This avoids a separate sts:GetCallerIdentity dependency.
        client_id = _extract_account_id_from_arn(n["arn"])
        if client_id is None:
            continue

        # --- Step 3: Primary CloudWatch signal (hourly, with coverage) ---
        datapoints = _get_cw_hourly(
            cloudwatch,
            "OpenSearchRequests",
            client_id,
            n["domain_name"],
            window_start,
            now,
        )

        # No datapoints => insufficient evidence
        if datapoints is None:
            continue

        # Deduplicate by timestamp — CloudWatch can theoretically return
        # duplicate datapoints for the same period. Keep the last seen value
        # per timestamp to avoid inflating coverage_ratio.
        seen_timestamps: dict = {}
        for dp in datapoints:
            ts = dp.get("Timestamp")
            seen_timestamps[ts] = dp.get("Sum", 0.0)
        deduped_sums = list(seen_timestamps.values())

        actual_datapoints = len(deduped_sums)
        coverage_ratio = actual_datapoints / expected_datapoints if expected_datapoints > 0 else 0

        # Coverage check
        if coverage_ratio < _COVERAGE_THRESHOLD:
            continue

        # Idle check: every hourly datapoint must have Sum == 0
        opensearch_requests_sum = sum(deduped_sums)
        if any(v > 0 for v in deduped_sums):
            continue

        # --- Step 4: Secondary signals (best-effort) ---
        search_rate_sum = _get_secondary_sum(
            cloudwatch,
            "SearchRate",
            client_id,
            n["domain_name"],
            window_start,
            now,
            idle_window_seconds,
        )
        indexing_rate_sum = _get_secondary_sum(
            cloudwatch,
            "IndexingRate",
            client_id,
            n["domain_name"],
            window_start,
            now,
            idle_window_seconds,
        )

        # --- Step 5: Confidence and Risk ---
        all_secondary_present = search_rate_sum is not None and indexing_rate_sum is not None
        all_secondary_zero = (
            all_secondary_present and abs(search_rate_sum) < 1e-9 and abs(indexing_rate_sum) < 1e-9
        )
        confidence = ConfidenceLevel.HIGH if all_secondary_zero else ConfidenceLevel.MEDIUM

        is_large = (
            (n["instance_count"] is not None and n["instance_count"] >= 3)
            or n["warm_enabled"]
            or n["dedicated_master_enabled"]
        )
        risk = RiskLevel.HIGH if is_large else RiskLevel.MEDIUM

        # --- Step 6: Emit ---
        signals_used = [
            f"Domain processing status is '{_ELIGIBLE_STATUS}'",
            f"OpenSearchRequests Sum was 0 across all {actual_datapoints} hourly "
            f"datapoints in the {idle_days_threshold}-day evaluation window "
            f"(coverage: {coverage_ratio:.0%})",
        ]

        findings.append(
            Finding(
                provider="aws",
                rule_id="aws.opensearch.domain.idle",
                resource_type="aws.opensearch.domain",
                resource_id=n["resource_id"],
                region=region,
                estimated_monthly_cost_usd=None,
                title=_FINDING_TITLE,
                summary=(
                    f"OpenSearch domain '{n['domain_name']}' has had zero requests "
                    f"for {idle_days_threshold} days"
                ),
                reason=_FINDING_REASON,
                risk=risk,
                confidence=confidence,
                detected_at=now,
                evidence=Evidence(
                    signals_used=signals_used,
                    signals_not_checked=list(_SIGNALS_NOT_CHECKED),
                    time_window=f"{idle_days_threshold} days",
                ),
                details={
                    # Required fields
                    "evaluation_path": "idle-opensearch-domain-review-candidate",
                    "domain_name": n["domain_name"],
                    "arn": n["arn"],
                    "domain_processing_status": _ELIGIBLE_STATUS,
                    "engine_version": n["engine_version"],
                    "instance_type": n["instance_type"],
                    "instance_count": n["instance_count"],
                    "idle_days_threshold": idle_days_threshold,
                    "evaluation_window_start": window_start.isoformat(),
                    "evaluation_window_end": now.isoformat(),
                    "opensearch_requests_sum": opensearch_requests_sum,
                    "expected_datapoints": expected_datapoints,
                    "actual_datapoints": actual_datapoints,
                    "coverage_ratio": round(coverage_ratio, 4),
                    "is_idle": True,
                    # Optional context
                    "domain_id": n["domain_id"],
                    "search_rate_sum": search_rate_sum,
                    "indexing_rate_sum": indexing_rate_sum,
                    "dedicated_master_enabled": n["dedicated_master_enabled"],
                    "dedicated_master_type": n["dedicated_master_type"],
                    "dedicated_master_count": n["dedicated_master_count"],
                    "warm_enabled": n["warm_enabled"],
                    "warm_type": n["warm_type"],
                    "warm_count": n["warm_count"],
                    "ebs_enabled": n["ebs_enabled"],
                    "ebs_volume_type": n["ebs_volume_type"],
                    "ebs_volume_size_gb": n["ebs_volume_size_gb"],
                    "endpoint": n["endpoint"],
                    "endpoints": n["endpoints"],
                },
            )
        )

    return findings
