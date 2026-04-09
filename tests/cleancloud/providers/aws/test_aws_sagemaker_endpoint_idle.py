from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from cleancloud.providers.aws.rules.sagemaker_endpoint_idle import (
    find_idle_sagemaker_endpoints,
)


def _make_session(sagemaker, cloudwatch):
    session = MagicMock()

    def client_side_effect(service_name, *args, **kwargs):
        if service_name == "sagemaker":
            return sagemaker
        if service_name == "cloudwatch":
            return cloudwatch
        raise ValueError(f"Unexpected service: {service_name}")

    session.client.side_effect = client_side_effect
    return session


def _make_endpoint(name="test-endpoint", age_days=30):
    now = datetime.now(timezone.utc)
    return {
        "EndpointName": name,
        "EndpointArn": f"arn:aws:sagemaker:us-east-1:123456789012:endpoint/{name}",
        "CreationTime": now - timedelta(days=age_days),
        "LastModifiedTime": now - timedelta(days=age_days),
        "EndpointStatus": "InService",
    }


def _make_describe_response(
    instance_type="ml.m5.xlarge", variant_count=1, desired_instance_count=1
):
    """Build a describe_endpoint response.

    ProductionVariantSummary does NOT include InstanceType — that lives in the
    endpoint config. We include EndpointConfigName so the rule can fetch it.
    """
    variants = [
        {
            "VariantName": f"variant-{i}",
            "CurrentInstanceCount": desired_instance_count,
            "DesiredInstanceCount": desired_instance_count,
        }
        for i in range(variant_count)
    ]
    return {"ProductionVariants": variants, "EndpointConfigName": "test-config"}


def _make_describe_config_response(instance_type="ml.m5.xlarge", variant_count=1):
    """Build a describe_endpoint_config response with InstanceType per variant."""
    variants = [
        {"VariantName": f"variant-{i}", "InstanceType": instance_type} for i in range(variant_count)
    ]
    return {"ProductionVariants": variants}


def _no_invocations():
    """CloudWatch returns no datapoints for an idle endpoint.

    SageMaker only publishes the Invocations metric when invocations actually occur.
    An endpoint with zero invocations has no metric series — empty datapoints.
    """
    return {"Datapoints": []}


def _has_invocations():
    return {"Datapoints": [{"Sum": 500.0, "Timestamp": datetime.now(timezone.utc)}]}


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------


def test_idle_cpu_endpoint_detected():
    """Idle CPU endpoint with zero invocations should be flagged as MEDIUM risk, HIGH confidence."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "aws.sagemaker.endpoint.idle"
    assert f.resource_type == "aws.sagemaker.endpoint"
    assert f.resource_id == "test-endpoint"
    assert f.confidence.value == "high"
    assert f.risk.value == "medium"
    assert f.details["is_gpu"] is False
    assert f.details["instance_type"] == "ml.m5.xlarge"
    assert f.details["age_days"] == 30
    assert f.details["total_instances"] == 1


def test_idle_gpu_endpoint_detected_high_risk():
    """GPU endpoint at exactly idle_days threshold (idle_ratio=1.0) -> HIGH risk."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    # age_days=14, idle_days=14 -> idle_ratio=1.0 -> HIGH (not CRITICAL)
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=14)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.p3.2xlarge")
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response(
        "ml.p3.2xlarge"
    )
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    assert f.risk.value == "high"
    assert f.details["is_gpu"] is True
    assert f.details["instance_type"] == "ml.p3.2xlarge"
    assert f.estimated_monthly_cost_usd == 2754.0


def test_idle_gpu_endpoint_critical_risk_when_very_stale():
    """GPU endpoint idle ≥ 2× threshold (idle_ratio ≥ 2.0) -> CRITICAL risk."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    # age_days=30, idle_days=14 -> idle_ratio=30/14≈2.14 -> CRITICAL
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.p3.2xlarge")
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response(
        "ml.p3.2xlarge"
    )
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 1
    assert findings[0].risk.value == "critical"
    assert findings[0].details["idle_ratio"] >= 2.0


def test_cpu_endpoint_never_reaches_critical():
    """CPU endpoints are capped at MEDIUM regardless of idle_ratio."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=60)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert findings[0].risk.value == "medium"


def test_active_endpoint_skipped():
    """Endpoint with invocations should NOT be flagged."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    cloudwatch.get_metric_statistics.return_value = _has_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 0


def test_young_endpoint_skipped():
    """Endpoint younger than minimum threshold should NOT be flagged."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=3)]}]
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 0


def test_timezone_naive_creation_time_handled():
    """boto3 may return timezone-naive CreationTime; endpoint should still be correctly aged."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    # Use a naive datetime (no tzinfo) — older boto3 behaviour
    naive_create_time = datetime.now() - timedelta(days=30)
    assert naive_create_time.tzinfo is None
    endpoint = _make_endpoint(age_days=30)
    endpoint["CreationTime"] = naive_create_time

    paginator.paginate.return_value = [{"Endpoints": [endpoint]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    # Should be flagged — age correctly computed despite naive timestamp
    assert len(findings) == 1
    assert findings[0].details["age_days"] >= 29  # allow off-by-one from sub-second timing


def test_no_endpoints_returns_empty():
    """No endpoints should return empty findings."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": []}]

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert findings == []


# ---------------------------------------------------------------------------
# Scaled-to-zero endpoints
# ---------------------------------------------------------------------------


def test_scaled_to_zero_endpoint_skipped():
    """Endpoint with all variants scaled to zero instances should NOT be flagged (no compute cost)."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response(
        "ml.m5.xlarge", desired_instance_count=0
    )
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 0


def test_missing_desired_instance_count_treated_as_zero():
    """DesiredInstanceCount missing from API response should be treated as 0, not 1."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    # No DesiredInstanceCount key — AWS response omits it
    sagemaker.describe_endpoint.return_value = {
        "ProductionVariants": [{"VariantName": "v1"}],
        "EndpointConfigName": "test-config",
    }
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    # total_instances = 0 (missing treated as 0) -> scaled-to-zero, no cost -> skip
    assert len(findings) == 0


def test_partial_scaled_to_zero_still_flagged():
    """Multi-variant endpoint where only some variants are zero should still be flagged if total > 0."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    # 2 variants: one with 1 instance, one with 0
    sagemaker.describe_endpoint.return_value = {
        "ProductionVariants": [
            {"VariantName": "v1", "DesiredInstanceCount": 1},
            {"VariantName": "v2", "DesiredInstanceCount": 0},
        ],
        "EndpointConfigName": "test-config",
    }
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 1
    assert findings[0].details["total_instances"] == 1


# ---------------------------------------------------------------------------
# Empty datapoints — unknown state
# ---------------------------------------------------------------------------


def test_empty_datapoints_on_old_endpoint_treated_as_idle():
    """Old endpoint with no CloudWatch data (metric series never initialized) should be flagged.

    CloudWatch only publishes SageMaker Invocations when invocations occur. An endpoint
    that has never been called has no metric series. Since the age guard already filters
    out endpoints < 7 days old, empty datapoints on a 30-day-old endpoint means idle.
    """
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = {"Datapoints": []}

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


# ---------------------------------------------------------------------------
# Effective window (age vs idle period)
# ---------------------------------------------------------------------------


def test_effective_window_capped_to_age():
    """For an endpoint younger than days_idle, the effective window is capped to age."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    # age=12, days_idle=14 -> effective_window=12
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=12)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 1
    assert findings[0].details["idle_window_days"] == 12
    assert findings[0].details["idle_days_threshold"] == 14


def test_very_small_effective_window_skipped():
    """Effective window < 3 days is too narrow for a reliable conclusion — skip.

    Setup: days_idle=2, age=8
    - Early age guard: age=8 >= max(2//2=1, 7) = 7 -> passes
    - effective_window = min(2, 8) = 2 < 3 -> skipped by the window guard
    """
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=8)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1", idle_days=2)

    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence_for_old_endpoint():
    """Endpoint older than days_idle should be HIGH confidence."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert findings[0].confidence.value == "high"


def test_medium_confidence_for_borderline_age():
    """Endpoint at 75% of idle threshold should be MEDIUM confidence."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    # age_days=11, int(14 * 0.75)=10 -> 11 >= 10 -> MEDIUM
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=11)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_borderline_age_below_threshold_skipped():
    """Endpoint below the 75% confidence threshold should be skipped."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    # age_days=8, int(14 * 0.75)=10 -> 8 < 10 -> skip
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=8)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 0


# ---------------------------------------------------------------------------
# GPU family detection
# ---------------------------------------------------------------------------


def test_g4dn_instance_detected_as_gpu():
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    # age_days=14 -> idle_ratio=1.0 -> HIGH (not CRITICAL)
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=14)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.g4dn.xlarge")
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response(
        "ml.g4dn.xlarge"
    )
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert findings[0].details["is_gpu"] is True
    assert findings[0].risk.value == "high"
    assert findings[0].estimated_monthly_cost_usd == 531.0


def test_inf1_instance_detected_as_gpu():
    """Inferentia instances should be classified as GPU-class (accelerator)."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.inf1.xlarge")
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response(
        "ml.inf1.xlarge"
    )
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert findings[0].details["is_gpu"] is True


# ---------------------------------------------------------------------------
# Multi-variant cost scaling
# ---------------------------------------------------------------------------


def test_multi_variant_cost_scaled():
    """Cost estimate should sum across all production variants × DesiredInstanceCount."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response(
        "ml.m5.xlarge", variant_count=3
    )
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response(
        "ml.m5.xlarge", variant_count=3
    )
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 1
    # ml.m5.xlarge = $188/month × 3 variants × 1 instance each
    assert findings[0].estimated_monthly_cost_usd == 188.0 * 3
    assert findings[0].details["variant_count"] == 3
    assert findings[0].details["total_instances"] == 3


def test_multi_variant_mixed_instance_types_cost():
    """Cost should sum per-variant when variants have different instance types."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.return_value = {
        "ProductionVariants": [
            {"VariantName": "cpu", "DesiredInstanceCount": 2},
            {"VariantName": "gpu", "DesiredInstanceCount": 1},
        ],
        "EndpointConfigName": "test-config",
    }
    sagemaker.describe_endpoint_config.return_value = {
        "ProductionVariants": [
            {"VariantName": "cpu", "InstanceType": "ml.m5.xlarge"},
            {"VariantName": "gpu", "InstanceType": "ml.g4dn.xlarge"},
        ]
    }
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 1
    f = findings[0]
    # ml.m5.xlarge × 2 + ml.g4dn.xlarge × 1 = 188×2 + 531×1 = 907
    assert f.estimated_monthly_cost_usd == 188.0 * 2 + 531.0 * 1
    # GPU because second variant is GPU
    assert f.details["is_gpu"] is True
    assert f.details["total_instances"] == 3


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_cloudwatch_failure_treated_as_active():
    """If CloudWatch metrics fail, endpoint should NOT be flagged (avoid false positives)."""
    from botocore.exceptions import ClientError

    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    cloudwatch.get_metric_statistics.side_effect = ClientError(
        {"Error": {"Code": "InternalError", "Message": "Service error"}},
        "GetMetricStatistics",
    )

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 0


def test_describe_endpoint_failure_skips_endpoint():
    """If describe_endpoint fails, endpoint is skipped (unknown state — don't accuse)."""
    from botocore.exceptions import ClientError

    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.side_effect = ClientError(
        {"Error": {"Code": "ValidationException", "Message": "Not found"}},
        "DescribeEndpoint",
    )
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    session = _make_session(sagemaker, cloudwatch)
    findings = find_idle_sagemaker_endpoints(session, "us-east-1")

    assert len(findings) == 0


def test_permission_error_raised():
    """AccessDenied on ListEndpoints should raise PermissionError."""
    from botocore.exceptions import ClientError

    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "ListEndpoints",
    )

    session = _make_session(sagemaker, cloudwatch)

    try:
        find_idle_sagemaker_endpoints(session, "us-east-1")
        assert False, "Expected PermissionError"
    except PermissionError as e:
        assert "sagemaker:ListEndpoints" in str(e)


# ---------------------------------------------------------------------------
# RULE_METADATA
# ---------------------------------------------------------------------------


def test_rule_metadata_present():
    """Rule must expose RULE_METADATA with correct fields."""
    from cleancloud.providers.aws.rules.sagemaker_endpoint_idle import RULE_METADATA

    assert RULE_METADATA["id"] == "aws.sagemaker.endpoint.idle"
    assert RULE_METADATA["category"] == "ai"
    assert RULE_METADATA["service"] == "sagemaker"
    assert RULE_METADATA["cost_impact"] == "high"


# ---------------------------------------------------------------------------
# idle_ratio + cost_source in details
# ---------------------------------------------------------------------------


def test_details_include_idle_ratio():
    """idle_ratio should be present in finding details."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=28)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

    assert findings[0].details["idle_ratio"] == 2.0


def test_details_include_cost_source_with_region():
    """cost_source should reflect the scanned region, not always us-east-1."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response("ml.m5.xlarge")
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response("ml.m5.xlarge")
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "eu-west-1")

    assert findings[0].details["cost_source"] == "approximate_eu-west-1"


# ---------------------------------------------------------------------------
# New cost entries — p4de, p5, trn1, inf2
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "instance_type,expected_cost",
    [
        ("ml.p4de.24xlarge", 29_908.0),
        ("ml.p5.48xlarge", 71_774.0),
        ("ml.trn1.2xlarge", 978.0),
        ("ml.trn1.32xlarge", 15_695.0),
        ("ml.inf2.xlarge", 554.0),
        ("ml.inf2.48xlarge", 26_566.0),
    ],
)
def test_new_gpu_instance_cost_lookup(instance_type, expected_cost):
    """Newly added accelerator instance types should resolve to their correct cost."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=14)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response(instance_type)
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response(instance_type)
    cloudwatch.get_metric_statistics.return_value = _no_invocations()

    findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd == expected_cost
    assert findings[0].details["is_gpu"] is True
