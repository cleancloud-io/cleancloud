from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.ai.sagemaker_endpoint_idle import (
    _normalize_endpoint_summary,
    _normalize_variant,
    find_idle_sagemaker_endpoints,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _make_endpoint(name="test-endpoint", age_days=30, arn=None):
    now = datetime.now(timezone.utc)
    arn = arn or f"arn:aws:sagemaker:us-east-1:123456789012:endpoint/{name}"
    return {
        "EndpointName": name,
        "EndpointArn": arn,
        "CreationTime": now - timedelta(days=age_days),
        "LastModifiedTime": now - timedelta(days=age_days),
        "EndpointStatus": "InService",
    }


def _make_describe_response(
    instance_type="ml.m5.xlarge", variant_count=1, current_instance_count=1
):
    variants = [
        {
            "VariantName": f"variant-{i}",
            "CurrentInstanceCount": current_instance_count,
        }
        for i in range(variant_count)
    ]
    return {
        "ProductionVariants": variants,
        "EndpointConfigName": "test-config",
        "EndpointStatus": "InService",
    }


def _make_describe_config_response(instance_type="ml.m5.xlarge", variant_count=1):
    variants = [
        {"VariantName": f"variant-{i}", "InstanceType": instance_type} for i in range(variant_count)
    ]
    return {"ProductionVariants": variants}


def _zero_invocations():
    """CloudWatch returns datapoints with Sum=0 — explicit zero traffic."""
    return {"Datapoints": [{"Sum": 0.0, "Timestamp": datetime.now(timezone.utc)}]}


def _no_invocations():
    """CloudWatch returns no datapoints — no metric series published."""
    return {"Datapoints": []}


def _has_invocations():
    return {"Datapoints": [{"Sum": 500.0, "Timestamp": datetime.now(timezone.utc)}]}


def _client_error(code="InternalError"):
    err = ClientError({"Error": {"Code": code, "Message": "err"}}, "GetMetricStatistics")
    return err


def _botocore_error():
    return BotoCoreError()


def _make_full_sagemaker(
    endpoint_name="test-endpoint",
    age_days=30,
    instance_type="ml.m5.xlarge",
    current_instance_count=1,
    variant_count=1,
    invocations_response=None,
):
    """Build a complete sagemaker+cloudwatch mock for a single idle endpoint."""
    sagemaker = MagicMock()
    cloudwatch = MagicMock()
    if invocations_response is None:
        invocations_response = _zero_invocations()

    paginator = sagemaker.get_paginator.return_value
    paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(endpoint_name, age_days)]}]
    sagemaker.describe_endpoint.return_value = _make_describe_response(
        instance_type, variant_count, current_instance_count
    )
    sagemaker.describe_endpoint_config.return_value = _make_describe_config_response(
        instance_type, variant_count
    )
    cloudwatch.get_metric_statistics.return_value = invocations_response
    return sagemaker, cloudwatch


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_idle_instance_endpoint_emits(self):
        """InService endpoint, age >= threshold, billable instance, zero Sum → emit."""
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws.sagemaker.endpoint.idle"
        assert f.provider == "aws"
        assert f.resource_type == "aws.sagemaker.endpoint"

    def test_resource_id_is_endpoint_arn(self):
        """resource_id must be the EndpointArn, not the endpoint name."""
        sagemaker, cloudwatch = _make_full_sagemaker(endpoint_name="my-endpoint")
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].resource_id.startswith("arn:aws:sagemaker:")
        assert "my-endpoint" in findings[0].resource_id
        assert findings[0].resource_id != "my-endpoint"

    def test_idle_serverless_provisioned_endpoint_emits(self):
        """Serverless variant with CurrentServerlessConfig.ProvisionedConcurrency > 0 → emit."""
        sagemaker = MagicMock()
        cloudwatch = MagicMock()

        now = datetime.now(timezone.utc)
        endpoint = {
            "EndpointName": "sl-endpoint",
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/sl-endpoint",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
            "EndpointStatus": "InService",
        }
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [endpoint]}]
        sagemaker.describe_endpoint.return_value = {
            "ProductionVariants": [
                {
                    "VariantName": "AllTraffic",
                    "CurrentServerlessConfig": {"ProvisionedConcurrency": 3},
                }
            ],
            "EndpointConfigName": "sl-config",
            "EndpointStatus": "InService",
        }
        sagemaker.describe_endpoint_config.return_value = {
            "ProductionVariants": [
                {
                    "VariantName": "AllTraffic",
                    "ServerlessConfig": {
                        "MaxConcurrency": 10,
                        "ProvisionedConcurrency": 3,
                    },
                }
            ]
        }
        cloudwatch.get_metric_statistics.return_value = _zero_invocations()

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert len(findings) == 1
        assert findings[0].details["total_provisioned_concurrency"] == 3

    def test_high_confidence_when_all_variants_have_datapoints(self):
        """All billable variants return datapoints + Sum=0 → HIGH confidence."""
        sagemaker, cloudwatch = _make_full_sagemaker(invocations_response=_zero_invocations())
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].confidence.value == "high"

    def test_medium_confidence_when_any_variant_has_no_datapoints(self):
        """Any billable variant with no datapoints → MEDIUM confidence."""
        sagemaker, cloudwatch = _make_full_sagemaker(invocations_response=_no_invocations())
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].confidence.value == "medium"

    def test_gpu_endpoint_emits_high_risk(self):
        """Accelerator-backed endpoint → HIGH risk."""
        sagemaker, cloudwatch = _make_full_sagemaker(instance_type="ml.p3.2xlarge")
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].risk.value == "high"

    def test_cpu_endpoint_emits_medium_risk(self):
        """Non-accelerator endpoint → MEDIUM risk."""
        sagemaker, cloudwatch = _make_full_sagemaker(instance_type="ml.m5.xlarge")
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].risk.value == "medium"

    def test_multi_variant_all_idle_emits(self):
        """Multiple billable variants all with zero invocations → emit."""
        sagemaker, cloudwatch = _make_full_sagemaker(variant_count=3)
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].details["billable_variant_count"] == 3


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_endpoint_arn_absent_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        now = datetime.now(timezone.utc)
        endpoint = {
            "EndpointName": "no-arn",
            # EndpointArn absent
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
            "EndpointStatus": "InService",
        }
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [endpoint]}]

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_endpoint_name_absent_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        now = datetime.now(timezone.utc)
        endpoint = {
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/x",
            # EndpointName absent
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=30),
            "EndpointStatus": "InService",
        }
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [endpoint]}]

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_creation_time_absent_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        now = datetime.now(timezone.utc)
        endpoint = {
            "EndpointName": "ep",
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/ep",
            # CreationTime absent
            "LastModifiedTime": now - timedelta(days=30),
            "EndpointStatus": "InService",
        }
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [endpoint]}]

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_creation_time_naive_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        now = datetime.now(timezone.utc)
        endpoint = {
            "EndpointName": "ep",
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/ep",
            "CreationTime": datetime.now(),  # naive
            "LastModifiedTime": now - timedelta(days=30),
            "EndpointStatus": "InService",
        }
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [endpoint]}]

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_last_modified_time_absent_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        now = datetime.now(timezone.utc)
        endpoint = {
            "EndpointName": "ep",
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/ep",
            "CreationTime": now - timedelta(days=30),
            # LastModifiedTime absent
            "EndpointStatus": "InService",
        }
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [endpoint]}]

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_last_modified_time_naive_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        now = datetime.now(timezone.utc)
        endpoint = {
            "EndpointName": "ep",
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/ep",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": datetime.now(),  # naive
            "EndpointStatus": "InService",
        }
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [endpoint]}]

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_future_reference_time_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        now = datetime.now(timezone.utc)
        endpoint = {
            "EndpointName": "ep",
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/ep",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now + timedelta(days=1),  # future
            "EndpointStatus": "InService",
        }
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [endpoint]}]

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_too_young_skips(self):
        """Endpoint age < threshold → skip."""
        sagemaker, cloudwatch = _make_full_sagemaker(age_days=5)
        findings = find_idle_sagemaker_endpoints(
            _make_session(sagemaker, cloudwatch), "us-east-1", idle_days_threshold=14
        )
        assert findings == []

    def test_describe_endpoint_failure_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        sagemaker.describe_endpoint.side_effect = _client_error("ValidationException")

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_describe_endpoint_botocore_error_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        sagemaker.describe_endpoint.side_effect = _botocore_error()

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_describe_endpoint_status_not_inservice_skips(self):
        """DescribeEndpoint returns a different status → skip."""
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        desc = _make_describe_response()
        desc["EndpointStatus"] = "Updating"
        sagemaker.describe_endpoint.return_value = desc

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_describe_endpoint_config_failure_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        sagemaker.describe_endpoint.return_value = _make_describe_response()
        sagemaker.describe_endpoint_config.side_effect = _client_error("ValidationException")

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_async_inference_config_present_skips(self):
        """Endpoint with AsyncInferenceConfig → out of scope → skip."""
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        sagemaker.describe_endpoint.return_value = _make_describe_response()
        config = _make_describe_config_response()
        config["AsyncInferenceConfig"] = {"OutputConfig": {"S3OutputPath": "s3://bucket/output"}}
        sagemaker.describe_endpoint_config.return_value = config

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_no_production_variants_skips(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        sagemaker.describe_endpoint.return_value = {
            "ProductionVariants": [],
            "EndpointConfigName": "cfg",
            "EndpointStatus": "InService",
        }
        sagemaker.describe_endpoint_config.return_value = {"ProductionVariants": []}

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_no_billable_variants_skips(self):
        """All variants have CurrentInstanceCount=0 and no serverless provisioned concurrency."""
        sagemaker, cloudwatch = _make_full_sagemaker(current_instance_count=0)
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_variant_with_positive_invocations_skips(self):
        sagemaker, cloudwatch = _make_full_sagemaker(invocations_response=_has_invocations())
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_cloudwatch_failure_skips(self):
        """CloudWatch API failure for any variant → SKIP ITEM (not a low-confidence finding)."""
        sagemaker, cloudwatch = _make_full_sagemaker()
        cloudwatch.get_metric_statistics.side_effect = _client_error("InternalError")

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_cloudwatch_botocore_error_skips(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        cloudwatch.get_metric_statistics.side_effect = _botocore_error()

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_serverless_without_provisioned_concurrency_skips(self):
        """Serverless variant with no ProvisionedConcurrency in runtime state → not billable → skip."""
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        sagemaker.describe_endpoint.return_value = {
            "ProductionVariants": [
                {
                    "VariantName": "AllTraffic",
                    # No CurrentInstanceCount, no CurrentServerlessConfig
                }
            ],
            "EndpointConfigName": "sl-cfg",
            "EndpointStatus": "InService",
        }
        sagemaker.describe_endpoint_config.return_value = {
            "ProductionVariants": [
                {
                    "VariantName": "AllTraffic",
                    "ServerlessConfig": {"MaxConcurrency": 10},  # no ProvisionedConcurrency
                }
            ]
        }

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []

    def test_any_variant_traffic_short_circuits(self):
        """If the first variant shows traffic, subsequent variants are not queried."""
        sagemaker, cloudwatch = _make_full_sagemaker(variant_count=3)
        # First variant returns traffic
        cloudwatch.get_metric_statistics.side_effect = [
            _has_invocations(),
            _zero_invocations(),
            _zero_invocations(),
        ]

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []
        # Only one CloudWatch call should have been made (short-circuit)
        assert cloudwatch.get_metric_statistics.call_count == 1

    def test_no_findings_for_empty_endpoint_list(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": []}]

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert findings == []


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_list_endpoints_client_error_fails_rule(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.side_effect = _client_error("InternalError")

        with pytest.raises(ClientError):
            find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

    def test_list_endpoints_botocore_error_fails_rule(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.side_effect = _botocore_error()

        with pytest.raises(BotoCoreError):
            find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

    def test_list_endpoints_access_denied_raises_permission_error(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.side_effect = _client_error("AccessDenied")

        with pytest.raises(PermissionError) as exc_info:
            find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert "sagemaker:ListEndpoints" in str(exc_info.value)

    def test_list_endpoints_unauthorized_raises_permission_error(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.side_effect = _client_error("UnauthorizedOperation")

        with pytest.raises(PermissionError):
            find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

    def test_describe_endpoint_access_denied_fails_rule(self):
        """Permission failure on DescribeEndpoint → FAIL RULE (not silent skip)."""
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        sagemaker.describe_endpoint.side_effect = _client_error("AccessDenied")

        with pytest.raises(PermissionError) as exc_info:
            find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert "sagemaker:DescribeEndpoint" in str(exc_info.value)

    def test_describe_endpoint_config_access_denied_fails_rule(self):
        """Permission failure on DescribeEndpointConfig → FAIL RULE (not silent skip)."""
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        sagemaker.describe_endpoint.return_value = _make_describe_response()
        sagemaker.describe_endpoint_config.side_effect = _client_error("AccessDenied")

        with pytest.raises(PermissionError) as exc_info:
            find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert "sagemaker:DescribeEndpointConfig" in str(exc_info.value)

    def test_cloudwatch_access_denied_fails_rule(self):
        """Permission failure on GetMetricStatistics → FAIL RULE (not silent skip)."""
        sagemaker, cloudwatch = _make_full_sagemaker()
        cloudwatch.get_metric_statistics.side_effect = _client_error("AccessDenied")

        with pytest.raises(PermissionError) as exc_info:
            find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert "cloudwatch:GetMetricStatistics" in str(exc_info.value)


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def _now(self):
        return datetime.now(timezone.utc)

    def test_reference_time_is_max_of_creation_and_last_modified(self):
        now = self._now()
        # LastModifiedTime is later — reference_time should be LastModifiedTime
        item = {
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/ep",
            "EndpointName": "ep",
            "EndpointStatus": "InService",
            "CreationTime": now - timedelta(days=30),
            "LastModifiedTime": now - timedelta(days=10),
        }
        n = _normalize_endpoint_summary(item, now)
        assert n is not None
        assert n["reference_time_utc"] == (now - timedelta(days=10)).astimezone(timezone.utc)
        assert n["age_days"] == 10

    def test_reference_time_creation_when_creation_is_later(self):
        now = self._now()
        # CreationTime later than LastModifiedTime (edge case)
        item = {
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123:endpoint/ep",
            "EndpointName": "ep",
            "EndpointStatus": "InService",
            "CreationTime": now - timedelta(days=5),
            "LastModifiedTime": now - timedelta(days=20),
        }
        n = _normalize_endpoint_summary(item, now)
        assert n is not None
        assert n["age_days"] == 5

    def test_resource_id_equals_endpoint_arn(self):
        now = self._now()
        arn = "arn:aws:sagemaker:us-east-1:123456789012:endpoint/myep"
        item = {
            "EndpointArn": arn,
            "EndpointName": "myep",
            "EndpointStatus": "InService",
            "CreationTime": now - timedelta(days=20),
            "LastModifiedTime": now - timedelta(days=20),
        }
        n = _normalize_endpoint_summary(item, now)
        assert n["resource_id"] == arn
        assert n["endpoint_arn"] == arn

    def test_variant_without_name_returns_none(self):
        n = _normalize_variant({"CurrentInstanceCount": 1}, {})
        assert n is None

    def test_variant_empty_name_returns_none(self):
        n = _normalize_variant({"VariantName": "", "CurrentInstanceCount": 1}, {})
        assert n is None

    def test_variant_billable_when_current_instance_count_positive(self):
        n = _normalize_variant(
            {"VariantName": "v1", "CurrentInstanceCount": 2},
            {},
        )
        assert n is not None
        assert n["is_billable"] is True
        assert n["billable_compute_mode"] == "instance"
        assert n["current_instance_count"] == 2

    def test_variant_not_billable_when_current_instance_count_zero(self):
        n = _normalize_variant(
            {"VariantName": "v1", "CurrentInstanceCount": 0},
            {},
        )
        assert n is not None
        assert n["is_billable"] is False
        assert n["billable_compute_mode"] == "none"

    def test_variant_billable_when_current_serverless_provisioned_concurrency_positive(self):
        n = _normalize_variant(
            {
                "VariantName": "v1",
                "CurrentServerlessConfig": {"ProvisionedConcurrency": 5},
            },
            {},
        )
        assert n is not None
        assert n["is_billable"] is True
        assert n["billable_compute_mode"] == "serverless_provisioned"
        assert n["current_serverless_provisioned_concurrency"] == 5

    def test_variant_not_billable_when_config_only_provisioned_concurrency(self):
        """Configured ProvisionedConcurrency is enrichment only — not the billing driver."""
        n = _normalize_variant(
            {"VariantName": "v1"},  # no CurrentServerlessConfig
            {"v1": {"ServerlessConfig": {"ProvisionedConcurrency": 3}}},
        )
        assert n is not None
        assert n["is_billable"] is False
        assert n["configured_serverless_provisioned_concurrency"] == 3  # captured as context

    def test_instance_type_comes_from_config_enrichment(self):
        n = _normalize_variant(
            {"VariantName": "v1", "CurrentInstanceCount": 1},
            {"v1": {"InstanceType": "ml.m5.xlarge"}},
        )
        assert n["instance_type"] == "ml.m5.xlarge"

    def test_instance_type_null_when_not_in_config(self):
        n = _normalize_variant(
            {"VariantName": "v1", "CurrentInstanceCount": 1},
            {},
        )
        assert n["instance_type"] is None


# ---------------------------------------------------------------------------
# TestCloudWatchContract
# ---------------------------------------------------------------------------


class TestCloudWatchContract:
    def test_cloudwatch_queried_per_variant_with_correct_dimensions(self):
        """CloudWatch must use EndpointName + VariantName dimensions per variant."""
        sagemaker, cloudwatch = _make_full_sagemaker(variant_count=2)
        find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        calls = cloudwatch.get_metric_statistics.call_args_list
        assert len(calls) == 2  # one call per variant
        for c in calls:
            call_kwargs = c.kwargs
            assert call_kwargs.get("Namespace") == "AWS/SageMaker"
            assert call_kwargs.get("MetricName") == "Invocations"
            dimensions = call_kwargs.get("Dimensions", [])
            dim_names = {d["Name"] for d in dimensions}
            assert "EndpointName" in dim_names
            assert "VariantName" in dim_names

    def test_no_endpoint_name_only_fallback(self):
        """EndpointName-only queries must never be used."""
        sagemaker, cloudwatch = _make_full_sagemaker()
        find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        for c in cloudwatch.get_metric_statistics.call_args_list:
            dimensions = c.kwargs.get("Dimensions", [])
            dim_names = {d["Name"] for d in dimensions}
            assert "VariantName" in dim_names, "EndpointName-only fallback must not be used"

    def test_period_is_sub_window_not_full_bucket(self):
        """Period must be a sub-window period, not idle_days_threshold × 86400."""
        sagemaker, cloudwatch = _make_full_sagemaker()
        find_idle_sagemaker_endpoints(
            _make_session(sagemaker, cloudwatch), "us-east-1", idle_days_threshold=14
        )

        period = cloudwatch.get_metric_statistics.call_args.kwargs.get("Period")
        assert period != 14 * 86400, "Period must not be the full observation window"
        assert period % 60 == 0, "Period must be a multiple of 60 seconds"

    def test_period_for_14_days_is_840(self):
        """14-day window: smallest legal period is idle_days * 60 = 840 s (exactly 1440 datapoints)."""
        sagemaker, cloudwatch = _make_full_sagemaker()
        find_idle_sagemaker_endpoints(
            _make_session(sagemaker, cloudwatch), "us-east-1", idle_days_threshold=14
        )

        period = cloudwatch.get_metric_statistics.call_args.kwargs.get("Period")
        assert period == 14 * 60  # 840 s → exactly 1440 datapoints

    def test_period_for_61_days_is_3900(self):
        """61-day window (>15 ≤63, 300 s tier): ceil(3660/300)*300 = 13*300 = 3900 s."""
        sagemaker, cloudwatch = _make_full_sagemaker(age_days=65)
        find_idle_sagemaker_endpoints(
            _make_session(sagemaker, cloudwatch), "us-east-1", idle_days_threshold=61
        )

        period = cloudwatch.get_metric_statistics.call_args.kwargs.get("Period")
        assert period == 3900

    def test_period_per_tier(self):
        """Period is smallest legal multiple for the lookback tier, capped at 1440 datapoints."""
        # (idle_days, expected_period)
        # ≤15 days → 60 s granularity: period = ceil(idle_days*86400/1440 / 60)*60 = idle_days*60
        # ≤63 days → 300 s granularity: ceil(min_period/300)*300
        # >63 days → 3600 s granularity: ceil(min_period/3600)*3600
        cases = [
            (1, 60),  # 1 *60 = 60
            (7, 420),  # 7 *60 = 420
            (14, 840),  # 14*60 = 840
            (15, 900),  # 15*60 = 900
            (16, 1200),  # ceil(960/300)*300 = 4*300
            (30, 1800),  # ceil(1800/300)*300 = 6*300
            (60, 3600),  # ceil(3600/300)*300 = 12*300
            (61, 3900),  # ceil(3660/300)*300 = 13*300
            (64, 7200),  # ceil(3840/3600)*3600 = 2*3600
            (90, 7200),  # ceil(5400/3600)*3600 = 2*3600
        ]
        for idle_days, expected in cases:
            sagemaker, cloudwatch = _make_full_sagemaker(age_days=idle_days + 10)
            find_idle_sagemaker_endpoints(
                _make_session(sagemaker, cloudwatch), "us-east-1", idle_days_threshold=idle_days
            )
            period = cloudwatch.get_metric_statistics.call_args.kwargs.get("Period")
            assert (
                period == expected
            ), f"idle_days={idle_days}: expected period={expected}, got {period}"


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_high_confidence_all_variants_have_datapoints(self):
        """All billable variants returned datapoints with Sum=0 → HIGH."""
        sagemaker, cloudwatch = _make_full_sagemaker(invocations_response=_zero_invocations())
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].confidence.value == "high"

    def test_medium_confidence_when_variant_has_no_datapoints(self):
        """Any variant with no datapoints → MEDIUM confidence."""
        sagemaker, cloudwatch = _make_full_sagemaker(invocations_response=_no_invocations())
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].confidence.value == "medium"

    def test_no_low_confidence_emitted(self):
        """LOW confidence must never be emitted. CloudWatch failure → SKIP, not LOW."""
        sagemaker, cloudwatch = _make_full_sagemaker()
        cloudwatch.get_metric_statistics.side_effect = _client_error("InternalError")

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        # Must not emit a LOW finding — it must skip entirely
        assert findings == []
        for f in findings:
            assert f.confidence.value != "low"

    def test_mixed_datapoint_presence_gives_medium(self):
        """2 variants: first has datapoints (Sum=0), second has no datapoints → MEDIUM."""
        sagemaker, cloudwatch = _make_full_sagemaker(variant_count=2)
        cloudwatch.get_metric_statistics.side_effect = [
            _zero_invocations(),
            _no_invocations(),
        ]
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].confidence.value == "medium"


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    @pytest.mark.parametrize(
        "instance_type",
        [
            "ml.g4dn.xlarge",
            "ml.g5.2xlarge",
            "ml.p3.2xlarge",
            "ml.p4d.24xlarge",
            "ml.p5.48xlarge",
            "ml.trn1.2xlarge",
            "ml.inf1.xlarge",
            "ml.inf2.xlarge",
        ],
    )
    def test_accelerator_instance_is_high_risk(self, instance_type):
        sagemaker, cloudwatch = _make_full_sagemaker(instance_type=instance_type)
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].risk.value == "high"

    @pytest.mark.parametrize("instance_type", ["ml.m5.xlarge", "ml.c5.xlarge", "ml.t3.medium"])
    def test_cpu_instance_is_medium_risk(self, instance_type):
        sagemaker, cloudwatch = _make_full_sagemaker(instance_type=instance_type)
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].risk.value == "medium"

    def test_no_critical_risk_emitted(self):
        """Spec allows only HIGH or MEDIUM risk — CRITICAL must never be emitted."""
        sagemaker, cloudwatch = _make_full_sagemaker(instance_type="ml.p5.48xlarge", age_days=90)
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        for f in findings:
            assert f.risk.value != "critical"


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_monthly_cost_is_none_for_cpu(self):
        sagemaker, cloudwatch = _make_full_sagemaker(instance_type="ml.m5.xlarge")
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd is None

    def test_estimated_monthly_cost_is_none_for_gpu(self):
        sagemaker, cloudwatch = _make_full_sagemaker(instance_type="ml.p3.2xlarge")
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd is None

    def test_estimated_monthly_cost_is_none_for_serverless(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": [_make_endpoint(age_days=30)]}]
        sagemaker.describe_endpoint.return_value = {
            "ProductionVariants": [
                {
                    "VariantName": "AllTraffic",
                    "CurrentServerlessConfig": {"ProvisionedConcurrency": 5},
                }
            ],
            "EndpointConfigName": "sl-cfg",
            "EndpointStatus": "InService",
        }
        sagemaker.describe_endpoint_config.return_value = {
            "ProductionVariants": [
                {"VariantName": "AllTraffic", "ServerlessConfig": {"ProvisionedConcurrency": 5}}
            ]
        }
        cloudwatch.get_metric_statistics.return_value = _zero_invocations()

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestDetailsContract
# ---------------------------------------------------------------------------


class TestDetailsContract:
    def test_all_required_fields_present(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        d = findings[0].details
        required_keys = [
            "evaluation_path",
            "endpoint_arn",
            "endpoint_name",
            "endpoint_status",
            "endpoint_config_name",
            "creation_time",
            "last_modified_time",
            "reference_time",
            "evaluation_window_start",
            "evaluation_window_end",
            "age_days",
            "idle_days_threshold",
            "variant_names_evaluated",
            "billable_variant_count",
            "billable_compute_mode",
            "total_current_instance_count",
            "total_provisioned_concurrency",
            "invocation_metric_namespace",
            "invocation_metric_name",
            "invocation_dimensions",
            "traffic_detected",
            "no_datapoint_variant_count",
            "total_invocations_sum",
        ]
        for key in required_keys:
            assert key in d, f"Missing required details field: {key}"

    def test_evaluation_path(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].details["evaluation_path"] == "idle-sagemaker-endpoint-review-candidate"

    def test_traffic_detected_is_false(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].details["traffic_detected"] is False

    def test_invocation_metric_namespace(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].details["invocation_metric_namespace"] == "AWS/SageMaker"

    def test_invocation_metric_name(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].details["invocation_metric_name"] == "Invocations"

    def test_invocation_dimensions(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].details["invocation_dimensions"] == "EndpointName + VariantName"

    def test_endpoint_status_in_details(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].details["endpoint_status"] == "InService"

    def test_idle_days_threshold_in_details(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(
            _make_session(sagemaker, cloudwatch), "us-east-1", idle_days_threshold=21
        )

        assert findings[0].details["idle_days_threshold"] == 21

    def test_billable_compute_mode_instance(self):
        sagemaker, cloudwatch = _make_full_sagemaker(
            instance_type="ml.m5.xlarge", current_instance_count=2
        )
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].details["billable_compute_mode"] == "instance"

    def test_no_datapoint_variant_count_tracked(self):
        sagemaker, cloudwatch = _make_full_sagemaker(
            variant_count=2, invocations_response=_no_invocations()
        )
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert len(findings) == 1
        assert findings[0].details["no_datapoint_variant_count"] == 2

    def test_total_invocations_sum_is_zero(self):
        sagemaker, cloudwatch = _make_full_sagemaker(invocations_response=_zero_invocations())
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].details["total_invocations_sum"] == 0.0


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_signals_used_mention_inservice(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        signals = " ".join(findings[0].evidence.signals_used)
        assert "InService" in signals

    def test_signals_used_mention_async_exclusion(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        signals = " ".join(findings[0].evidence.signals_used)
        assert "AsyncInferenceConfig" in signals or "async" in signals.lower()

    def test_signals_used_mention_billable_compute(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        signals = " ".join(findings[0].evidence.signals_used)
        assert "billable" in signals.lower()

    def test_signals_used_mention_no_traffic(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        signals = " ".join(findings[0].evidence.signals_used)
        assert "InvokeEndpoint" in signals or "traffic" in signals.lower()

    def test_no_datapoint_signal_when_applicable(self):
        sagemaker, cloudwatch = _make_full_sagemaker(invocations_response=_no_invocations())
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        signals = " ".join(findings[0].evidence.signals_used)
        assert "no datapoints" in signals.lower() or "no cloudwatch datapoints" in signals.lower()

    def test_signals_not_checked_include_async_blind_spot(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        not_checked = " ".join(findings[0].evidence.signals_not_checked)
        assert "async" in not_checked.lower() or "InvokeEndpointAsync" in not_checked

    def test_title_is_canonical(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        assert findings[0].title == "Idle SageMaker endpoint review candidate"

    def test_reason_contains_required_wording(self):
        sagemaker, cloudwatch = _make_full_sagemaker()
        findings = find_idle_sagemaker_endpoints(
            _make_session(sagemaker, cloudwatch), "us-east-1", idle_days_threshold=14
        )

        reason = findings[0].reason
        assert "InService" in reason
        assert "InvokeEndpoint" in reason
        assert "14" in reason
        assert "billable" in reason.lower()


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multiple_pages_processed(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [
            {"Endpoints": [_make_endpoint("ep-1", 30), _make_endpoint("ep-2", 30)]},
            {"Endpoints": [_make_endpoint("ep-3", 30)]},
        ]
        sagemaker.describe_endpoint.return_value = _make_describe_response()
        sagemaker.describe_endpoint_config.return_value = _make_describe_config_response()
        cloudwatch.get_metric_statistics.return_value = _zero_invocations()

        findings = find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")
        assert len(findings) == 3

    def test_list_endpoints_paginated_with_status_equals(self):
        sagemaker = MagicMock()
        cloudwatch = MagicMock()
        paginator = sagemaker.get_paginator.return_value
        paginator.paginate.return_value = [{"Endpoints": []}]

        find_idle_sagemaker_endpoints(_make_session(sagemaker, cloudwatch), "us-east-1")

        paginator.paginate.assert_called_once_with(StatusEquals="InService")


# ---------------------------------------------------------------------------
# TestRuleMetadata
# ---------------------------------------------------------------------------


class TestRuleMetadata:
    def test_rule_metadata_present(self):
        from cleancloud.providers.aws.rules.ai.sagemaker_endpoint_idle import RULE_METADATA

        assert RULE_METADATA["id"] == "aws.sagemaker.endpoint.idle"
        assert RULE_METADATA["category"] == "ai"
        assert RULE_METADATA["service"] == "sagemaker"
