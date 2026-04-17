from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cleancloud.providers.aws.rules.bedrock_provisioned_idle import (
    _extract_model_id,
    _extract_model_id_for_cw,
    _parse_model_family,
    find_idle_bedrock_provisioned_throughputs,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"
_SONNET_ARN = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0"
_HAIKU_ARN = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
_OPUS_ARN = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-opus-20240229-v1:0"
_LLAMA_ARN = "arn:aws:bedrock:us-east-1::foundation-model/meta.llama3-70b-instruct-v1:0"
_TITAN_ARN = "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1"


def _make_provisioned(
    name="my-throughput",
    model_arn=_SONNET_ARN,
    desired_units=2,
    commitment="NoCommitment",
    age_days=30,
):
    provisioned_arn = f"arn:aws:bedrock:{_REGION}:123456789012:provisioned-model/{name}"
    now = datetime.now(timezone.utc)
    create_time = now - timedelta(days=age_days)
    return {
        "provisionedModelName": name,
        "provisionedModelArn": provisioned_arn,
        "modelArn": model_arn,
        "foundationModelArn": model_arn,
        "desiredModelUnits": desired_units,
        "currentModelUnits": desired_units,
        "commitmentDuration": commitment,
        "creationTime": create_time,
        "lastModifiedTime": create_time,
        "status": "InService",
    }


def _make_session(provisioned_items=None, cw_datapoints=None):
    """Return (session, bedrock_client, cloudwatch_client) mocks."""
    session = MagicMock()

    bedrock = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"provisionedModelSummaries": provisioned_items or []}]
    bedrock.get_paginator.return_value = paginator

    cloudwatch = MagicMock()
    cloudwatch.get_metric_statistics.return_value = {
        "Datapoints": cw_datapoints if cw_datapoints is not None else []
    }

    def _client(service, **kwargs):
        if service == "bedrock":
            return bedrock
        if service == "cloudwatch":
            return cloudwatch
        return MagicMock()

    session.client.side_effect = _client
    return session, bedrock, cloudwatch


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


def test_idle_provisioned_throughput_detected():
    """Idle InService throughput with zero invocations is flagged."""
    item = _make_provisioned(age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "aws.bedrock.provisioned_throughput.idle"
    assert f.resource_id == "my-throughput"
    assert f.provider == "aws"
    assert f.region == _REGION
    assert f.confidence.value == "high"


def test_active_throughput_skipped():
    """Throughput with actual invocations is not flagged."""
    item = _make_provisioned(age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[{"Sum": 5.0, "Timestamp": "x"}])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings == []


def test_no_provisioned_throughputs_returns_empty():
    """Account with no provisioned throughput returns no findings."""
    session, _, _ = _make_session([], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings == []


# ---------------------------------------------------------------------------
# Age guard
# ---------------------------------------------------------------------------


def test_young_throughput_skipped():
    """Reservations younger than max(idle_days//2, 3) days are skipped."""
    # idle_days=7 → guard=max(3,3)=3; age=2 < 3 → blocked by age guard
    item = _make_provisioned(age_days=2)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings == []


def test_below_confidence_threshold_skipped():
    """age passes guard but effective_window < ceil(75%) → skipped by confidence logic."""
    # idle_days=7, guard=3: age=5 passes guard (5>=3), effective_window=5 < ceil(5.25)=6 → skip
    item = _make_provisioned(age_days=5)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings == []


def test_medium_confidence_reachable_at_default_idle_days():
    """With idle_days=7 (default), age=6 should produce MEDIUM (regression guard for age-guard fix)."""
    # guard=max(3,3)=3; age=6>=3 passes; effective_window=6; ceil(7*0.75)=6 → MEDIUM
    item = _make_provisioned(age_days=6)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------


def test_high_confidence_full_window():
    """effective_window >= idle_days → HIGH confidence."""
    item = _make_provisioned(age_days=14)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION, idle_days=7)

    assert len(findings) == 1
    assert findings[0].confidence.value == "high"


def test_medium_confidence_borderline_age():
    """effective_window at ceil(75% of idle_days) → MEDIUM confidence."""
    # idle_days=14, ceil(14*0.75)=ceil(10.5)=11 → age=12 → effective_window=12 → MEDIUM
    # (age guard = max(7,7)=7, 12 >= 7 ✓; 12 >= 11 but < 14 → MEDIUM)
    item = _make_provisioned(age_days=12)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION, idle_days=14)

    assert len(findings) == 1
    assert findings[0].confidence.value == "medium"


def test_below_75pct_age_skipped():
    """effective_window < ceil(75%) of idle_days → skipped."""
    # idle_days=14, ceil(14*0.75)=11 → age=10 → effective_window=10 < 11 → skip
    # (age guard = 7, 10 >= 7 ✓)
    item = _make_provisioned(age_days=10)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION, idle_days=14)

    assert findings == []


def test_effective_window_capped_to_age():
    """effective_window = min(idle_days, age_days) is reflected in evidence."""
    # idle_days=14, age=10 → effective_window=10; ceil(14*0.75)=11 → 10<11 → MEDIUM
    # Adjust so age qualifies: idle_days=10, age=8, ceil(10*0.75)=ceil(7.5)=8 → MEDIUM
    item = _make_provisioned(age_days=8)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION, idle_days=10)

    assert len(findings) == 1
    assert findings[0].evidence.time_window == "8 days"


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------


def test_critical_risk_when_idle_ratio_gte_2():
    """idle_ratio >= 2.0 → CRITICAL risk."""
    item = _make_provisioned(age_days=30)  # idle_days=7, ratio=30/7≈4.3 → CRITICAL
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings[0].risk.value == "critical"


def test_high_risk_when_idle_ratio_lt_2():
    """idle_ratio < 2.0 → HIGH risk."""
    item = _make_provisioned(age_days=10)  # idle_days=7, ratio=10/7≈1.43 → HIGH
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings[0].risk.value == "high"


# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------


def test_cost_scales_with_model_units():
    """Estimated cost = cost_per_MU × desired_units."""
    item = _make_provisioned(model_arn=_SONNET_ARN, desired_units=3, age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    # Sonnet: $2,600/MU × 3 MU = $7,800/month
    assert findings[0].estimated_monthly_cost_usd == pytest.approx(7_800.0)


def test_opus_cost_per_mu():
    """Claude 3 Opus uses the correct per-MU cost."""
    item = _make_provisioned(model_arn=_OPUS_ARN, desired_units=1, age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings[0].estimated_monthly_cost_usd == pytest.approx(7_300.0)


def test_haiku_cost_per_mu():
    """Claude 3 Haiku uses the correct per-MU cost."""
    item = _make_provisioned(model_arn=_HAIKU_ARN, desired_units=2, age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings[0].estimated_monthly_cost_usd == pytest.approx(1_200.0)


def test_llama_cost_per_mu():
    """Meta Llama 3 uses the correct per-MU cost."""
    item = _make_provisioned(model_arn=_LLAMA_ARN, desired_units=2, age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings[0].estimated_monthly_cost_usd == pytest.approx(2_000.0)


def test_zero_model_units_skipped():
    """desired_units=0 (shouldn't happen for InService) → skipped to avoid cost-less HIGH finding."""
    item = _make_provisioned(desired_units=0, age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings == []


# ---------------------------------------------------------------------------
# Model family parsing
# ---------------------------------------------------------------------------


def test_model_family_sonnet():
    assert _parse_model_family(_SONNET_ARN) == "anthropic.claude-3-sonnet"


def test_model_family_sonnet35():
    arn = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0"
    assert _parse_model_family(arn) == "anthropic.claude-3-5-sonnet"


def test_model_family_opus():
    assert _parse_model_family(_OPUS_ARN) == "anthropic.claude-3-opus"


def test_model_family_llama():
    assert _parse_model_family(_LLAMA_ARN) == "meta.llama3"


def test_model_family_unknown_returns_model_id():
    arn = "arn:aws:bedrock:us-east-1::foundation-model/acme.newmodel-v1"
    result = _parse_model_family(arn)
    assert result == "acme.newmodel-v1"


def test_model_family_empty_arn():
    assert _parse_model_family("") is None


def test_extract_model_id_normal():
    assert _extract_model_id(_SONNET_ARN) == "anthropic.claude-3-sonnet-20240229-v1"


def test_extract_model_id_empty():
    assert _extract_model_id("") is None


def test_extract_model_id_no_slash():
    """Plain model ID string (no ARN prefix) is returned as-is."""
    assert _extract_model_id("anthropic.claude-3-haiku-20240307-v1") == (
        "anthropic.claude-3-haiku-20240307-v1"
    )


def test_extract_model_id_for_cw_preserves_version_suffix():
    """_extract_model_id_for_cw preserves the :0 version suffix for CloudWatch dimensions."""
    assert _extract_model_id_for_cw(_SONNET_ARN) == "anthropic.claude-3-sonnet-20240229-v1:0"


def test_extract_model_id_for_cw_strips_arn_prefix():
    """_extract_model_id_for_cw strips the ARN prefix but keeps version."""
    assert _extract_model_id_for_cw(_HAIKU_ARN) == "anthropic.claude-3-haiku-20240307-v1:0"


def test_extract_model_id_for_cw_empty():
    assert _extract_model_id_for_cw("") is None


def test_extract_model_id_for_cw_no_version_suffix():
    """ARN without :N version suffix (e.g. Titan) is extracted cleanly."""
    assert _extract_model_id_for_cw(_TITAN_ARN) == "amazon.titan-text-express-v1"


# ---------------------------------------------------------------------------
# Commitment term in finding details
# ---------------------------------------------------------------------------


def test_commitment_term_in_details():
    """Commitment duration is recorded in finding details."""
    item = _make_provisioned(commitment="OneMonth", age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings[0].details["commitment_duration"] == "OneMonth"


def test_commitment_in_signals():
    """Commitment term appears in the evidence signals."""
    item = _make_provisioned(commitment="SixMonths", age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert any("SixMonths" in s for s in findings[0].evidence.signals_used)


# ---------------------------------------------------------------------------
# CloudWatch behaviour
# ---------------------------------------------------------------------------


def test_cloudwatch_failure_assumes_active():
    """Transient CloudWatch error (throttling) → conservative skip (assume active)."""
    item = _make_provisioned(age_days=30)
    session, _, cloudwatch = _make_session([item])
    cloudwatch.get_metric_statistics.side_effect = ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
        "GetMetricStatistics",
    )

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings == []


def test_cloudwatch_auth_error_raises_permission_error():
    """AccessDeniedException from CloudWatch → PermissionError (not silent skip)."""
    item = _make_provisioned(age_days=30)
    session, _, cloudwatch = _make_session([item])
    cloudwatch.get_metric_statistics.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "User is not authorized",
            }
        },
        "GetMetricStatistics",
    )

    with pytest.raises(PermissionError, match="cloudwatch:GetMetricStatistics"):
        find_idle_bedrock_provisioned_throughputs(session, _REGION)


def test_cloudwatch_primary_dimension_uses_provisioned_arn():
    """First CloudWatch query uses the provisioned model ARN as the ModelId dimension."""
    item = _make_provisioned(age_days=30)
    session, _, cloudwatch = _make_session([item], cw_datapoints=[])

    find_idle_bedrock_provisioned_throughputs(session, _REGION)

    # First call must target the provisioned model ARN
    first_call_kwargs = cloudwatch.get_metric_statistics.call_args_list[0][1]
    dims = first_call_kwargs["Dimensions"]
    expected_arn = item["provisionedModelArn"]
    assert dims == [{"Name": "ModelId", "Value": expected_arn}]


def test_cloudwatch_fallback_to_base_model_id_when_active():
    """If provisioned ARN has no data but base model ID shows traffic, treated as active.

    The fallback dimension value must preserve the version suffix (:0) so it matches
    what AWS actually emits in CloudWatch (e.g. anthropic.claude-3-sonnet-20240229-v1:0,
    not anthropic.claude-3-sonnet-20240229-v1).
    """
    item = _make_provisioned(age_days=30, model_arn=_SONNET_ARN)
    session, _, cloudwatch = _make_session([item])

    # Versioned model ID — what AWS emits in CloudWatch (preserves :0 suffix)
    base_model_id_cw = "anthropic.claude-3-sonnet-20240229-v1:0"

    def _cw(**kwargs):
        dims = kwargs.get("Dimensions", [])
        val = dims[0]["Value"] if dims else ""
        if val == item["provisionedModelArn"]:
            return {"Datapoints": []}  # no data under provisioned ARN
        if val == base_model_id_cw:
            return {"Datapoints": [{"Sum": 2.0}]}  # traffic under versioned model ID
        return {"Datapoints": []}

    cloudwatch.get_metric_statistics.side_effect = _cw

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert findings == []  # conservative: versioned-model-ID traffic → active


def test_cloudwatch_namespace_is_bedrock():
    """CloudWatch query targets the AWS/Bedrock namespace."""
    item = _make_provisioned(age_days=30)
    session, _, cloudwatch = _make_session([item], cw_datapoints=[])

    find_idle_bedrock_provisioned_throughputs(session, _REGION)

    call_kwargs = cloudwatch.get_metric_statistics.call_args[1]
    assert call_kwargs["Namespace"] == "AWS/Bedrock"
    assert call_kwargs["MetricName"] == "Invocations"


# ---------------------------------------------------------------------------
# Permission errors
# ---------------------------------------------------------------------------


def test_bedrock_auth_error_raises_permission_error():
    """AccessDeniedException from ListProvisionedModelThroughputs raises PermissionError."""
    session = MagicMock()
    bedrock = MagicMock()
    paginator = MagicMock()
    paginator.paginate.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "User is not authorized",
            }
        },
        "ListProvisionedModelThroughputs",
    )
    bedrock.get_paginator.return_value = paginator
    cloudwatch = MagicMock()

    def _client(service, **kwargs):
        return bedrock if service == "bedrock" else cloudwatch

    session.client.side_effect = _client

    with pytest.raises(PermissionError, match="bedrock:ListProvisionedModelThroughputs"):
        find_idle_bedrock_provisioned_throughputs(session, _REGION)


# ---------------------------------------------------------------------------
# idle_days clamping and edge cases
# ---------------------------------------------------------------------------


def test_idle_days_minimum_guard():
    """Age guard floor is 3 regardless of idle_days; age below floor is skipped."""
    # idle_days=4 → guard = max(ceil(4*0.5), 3) = max(2, 3) = 3; age=2 < 3 → skipped
    item = _make_provisioned(age_days=2)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION, idle_days=4)

    assert findings == []


def test_idle_days_clamped_to_minimum():
    """idle_days below 3 is clamped to 3 so effective_window < 3 guard never kills all findings."""
    # Without clamping, idle_days=1 → effective_window=min(1,30)=1 < 3 → every resource skipped.
    # With clamping, idle_days=1 → clamped to 3 → effective_window=3 → detection works.
    item = _make_provisioned(age_days=30)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION, idle_days=1)

    assert len(findings) == 1  # found despite tiny idle_days input
    assert findings[0].details["idle_days_threshold"] == 3  # clamped value recorded


def test_multiple_throughputs_independent():
    """Each throughput is evaluated independently; one active does not suppress others."""
    idle_item = _make_provisioned(name="idle-tp", age_days=30)
    active_item = _make_provisioned(name="active-tp", age_days=30)

    session, _, cloudwatch = _make_session([idle_item, active_item])
    # idle-tp → no datapoints; active-tp → has invocations
    active_arn = active_item["provisionedModelArn"]

    def _cw(**kwargs):
        dims = kwargs.get("Dimensions", [])
        if dims and dims[0]["Value"] == active_arn:
            return {"Datapoints": [{"Sum": 3.0}]}
        return {"Datapoints": []}

    cloudwatch.get_metric_statistics.side_effect = _cw

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    assert len(findings) == 1
    assert findings[0].resource_id == "idle-tp"


def test_finding_details_complete():
    """Finding details dict contains all expected fields."""
    item = _make_provisioned(age_days=30, desired_units=5)
    session, _, _ = _make_session([item], cw_datapoints=[])

    findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

    d = findings[0].details
    assert "provisioned_model_name" in d
    assert "provisioned_model_arn" in d
    assert "desired_model_units" in d
    assert "commitment_duration" in d
    assert "age_days" in d
    assert "idle_ratio" in d
    assert d["desired_model_units"] == 5
