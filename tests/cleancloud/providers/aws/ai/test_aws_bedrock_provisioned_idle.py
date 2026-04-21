"""
Tests for aws.bedrock.provisioned_throughput.idle rule.

Test class overview:
    TestMustEmit                — canonical detection path
    TestMustSkip                — all exclusion rules
    TestMustFailRule            — required API failure behaviour
    TestNormalization           — _normalize_provisioned_throughput field extraction
    TestCloudWatchContract      — metric names, dimension, period, datapoint semantics
    TestConfidenceModel         — always HIGH
    TestRiskModel               — always HIGH
    TestCostModel               — estimated_monthly_cost_usd always None
    TestDetailsContract         — evaluation_path and all required detail fields
    TestEvidenceContract        — signals_used, signals_not_checked
    TestPagination              — multi-page exhaustion
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.ai.bedrock_provisioned_idle import (
    _normalize_provisioned_throughput,
    find_idle_bedrock_provisioned_throughputs,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"
_DEFAULT_THRESHOLD = 7
_PROVISIONED_ARN = "arn:aws:bedrock:us-east-1:123456789012:provisioned-model/my-throughput"
_FOUNDATION_ARN = (
    "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0"
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _old() -> datetime:
    """30 days ago — always older than the default 7-day threshold."""
    return datetime.now(timezone.utc) - timedelta(days=30)


def _young() -> datetime:
    """3 days ago — always younger than the default 7-day threshold."""
    return datetime.now(timezone.utc) - timedelta(days=3)


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def _botocore_error() -> BotoCoreError:
    return BotoCoreError()


def _make_item(**overrides) -> dict:
    """Return a minimal valid ListProvisionedModelThroughputs item."""
    base = {
        "provisionedModelArn": _PROVISIONED_ARN,
        "provisionedModelName": "my-throughput",
        "status": "InService",
        "creationTime": _old(),
        "modelArn": _FOUNDATION_ARN,
        "foundationModelArn": _FOUNDATION_ARN,
        "modelUnits": 2,
        "desiredModelUnits": 2,
        "commitmentDuration": "NoCommitment",
    }
    base.update(overrides)
    return base


def _make_session(items=None):
    """Return (session, bedrock_client, cloudwatch_client) mocks.

    CloudWatch is configured to return a single zero-Sum datapoint for every
    metric call by default — representing the canonical idle state.
    """
    session = MagicMock()
    bedrock = MagicMock()
    cloudwatch = MagicMock()

    paginator = MagicMock()
    paginator.paginate.return_value = [{"provisionedModelSummaries": items or []}]
    bedrock.get_paginator.return_value = paginator

    # Default: all metrics return one zero-Sum datapoint → idle
    cloudwatch.get_metric_statistics.return_value = {"Datapoints": [{"Sum": 0.0, "Timestamp": "x"}]}

    def _client(service, **kwargs):
        if service == "bedrock":
            return bedrock
        if service == "cloudwatch":
            return cloudwatch
        return MagicMock()

    session.client.side_effect = _client
    return session, bedrock, cloudwatch


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_canonical_emit(self):
        session, _, _ = _make_session([_make_item()])

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws.bedrock.provisioned_throughput.idle"
        assert f.provider == "aws"
        assert f.region == _REGION

    def test_resource_id_is_provisioned_model_arn(self):
        """resource_id must be provisionedModelArn, not the friendly name."""
        session, _, _ = _make_session([_make_item()])

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert findings[0].resource_id == _PROVISIONED_ARN

    def test_exactly_at_threshold_emitted(self):
        session, _, _ = _make_session(
            [_make_item(creationTime=_now() - timedelta(days=_DEFAULT_THRESHOLD))]
        )

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert len(findings) == 1

    def test_empty_account_emits_nothing(self):
        session, _, _ = _make_session([])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_custom_threshold_respected(self):
        session, _, _ = _make_session([_make_item(creationTime=_now() - timedelta(days=10))])

        # 10 days old, threshold=14 → too young
        assert (
            find_idle_bedrock_provisioned_throughputs(session, _REGION, idle_days_threshold=14)
            == []
        )

        # 10 days old, threshold=7 → old enough
        findings = find_idle_bedrock_provisioned_throughputs(
            session, _REGION, idle_days_threshold=7
        )
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_skip_missing_provisioned_model_arn(self):
        item = _make_item()
        del item["provisionedModelArn"]
        session, _, _ = _make_session([item])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_empty_provisioned_model_arn(self):
        session, _, _ = _make_session([_make_item(provisionedModelArn="")])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_creating_status(self):
        session, _, _ = _make_session([_make_item(status="Creating")])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_updating_status(self):
        session, _, _ = _make_session([_make_item(status="Updating")])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_failed_status(self):
        session, _, _ = _make_session([_make_item(status="Failed")])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_missing_status(self):
        item = _make_item()
        del item["status"]
        session, _, _ = _make_session([item])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_too_young(self):
        session, _, _ = _make_session([_make_item(creationTime=_young())])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_missing_creation_time(self):
        item = _make_item()
        del item["creationTime"]
        session, _, _ = _make_session([item])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_naive_creation_time(self):
        naive = datetime.now() - timedelta(days=30)
        session, _, _ = _make_session([_make_item(creationTime=naive)])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_future_creation_time(self):
        future = _now() + timedelta(days=10)
        session, _, _ = _make_session([_make_item(creationTime=future)])

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_invocations_sum_positive(self):
        session, _, cloudwatch = _make_session([_make_item()])
        cloudwatch.get_metric_statistics.return_value = {
            "Datapoints": [{"Sum": 5.0, "Timestamp": "x"}]
        }

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_invocation_client_errors_sum_positive(self):
        """InvocationClientErrors > 0 → not idle."""
        session, _, cloudwatch = _make_session([_make_item()])

        def _cw(**kwargs):
            metric = kwargs["MetricName"]
            if metric == "InvocationClientErrors":
                return {"Datapoints": [{"Sum": 1.0}]}
            return {"Datapoints": [{"Sum": 0.0}]}

        cloudwatch.get_metric_statistics.side_effect = _cw

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_invocation_server_errors_sum_positive(self):
        """InvocationServerErrors > 0 → not idle."""
        session, _, cloudwatch = _make_session([_make_item()])

        def _cw(**kwargs):
            metric = kwargs["MetricName"]
            if metric == "InvocationServerErrors":
                return {"Datapoints": [{"Sum": 2.0}]}
            return {"Datapoints": [{"Sum": 0.0}]}

        cloudwatch.get_metric_statistics.side_effect = _cw

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_invocation_throttles_sum_positive(self):
        """InvocationThrottles > 0 → not idle."""
        session, _, cloudwatch = _make_session([_make_item()])

        def _cw(**kwargs):
            metric = kwargs["MetricName"]
            if metric == "InvocationThrottles":
                return {"Datapoints": [{"Sum": 3.0}]}
            return {"Datapoints": [{"Sum": 0.0}]}

        cloudwatch.get_metric_statistics.side_effect = _cw

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_any_metric_no_datapoints(self):
        """Any required metric with no datapoints → insufficient evidence → SKIP ITEM."""
        session, _, cloudwatch = _make_session([_make_item()])

        def _cw(**kwargs):
            metric = kwargs["MetricName"]
            if metric == "InvocationServerErrors":
                return {"Datapoints": []}  # no datapoints
            return {"Datapoints": [{"Sum": 0.0}]}

        cloudwatch.get_metric_statistics.side_effect = _cw

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_skip_all_metrics_no_datapoints(self):
        """All metrics returning no datapoints → SKIP ITEM."""
        session, _, cloudwatch = _make_session([_make_item()])
        cloudwatch.get_metric_statistics.return_value = {"Datapoints": []}

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_list_provisioned_access_denied_raises_permission_error(self):
        session, bedrock, _ = _make_session()
        bedrock.get_paginator.return_value.paginate.side_effect = _client_error(
            "AccessDeniedException"
        )

        with pytest.raises(PermissionError, match="bedrock:ListProvisionedModelThroughputs"):
            find_idle_bedrock_provisioned_throughputs(session, _REGION)

    def test_list_provisioned_unauthorized_raises_permission_error(self):
        session, bedrock, _ = _make_session()
        bedrock.get_paginator.return_value.paginate.side_effect = _client_error(
            "UnauthorizedOperation"
        )

        with pytest.raises(PermissionError, match="bedrock:ListProvisionedModelThroughputs"):
            find_idle_bedrock_provisioned_throughputs(session, _REGION)

    def test_list_provisioned_other_client_error_propagates(self):
        session, bedrock, _ = _make_session()
        bedrock.get_paginator.return_value.paginate.side_effect = _client_error("InternalError")

        with pytest.raises(ClientError):
            find_idle_bedrock_provisioned_throughputs(session, _REGION)

    def test_list_provisioned_botocore_error_propagates(self):
        session, bedrock, _ = _make_session()
        bedrock.get_paginator.return_value.paginate.side_effect = _botocore_error()

        with pytest.raises(BotoCoreError):
            find_idle_bedrock_provisioned_throughputs(session, _REGION)

    def test_cloudwatch_access_denied_raises_permission_error(self):
        session, _, cloudwatch = _make_session([_make_item()])
        cloudwatch.get_metric_statistics.side_effect = _client_error("AccessDeniedException")

        with pytest.raises(PermissionError, match="cloudwatch:GetMetricStatistics"):
            find_idle_bedrock_provisioned_throughputs(session, _REGION)

    def test_cloudwatch_unauthorized_raises_permission_error(self):
        session, _, cloudwatch = _make_session([_make_item()])
        cloudwatch.get_metric_statistics.side_effect = _client_error("UnauthorizedOperation")

        with pytest.raises(PermissionError, match="cloudwatch:GetMetricStatistics"):
            find_idle_bedrock_provisioned_throughputs(session, _REGION)

    def test_cloudwatch_transient_error_fails_rule(self):
        """Transient CloudWatch error → FAIL RULE (not conservative skip)."""
        session, _, cloudwatch = _make_session([_make_item()])
        cloudwatch.get_metric_statistics.side_effect = _client_error("ThrottlingException")

        with pytest.raises(ClientError):
            find_idle_bedrock_provisioned_throughputs(session, _REGION)

    def test_cloudwatch_botocore_error_fails_rule(self):
        session, _, cloudwatch = _make_session([_make_item()])
        cloudwatch.get_metric_statistics.side_effect = _botocore_error()

        with pytest.raises(BotoCoreError):
            find_idle_bedrock_provisioned_throughputs(session, _REGION)


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_non_dict_returns_none(self):
        assert _normalize_provisioned_throughput("bad", _now()) is None
        assert _normalize_provisioned_throughput(None, _now()) is None

    def test_missing_arn_returns_none(self):
        item = _make_item()
        del item["provisionedModelArn"]
        assert _normalize_provisioned_throughput(item, _now()) is None

    def test_empty_arn_returns_none(self):
        assert _normalize_provisioned_throughput(_make_item(provisionedModelArn=""), _now()) is None

    def test_missing_status_returns_none(self):
        item = _make_item()
        del item["status"]
        assert _normalize_provisioned_throughput(item, _now()) is None

    def test_missing_creation_time_returns_none(self):
        item = _make_item()
        del item["creationTime"]
        assert _normalize_provisioned_throughput(item, _now()) is None

    def test_naive_creation_time_returns_none(self):
        naive = datetime.now() - timedelta(days=30)
        assert _normalize_provisioned_throughput(_make_item(creationTime=naive), _now()) is None

    def test_future_creation_time_returns_none(self):
        future = _now() + timedelta(days=5)
        assert _normalize_provisioned_throughput(_make_item(creationTime=future), _now()) is None

    def test_resource_id_equals_provisioned_model_arn(self):
        n = _normalize_provisioned_throughput(_make_item(), _now())
        assert n["resource_id"] == _PROVISIONED_ARN
        assert n["provisioned_model_arn"] == _PROVISIONED_ARN

    def test_age_days_computed(self):
        ct = _now() - timedelta(days=45)
        n = _normalize_provisioned_throughput(_make_item(creationTime=ct), _now())
        assert n["age_days"] == 45

    def test_model_units_int_only(self):
        n = _normalize_provisioned_throughput(_make_item(modelUnits=4), _now())
        assert n["model_units"] == 4

        n2 = _normalize_provisioned_throughput(_make_item(modelUnits="4"), _now())
        assert n2["model_units"] is None

    def test_optional_fields_null_when_absent(self):
        item = _make_item()
        for key in [
            "modelArn",
            "foundationModelArn",
            "commitmentDuration",
            "commitmentExpirationTime",
            "lastModifiedTime",
        ]:
            item.pop(key, None)
        n = _normalize_provisioned_throughput(item, _now())
        assert n["model_arn"] is None
        assert n["foundation_model_arn"] is None
        assert n["commitment_duration"] is None
        assert n["commitment_expiration_time_utc"] is None
        assert n["last_modified_time_utc"] is None

    def test_contextual_naive_timestamp_null(self):
        naive_exp = datetime.now() + timedelta(days=30)
        n = _normalize_provisioned_throughput(
            _make_item(commitmentExpirationTime=naive_exp), _now()
        )
        assert n["commitment_expiration_time_utc"] is None


# ---------------------------------------------------------------------------
# TestCloudWatchContract
# ---------------------------------------------------------------------------


class TestCloudWatchContract:
    def test_all_four_metrics_queried(self):
        """All 4 required metrics must be queried per candidate."""
        session, _, cloudwatch = _make_session([_make_item()])

        find_idle_bedrock_provisioned_throughputs(session, _REGION)

        called_metrics = [
            c.kwargs["MetricName"] for c in cloudwatch.get_metric_statistics.call_args_list
        ]
        assert "Invocations" in called_metrics
        assert "InvocationClientErrors" in called_metrics
        assert "InvocationServerErrors" in called_metrics
        assert "InvocationThrottles" in called_metrics
        assert cloudwatch.get_metric_statistics.call_count == 4

    def test_dimension_uses_provisioned_model_arn_only(self):
        """Dimension must be ModelId = provisionedModelArn — no fallback dimensions."""
        session, _, cloudwatch = _make_session([_make_item()])

        find_idle_bedrock_provisioned_throughputs(session, _REGION)

        for c in cloudwatch.get_metric_statistics.call_args_list:
            dims = c.kwargs["Dimensions"]
            assert dims == [{"Name": "ModelId", "Value": _PROVISIONED_ARN}]

    def test_namespace_is_aws_bedrock(self):
        session, _, cloudwatch = _make_session([_make_item()])

        find_idle_bedrock_provisioned_throughputs(session, _REGION)

        for c in cloudwatch.get_metric_statistics.call_args_list:
            assert c.kwargs["Namespace"] == "AWS/Bedrock"

    def test_statistic_is_sum(self):
        session, _, cloudwatch = _make_session([_make_item()])

        find_idle_bedrock_provisioned_throughputs(session, _REGION)

        for c in cloudwatch.get_metric_statistics.call_args_list:
            assert "Sum" in c.kwargs["Statistics"]

    def test_period_equals_threshold_times_86400(self):
        session, _, cloudwatch = _make_session([_make_item()])

        find_idle_bedrock_provisioned_throughputs(session, _REGION, idle_days_threshold=7)

        for c in cloudwatch.get_metric_statistics.call_args_list:
            assert c.kwargs["Period"] == 7 * 86400

    def test_missing_datapoints_skips_item(self):
        """Any metric returning no datapoints → SKIP ITEM (insufficient evidence)."""
        session, _, cloudwatch = _make_session([_make_item()])
        cloudwatch.get_metric_statistics.return_value = {"Datapoints": []}

        assert find_idle_bedrock_provisioned_throughputs(session, _REGION) == []

    def test_cloudwatch_not_called_for_excluded_items(self):
        """CloudWatch must not be called for items excluded by age or status."""
        session, _, cloudwatch = _make_session([_make_item(status="Creating")])

        find_idle_bedrock_provisioned_throughputs(session, _REGION)

        cloudwatch.get_metric_statistics.assert_not_called()

    def test_metrics_queried_in_spec_order(self):
        """Metrics must be queried in the spec-defined order."""
        session, _, cloudwatch = _make_session([_make_item()])

        find_idle_bedrock_provisioned_throughputs(session, _REGION)

        called_metrics = [
            c.kwargs["MetricName"] for c in cloudwatch.get_metric_statistics.call_args_list
        ]
        assert called_metrics == [
            "Invocations",
            "InvocationClientErrors",
            "InvocationServerErrors",
            "InvocationThrottles",
        ]

    def test_short_circuits_on_first_active_metric(self):
        """Once a metric shows activity, remaining metrics must not be queried."""
        session, _, cloudwatch = _make_session([_make_item()])
        # Invocations > 0 → should stop immediately
        cloudwatch.get_metric_statistics.return_value = {"Datapoints": [{"Sum": 10.0}]}

        find_idle_bedrock_provisioned_throughputs(session, _REGION)

        # Only 1 call — stopped after Invocations showed activity
        assert cloudwatch.get_metric_statistics.call_count == 1


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_confidence_always_high(self):
        session, _, _ = _make_session([_make_item()])

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert findings[0].confidence == ConfidenceLevel.HIGH

    def test_no_medium_confidence(self):
        """Rule never emits MEDIUM confidence — only HIGH."""
        session, _, _ = _make_session([_make_item()])

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert findings[0].confidence != ConfidenceLevel.MEDIUM


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_risk_always_high(self):
        session, _, _ = _make_session([_make_item()])

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert findings[0].risk == RiskLevel.HIGH

    def test_no_critical_risk(self):
        """Rule never emits CRITICAL risk — only HIGH."""
        session, _, _ = _make_session([_make_item()])

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert findings[0].risk != RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# TestCostModel
# ---------------------------------------------------------------------------


class TestCostModel:
    def test_estimated_monthly_cost_always_none(self):
        session, _, _ = _make_session([_make_item(desiredModelUnits=10)])

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert findings[0].estimated_monthly_cost_usd is None


# ---------------------------------------------------------------------------
# TestDetailsContract
# ---------------------------------------------------------------------------


class TestDetailsContract:
    def _details(self) -> dict:
        session, _, _ = _make_session([_make_item()])
        return find_idle_bedrock_provisioned_throughputs(session, _REGION)[0].details

    def test_evaluation_path(self):
        assert self._details()["evaluation_path"] == (
            "idle-bedrock-provisioned-throughput-review-candidate"
        )

    def test_provisioned_model_arn_present(self):
        assert self._details()["provisioned_model_arn"] == _PROVISIONED_ARN

    def test_normalized_status_present(self):
        assert self._details()["normalized_status"] == "InService"

    def test_creation_time_present(self):
        d = self._details()
        assert "creation_time" in d
        assert isinstance(d["creation_time"], str)

    def test_age_days_present(self):
        d = self._details()
        assert "age_days" in d
        assert isinstance(d["age_days"], int)
        assert d["age_days"] > 0

    def test_idle_days_threshold_present(self):
        assert self._details()["idle_days_threshold"] == _DEFAULT_THRESHOLD

    def test_activity_metrics_checked_contains_all_four(self):
        metrics = self._details()["activity_metrics_checked"]
        assert "Invocations" in metrics
        assert "InvocationClientErrors" in metrics
        assert "InvocationServerErrors" in metrics
        assert "InvocationThrottles" in metrics

    def test_model_units_present(self):
        d = self._details()
        assert "model_units" in d

    def test_foundation_model_arn_present(self):
        d = self._details()
        assert "foundation_model_arn" in d

    def test_commitment_expiration_time_present(self):
        d = self._details()
        assert "commitment_expiration_time" in d

    def test_commitment_duration_present(self):
        d = self._details()
        assert "commitment_duration" in d

    def test_provisioned_model_name_present(self):
        session, _, _ = _make_session([_make_item(provisionedModelName="my-tp")])
        d = find_idle_bedrock_provisioned_throughputs(session, _REGION)[0].details
        assert d["provisioned_model_name"] == "my-tp"


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_signals_used_mention_in_service(self):
        session, _, _ = _make_session([_make_item()])
        signals = find_idle_bedrock_provisioned_throughputs(session, _REGION)[
            0
        ].evidence.signals_used
        assert any("InService" in s for s in signals)

    def test_signals_used_mention_model_id_dimension(self):
        session, _, _ = _make_session([_make_item()])
        signals = find_idle_bedrock_provisioned_throughputs(session, _REGION)[
            0
        ].evidence.signals_used
        assert any("ModelId" in s or _PROVISIONED_ARN in s for s in signals)

    def test_signals_used_mention_all_required_metrics(self):
        session, _, _ = _make_session([_make_item()])
        signals = " ".join(
            find_idle_bedrock_provisioned_throughputs(session, _REGION)[0].evidence.signals_used
        )
        assert "Invocations" in signals
        assert "InvocationClientErrors" in signals
        assert "InvocationServerErrors" in signals
        assert "InvocationThrottles" in signals

    def test_signals_not_checked_populated(self):
        session, _, _ = _make_session([_make_item()])
        not_checked = find_idle_bedrock_provisioned_throughputs(session, _REGION)[
            0
        ].evidence.signals_not_checked
        assert len(not_checked) > 0

    def test_signals_not_checked_mention_commitment(self):
        session, _, _ = _make_session([_make_item()])
        not_checked = find_idle_bedrock_provisioned_throughputs(session, _REGION)[
            0
        ].evidence.signals_not_checked
        assert any("commitment" in s.lower() for s in not_checked)


# ---------------------------------------------------------------------------
# TestPagination
# ---------------------------------------------------------------------------


class TestPagination:
    def test_multi_page_exhausted(self):
        session, bedrock, cloudwatch = _make_session()

        arn1 = "arn:aws:bedrock:us-east-1:123:provisioned-model/tp-1"
        arn2 = "arn:aws:bedrock:us-east-1:123:provisioned-model/tp-2"
        bedrock.get_paginator.return_value.paginate.return_value = [
            {"provisionedModelSummaries": [_make_item(provisionedModelArn=arn1)]},
            {"provisionedModelSummaries": [_make_item(provisionedModelArn=arn2)]},
        ]
        cloudwatch.get_metric_statistics.return_value = {"Datapoints": [{"Sum": 0.0}]}

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert len(findings) == 2
        arns = {f.resource_id for f in findings}
        assert arn1 in arns
        assert arn2 in arns

    def test_paginator_filtered_to_in_service(self):
        session, bedrock, _ = _make_session([])

        find_idle_bedrock_provisioned_throughputs(session, _REGION)

        bedrock.get_paginator.return_value.paginate.assert_called_once_with(
            statusEquals="InService"
        )

    def test_multiple_items_evaluated_independently(self):
        """One item with activity does not suppress other idle items."""
        arn_idle = "arn:aws:bedrock:us-east-1:123:provisioned-model/idle"
        arn_active = "arn:aws:bedrock:us-east-1:123:provisioned-model/active"

        session, bedrock, cloudwatch = _make_session()
        bedrock.get_paginator.return_value.paginate.return_value = [
            {
                "provisionedModelSummaries": [
                    _make_item(provisionedModelArn=arn_idle),
                    _make_item(provisionedModelArn=arn_active),
                ]
            }
        ]

        def _cw(**kwargs):
            dims = kwargs.get("Dimensions", [])
            val = dims[0]["Value"] if dims else ""
            if val == arn_active and kwargs.get("MetricName") == "Invocations":
                return {"Datapoints": [{"Sum": 5.0}]}
            return {"Datapoints": [{"Sum": 0.0}]}

        cloudwatch.get_metric_statistics.side_effect = _cw

        findings = find_idle_bedrock_provisioned_throughputs(session, _REGION)

        assert len(findings) == 1
        assert findings[0].resource_id == arn_idle
