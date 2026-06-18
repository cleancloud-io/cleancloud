"""
Tests for aws.opensearch.domain.idle rule.

Test class overview:
    TestMustEmit              => canonical detection path
    TestMustSkip              => all exclusion rules
    TestMustFailRule          => required API failure behaviour
    TestNormalization         => _normalize_domain field extraction
    TestCoverageModel         => hourly datapoint coverage requirement
    TestConfidenceModel       => HIGH with corroboration, MEDIUM without
    TestRiskModel             => HIGH for large domains, MEDIUM otherwise
    TestEvidenceContract      => signals_used, signals_not_checked, evaluation_path
    TestRuleMetadata          => rule_id, category, service, cost_impact
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from cleancloud.providers.aws.rules.opensearch_idle import (
    _normalize_domain,
    find_idle_opensearch_domains,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_REGION = "us-east-1"
_ACCOUNT_ID = "123456789012"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def _make_domain_status(**overrides) -> dict:
    """Return a minimal valid DomainStatus."""
    base = {
        "DomainName": "test-domain",
        "DomainId": f"{_ACCOUNT_ID}/test-domain",
        "ARN": f"arn:aws:es:us-east-1:{_ACCOUNT_ID}:domain/test-domain",
        "EngineVersion": "OpenSearch_2.11",
        "DomainProcessingStatus": "Active",
        "Created": True,
        "Deleted": False,
        "Processing": False,
        "ClusterConfig": {
            "InstanceType": "r6g.large.search",
            "InstanceCount": 2,
            "DedicatedMasterEnabled": False,
            "WarmEnabled": False,
            "ZoneAwarenessEnabled": True,
        },
        "EBSOptions": {
            "EBSEnabled": True,
            "VolumeType": "gp3",
            "VolumeSize": 100,
        },
        "Endpoint": "search-test-domain-abc123.us-east-1.es.amazonaws.com",
    }
    base.update(overrides)
    return base


def _zero_hourly_datapoints(count: int = 336) -> dict:
    """CloudWatch response: count hourly datapoints with unique timestamps, all Sum == 0."""
    return {
        "Datapoints": [
            {"Sum": 0.0, "Timestamp": f"2026-06-01T{i // 24:02d}:{i % 24:02d}:00Z"}
            for i in range(count)
        ]
    }


def _nonzero_hourly_datapoints() -> dict:
    """336 datapoints with unique timestamps, last one has Sum > 0."""
    dps = [
        {"Sum": 0.0, "Timestamp": f"2026-06-01T{i // 24:02d}:{i % 24:02d}:00Z"} for i in range(335)
    ]
    dps.append({"Sum": 5.0, "Timestamp": "2026-06-15T23:00:00Z"})
    return {"Datapoints": dps}


def _sparse_datapoints(count: int = 100) -> dict:
    """Too few datapoints with unique timestamps for 14-day coverage."""
    return {
        "Datapoints": [
            {"Sum": 0.0, "Timestamp": f"2026-06-01T{i // 24:02d}:{i % 24:02d}:00Z"}
            for i in range(count)
        ]
    }


def _no_datapoints_response() -> dict:
    return {"Datapoints": []}


def _zero_sum_response() -> dict:
    """Single full-window aggregate Sum = 0 (for secondary signals)."""
    return {"Datapoints": [{"Sum": 0.0}]}


def _setup(
    mock_boto3_session,
    domain_names=None,
    domain_status=None,
    cw_responses=None,
    cw_side_effect=None,
    list_side_effect=None,
    describe_side_effect=None,
):
    """Wire up OpenSearch + CloudWatch + STS mocks."""
    opensearch = MagicMock()
    cloudwatch = MagicMock()
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": _ACCOUNT_ID}

    # ListDomainNames
    if list_side_effect is not None:
        opensearch.list_domain_names.side_effect = list_side_effect
    else:
        if domain_names is None:
            domain_names = ["test-domain"]
        opensearch.list_domain_names.return_value = {
            "DomainNames": [{"DomainName": n} for n in domain_names]
        }

    # DescribeDomain
    if describe_side_effect is not None:
        opensearch.describe_domain.side_effect = describe_side_effect
    else:
        if domain_status is None:
            domain_status = _make_domain_status()
        opensearch.describe_domain.return_value = {"DomainStatus": domain_status}

    # CloudWatch
    if cw_side_effect is not None:
        cloudwatch.get_metric_statistics.side_effect = cw_side_effect
    elif cw_responses is not None:
        cloudwatch.get_metric_statistics.side_effect = cw_responses
    else:
        # Default: zero requests with full coverage + zero secondary
        cloudwatch.get_metric_statistics.side_effect = [
            _zero_hourly_datapoints(),  # OpenSearchRequests
            _zero_sum_response(),  # SearchRate
            _zero_sum_response(),  # IndexingRate
        ]

    def client_side_effect(service, **kwargs):
        if service == "opensearch":
            return opensearch
        if service == "cloudwatch":
            return cloudwatch
        if service == "sts":
            return sts
        raise ValueError(f"Unexpected service: {service}")

    mock_boto3_session.client.side_effect = client_side_effect
    return opensearch, cloudwatch, sts


# ---------------------------------------------------------------------------
# TestMustEmit
# ---------------------------------------------------------------------------


class TestMustEmit:
    def test_canonical_idle_domain_emits(self, mock_boto3_session):
        _setup(mock_boto3_session)
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 1
        f = findings[0]
        assert f.provider == "aws"
        assert f.rule_id == "aws.opensearch.domain.idle"
        assert f.resource_type == "aws.opensearch.domain"
        assert f.region == _REGION

    def test_resource_id_is_arn(self, mock_boto3_session):
        _setup(mock_boto3_session)
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings[0].resource_id == (f"arn:aws:es:us-east-1:{_ACCOUNT_ID}:domain/test-domain")

    def test_details_required_fields_present(self, mock_boto3_session):
        _setup(mock_boto3_session)
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        d = findings[0].details
        for key in (
            "evaluation_path",
            "domain_name",
            "arn",
            "domain_processing_status",
            "engine_version",
            "instance_type",
            "instance_count",
            "idle_days_threshold",
            "evaluation_window_start",
            "evaluation_window_end",
            "opensearch_requests_sum",
            "expected_datapoints",
            "actual_datapoints",
            "coverage_ratio",
            "is_idle",
        ):
            assert key in d, f"Missing required detail key: {key}"

    def test_details_optional_fields_present(self, mock_boto3_session):
        _setup(mock_boto3_session)
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        d = findings[0].details
        for key in (
            "domain_id",
            "search_rate_sum",
            "indexing_rate_sum",
            "dedicated_master_enabled",
            "warm_enabled",
            "ebs_enabled",
            "ebs_volume_type",
            "ebs_volume_size_gb",
            "endpoint",
            "endpoints",
        ):
            assert key in d, f"Missing optional detail key: {key}"

    def test_no_domains_returns_empty(self, mock_boto3_session):
        _setup(mock_boto3_session, domain_names=[])
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings == []


# ---------------------------------------------------------------------------
# TestMustSkip
# ---------------------------------------------------------------------------


class TestMustSkip:
    def test_skip_creating_status(self, mock_boto3_session):
        _setup(
            mock_boto3_session, domain_status=_make_domain_status(DomainProcessingStatus="Creating")
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_modifying_status(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            domain_status=_make_domain_status(DomainProcessingStatus="Modifying"),
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_deleting_status(self, mock_boto3_session):
        _setup(
            mock_boto3_session, domain_status=_make_domain_status(DomainProcessingStatus="Deleting")
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_created_false(self, mock_boto3_session):
        _setup(mock_boto3_session, domain_status=_make_domain_status(Created=False))
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_deleted_true(self, mock_boto3_session):
        _setup(mock_boto3_session, domain_status=_make_domain_status(Deleted=True))
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_nonzero_requests(self, mock_boto3_session):
        _setup(mock_boto3_session, cw_responses=[_nonzero_hourly_datapoints()])
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_no_datapoints(self, mock_boto3_session):
        _setup(mock_boto3_session, cw_responses=[_no_datapoints_response()])
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_missing_domain_name(self, mock_boto3_session):
        _setup(mock_boto3_session, domain_status=_make_domain_status(DomainName=None))
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_missing_arn(self, mock_boto3_session):
        _setup(mock_boto3_session, domain_status=_make_domain_status(ARN=None))
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_missing_processing_status(self, mock_boto3_session):
        _setup(mock_boto3_session, domain_status=_make_domain_status(DomainProcessingStatus=None))
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_describe_race_condition(self, mock_boto3_session):
        """Domain deleted between list and describe => skip, not fail."""
        _setup(
            mock_boto3_session,
            describe_side_effect=_client_error("ResourceNotFoundException"),
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_skip_describe_validation_error(self, mock_boto3_session):
        """ValidationException on describe => skip (narrow race variant)."""
        _setup(
            mock_boto3_session,
            describe_side_effect=_client_error("ValidationException"),
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# TestMustFailRule (describe non-race errors)
# ---------------------------------------------------------------------------


class TestDescribeFailures:
    def test_describe_transient_error_raises(self, mock_boto3_session):
        """Non-race ClientError on describe => FAIL RULE, not skip."""
        _setup(
            mock_boto3_session,
            describe_side_effect=_client_error("InternalServerError"),
        )
        with pytest.raises(ClientError):
            find_idle_opensearch_domains(mock_boto3_session, _REGION)

    def test_describe_botocore_error_raises(self, mock_boto3_session):
        """BotoCoreError on describe => FAIL RULE."""
        _setup(
            mock_boto3_session,
            describe_side_effect=BotoCoreError(),
        )
        with pytest.raises(BotoCoreError):
            find_idle_opensearch_domains(mock_boto3_session, _REGION)


# ---------------------------------------------------------------------------
# TestCoverageModel
# ---------------------------------------------------------------------------


class TestCoverageModel:
    def test_skip_insufficient_coverage(self, mock_boto3_session):
        """100 datapoints out of 336 expected = ~30% coverage => skip."""
        _setup(mock_boto3_session, cw_responses=[_sparse_datapoints(100)])
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_emit_at_95_percent_coverage(self, mock_boto3_session):
        """320 datapoints out of 336 expected = ~95.2% coverage => emit."""
        _setup(
            mock_boto3_session,
            cw_responses=[
                _zero_hourly_datapoints(320),
                _zero_sum_response(),
                _zero_sum_response(),
            ],
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 1

    def test_skip_just_below_95_percent(self, mock_boto3_session):
        """318 datapoints out of 336 expected = ~94.6% => skip."""
        _setup(mock_boto3_session, cw_responses=[_zero_hourly_datapoints(318)])
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 0

    def test_coverage_fields_in_details(self, mock_boto3_session):
        _setup(mock_boto3_session)
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        d = findings[0].details
        assert d["expected_datapoints"] == 336
        assert d["actual_datapoints"] == 336
        assert d["coverage_ratio"] == 1.0

    def test_duplicate_timestamps_deduped(self, mock_boto3_session):
        """Duplicate datapoints for same timestamp should not inflate coverage."""
        ts = "2026-06-01T00:00:00Z"
        duplicated = {"Datapoints": [{"Sum": 0.0, "Timestamp": ts} for _ in range(400)]}
        _setup(mock_boto3_session, cw_responses=[duplicated])
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        # 400 datapoints but all same timestamp => 1 unique => coverage ~0.3% => skip
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# TestMustFailRule
# ---------------------------------------------------------------------------


class TestMustFailRule:
    def test_list_domain_names_permission_error(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            list_side_effect=_client_error("AccessDenied"),
        )
        with pytest.raises(PermissionError, match="es:ListDomainNames"):
            find_idle_opensearch_domains(mock_boto3_session, _REGION)

    def test_describe_domain_permission_error(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            describe_side_effect=_client_error("AccessDeniedException"),
        )
        with pytest.raises(PermissionError, match="es:DescribeDomain"):
            find_idle_opensearch_domains(mock_boto3_session, _REGION)

    def test_cloudwatch_permission_error(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            cw_side_effect=_client_error("AccessDenied"),
        )
        with pytest.raises(PermissionError, match="cloudwatch:GetMetricStatistics"):
            find_idle_opensearch_domains(mock_boto3_session, _REGION)

    def test_cloudwatch_request_failure_raises(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            cw_side_effect=BotoCoreError(),
        )
        with pytest.raises(BotoCoreError):
            find_idle_opensearch_domains(mock_boto3_session, _REGION)


# ---------------------------------------------------------------------------
# TestNormalization
# ---------------------------------------------------------------------------


class TestNormalization:
    def test_valid_domain_normalizes(self):
        n = _normalize_domain(_make_domain_status())
        assert n is not None
        assert n["domain_name"] == "test-domain"
        assert n["domain_processing_status"] == "Active"
        assert n["instance_type"] == "r6g.large.search"
        assert n["instance_count"] == 2
        assert n["ebs_volume_size_gb"] == 100

    def test_non_dict_returns_none(self):
        assert _normalize_domain("not a dict") is None

    def test_missing_name_returns_none(self):
        assert _normalize_domain(_make_domain_status(DomainName=None)) is None

    def test_missing_arn_returns_none(self):
        assert _normalize_domain(_make_domain_status(ARN=None)) is None

    def test_missing_cluster_config_degrades(self):
        n = _normalize_domain(_make_domain_status(ClusterConfig=None))
        assert n is not None
        assert n["instance_type"] is None
        assert n["instance_count"] is None
        assert n["dedicated_master_enabled"] is False

    def test_missing_ebs_options_degrades(self):
        n = _normalize_domain(_make_domain_status(EBSOptions=None))
        assert n is not None
        assert n["ebs_enabled"] is False
        assert n["ebs_volume_type"] is None


# ---------------------------------------------------------------------------
# TestConfidenceModel
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    def test_high_confidence_with_secondary_zero(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            cw_responses=[
                _zero_hourly_datapoints(),
                _zero_sum_response(),
                _zero_sum_response(),
            ],
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings[0].confidence.value == "high"

    def test_medium_confidence_when_secondary_missing(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            cw_responses=[
                _zero_hourly_datapoints(),
                _no_datapoints_response(),
                _no_datapoints_response(),
            ],
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings[0].confidence.value == "medium"

    def test_medium_confidence_when_secondary_fails(self, mock_boto3_session):
        """Secondary metric failure => null => MEDIUM confidence, but still emits."""
        responses = [_zero_hourly_datapoints()]

        def cw_side_effect(*args, **kwargs):
            if responses:
                return responses.pop(0)
            raise BotoCoreError()

        _setup(mock_boto3_session, cw_side_effect=cw_side_effect)
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert len(findings) == 1
        assert findings[0].confidence.value == "medium"


# ---------------------------------------------------------------------------
# TestRiskModel
# ---------------------------------------------------------------------------


class TestRiskModel:
    def test_high_risk_multi_node(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            domain_status=_make_domain_status(
                ClusterConfig={
                    "InstanceType": "r6g.large.search",
                    "InstanceCount": 3,
                    "DedicatedMasterEnabled": False,
                    "WarmEnabled": False,
                }
            ),
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings[0].risk.value == "high"

    def test_high_risk_warm_enabled(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            domain_status=_make_domain_status(
                ClusterConfig={
                    "InstanceType": "r6g.large.search",
                    "InstanceCount": 1,
                    "DedicatedMasterEnabled": False,
                    "WarmEnabled": True,
                    "WarmType": "ultrawarm1.medium.search",
                    "WarmCount": 2,
                }
            ),
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings[0].risk.value == "high"

    def test_high_risk_dedicated_master(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            domain_status=_make_domain_status(
                ClusterConfig={
                    "InstanceType": "r6g.large.search",
                    "InstanceCount": 2,
                    "DedicatedMasterEnabled": True,
                    "DedicatedMasterType": "r6g.large.search",
                    "DedicatedMasterCount": 3,
                    "WarmEnabled": False,
                }
            ),
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings[0].risk.value == "high"

    def test_medium_risk_small_domain(self, mock_boto3_session):
        _setup(
            mock_boto3_session,
            domain_status=_make_domain_status(
                ClusterConfig={
                    "InstanceType": "t3.small.search",
                    "InstanceCount": 1,
                    "DedicatedMasterEnabled": False,
                    "WarmEnabled": False,
                }
            ),
        )
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings[0].risk.value == "medium"


# ---------------------------------------------------------------------------
# TestEvidenceContract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    def test_evaluation_path(self, mock_boto3_session):
        _setup(mock_boto3_session)
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings[0].details["evaluation_path"] == ("idle-opensearch-domain-review-candidate")

    def test_signals_not_checked(self, mock_boto3_session):
        _setup(mock_boto3_session)
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        snc = findings[0].evidence.signals_not_checked
        assert any("business value" in s.lower() for s in snc)
        assert any("deleting" in s.lower() for s in snc)
        assert any("backed up" in s.lower() for s in snc)

    def test_is_idle_always_true(self, mock_boto3_session):
        _setup(mock_boto3_session)
        findings = find_idle_opensearch_domains(mock_boto3_session, _REGION)
        assert findings[0].details["is_idle"] is True


# ---------------------------------------------------------------------------
# TestRuleMetadata
# ---------------------------------------------------------------------------


class TestRuleMetadata:
    def test_rule_id(self):
        from cleancloud.providers.aws.rules.opensearch_idle import RULE_METADATA

        assert RULE_METADATA["id"] == "aws.opensearch.domain.idle"

    def test_category(self):
        from cleancloud.providers.aws.rules.opensearch_idle import RULE_METADATA

        assert RULE_METADATA["category"] == "hygiene"

    def test_service(self):
        from cleancloud.providers.aws.rules.opensearch_idle import RULE_METADATA

        assert RULE_METADATA["service"] == "opensearch"

    def test_cost_impact(self):
        from cleancloud.providers.aws.rules.opensearch_idle import RULE_METADATA

        assert RULE_METADATA["cost_impact"] == "high"
