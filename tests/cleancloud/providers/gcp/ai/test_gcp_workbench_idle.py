"""
Tests for gcp.vertex.workbench.idle rule.

The rule is EMITTING_DISABLED and always returns an empty List[Finding].
No qualifying canonical kernel-activity signal exists; updateTime, createTime,
age, and CPU utilization are all explicitly non-canonical.

Coverage:
  Public API (find_idle_workbench_instances):
    - return type and value
    - idle_days validation (zero, negative, boundary, error message)
    - region_filter parameter accepted
    - 403/404/400/5xx/network error handling
    - warning type, message content (project, HTTP code, rule ID)

  Internal (_list_instances):
    - empty response
    - instance accumulation
    - pagination over 2 and 3 pages
    - pageToken forwarded on subsequent requests
    - pageSize=100 in initial request
    - unreachable[] collected and deduplicated across pages
    - empty unreachable entries skipped
    - 404 returns clean ([], [], False)
    - 400 returns ([], [], True)
    - 5xx sets discovery_failed; preserves already-fetched instances
    - network error sets discovery_failed; preserves already-fetched instances
    - 403 raises PermissionError
    - URL contains project ID and locations/- wildcard
"""

import warnings
from unittest.mock import MagicMock, patch

import pytest

from cleancloud.providers.gcp.rules.ai.workbench_idle import (
    RULE_METADATA,
    _list_instances,
    find_idle_workbench_instances,
)

_PROJECT = "my-project"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(body: dict = None):
    """Build a 200 response mock with the given JSON body."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = body or {}
    resp.raise_for_status.return_value = None
    return resp


def _err(status_code: int):
    """Build an error response mock with the given status code."""
    resp = MagicMock()
    resp.status_code = status_code
    return resp


def _session(*responses):
    """Build a mock session whose .get() returns responses in order."""
    mock = MagicMock()
    mock.get.side_effect = list(responses)
    return mock


def _invoke(**kwargs):
    """
    Call find_idle_workbench_instances with a default 200/empty mock session.
    Extra kwargs are forwarded to the rule function.
    """
    with patch(
        "cleancloud.providers.gcp.rules.ai.workbench_idle.AuthorizedSession",
        return_value=_session(_ok()),
    ):
        return find_idle_workbench_instances(
            project_id=_PROJECT, credentials=MagicMock(), **kwargs
        )


def _invoke_with_session(mock_session, **kwargs):
    """Call find_idle_workbench_instances with a custom session mock."""
    with patch(
        "cleancloud.providers.gcp.rules.ai.workbench_idle.AuthorizedSession",
        return_value=mock_session,
    ):
        return find_idle_workbench_instances(
            project_id=_PROJECT, credentials=MagicMock(), **kwargs
        )


# ---------------------------------------------------------------------------
# Return type and value
# ---------------------------------------------------------------------------


class TestReturnValue:
    def test_returns_list(self):
        assert isinstance(_invoke(), list)

    def test_always_empty(self):
        assert _invoke() == []

    def test_empty_when_api_returns_active_instances(self):
        """EMITTING_DISABLED: ACTIVE instances in API response still yield no findings."""
        inst = {"name": f"projects/{_PROJECT}/locations/us-central1/instances/wb-1", "state": "ACTIVE"}
        result = _invoke_with_session(_session(_ok({"instances": [inst]})))
        assert result == []

    def test_empty_when_api_returns_multiple_instances(self):
        instances = [
            {"name": f"projects/{_PROJECT}/locations/us-central1/instances/wb-{i}", "state": "ACTIVE"}
            for i in range(5)
        ]
        result = _invoke_with_session(_session(_ok({"instances": instances})))
        assert result == []


# ---------------------------------------------------------------------------
# idle_days validation
# ---------------------------------------------------------------------------


class TestIdleDaysValidation:
    def test_zero_raises_value_error(self):
        with pytest.raises(ValueError, match="idle_days must be >= 1"):
            find_idle_workbench_instances(
                project_id=_PROJECT, credentials=MagicMock(), idle_days=0
            )

    def test_negative_one_raises(self):
        with pytest.raises(ValueError, match="idle_days must be >= 1"):
            find_idle_workbench_instances(
                project_id=_PROJECT, credentials=MagicMock(), idle_days=-1
            )

    def test_large_negative_raises(self):
        with pytest.raises(ValueError, match="idle_days must be >= 1"):
            find_idle_workbench_instances(
                project_id=_PROJECT, credentials=MagicMock(), idle_days=-999
            )

    def test_error_message_includes_bad_value(self):
        with pytest.raises(ValueError, match="-3"):
            find_idle_workbench_instances(
                project_id=_PROJECT, credentials=MagicMock(), idle_days=-3
            )

    def test_one_is_valid(self):
        assert _invoke(idle_days=1) == []

    def test_default_14_is_valid(self):
        assert _invoke() == []

    def test_large_value_is_valid(self):
        assert _invoke(idle_days=365) == []


# ---------------------------------------------------------------------------
# region_filter parameter
# ---------------------------------------------------------------------------


class TestRegionFilter:
    def test_region_filter_string_accepted(self):
        assert _invoke(region_filter="us-central1") == []

    def test_region_filter_none_accepted(self):
        assert _invoke(region_filter=None) == []


# ---------------------------------------------------------------------------
# HTTP error handling via public API
# ---------------------------------------------------------------------------


class TestHttpErrors:
    def test_403_raises_permission_error(self):
        with pytest.raises(PermissionError):
            _invoke_with_session(_session(_err(403)))

    def test_403_message_mentions_permission(self):
        with pytest.raises(PermissionError, match="notebooks.instances.list"):
            _invoke_with_session(_session(_err(403)))

    def test_403_message_mentions_role(self):
        with pytest.raises(PermissionError, match="roles/notebooks.viewer"):
            _invoke_with_session(_session(_err(403)))

    def test_404_returns_empty_list(self):
        assert _invoke_with_session(_session(_err(404))) == []

    def test_404_no_warning_emitted(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(_session(_err(404)))
        assert not any(issubclass(w.category, UserWarning) for w in caught)

    def test_400_returns_empty_list(self):
        assert _invoke_with_session(_session(_err(400))) == []

    def test_400_emits_user_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(_session(_err(400)))
        assert any(issubclass(w.category, UserWarning) for w in caught)

    def test_400_warning_mentions_status_code(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(_session(_err(400)))
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert "400" in msgs

    def test_400_warning_mentions_project(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(_session(_err(400)))
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert _PROJECT in msgs

    def test_500_returns_empty_list(self):
        assert _invoke_with_session(_session(_err(500))) == []

    def test_500_emits_user_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(_session(_err(500)))
        assert any(issubclass(w.category, UserWarning) for w in caught)

    def test_500_warning_mentions_status_code(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(_session(_err(500)))
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert "500" in msgs

    def test_503_warning_mentions_status_code(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(_session(_err(503)))
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert "503" in msgs

    def test_5xx_warning_mentions_project(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(_session(_err(500)))
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert _PROJECT in msgs

    def test_network_error_returns_empty_list(self):
        session = MagicMock()
        session.get.side_effect = ConnectionError("timeout")
        assert _invoke_with_session(session) == []

    def test_network_error_emits_user_warning(self):
        session = MagicMock()
        session.get.side_effect = ConnectionError("timeout")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(session)
        assert any(issubclass(w.category, UserWarning) for w in caught)

    def test_network_error_warning_mentions_project(self):
        session = MagicMock()
        session.get.side_effect = OSError("no route to host")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(session)
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert _PROJECT in msgs

    def test_network_error_warning_mentions_exception_type(self):
        session = MagicMock()
        session.get.side_effect = ConnectionError("dropped")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _invoke_with_session(session)
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert "ConnectionError" in msgs


# ---------------------------------------------------------------------------
# _list_instances — direct unit tests
# ---------------------------------------------------------------------------


class TestListInstancesBasic:
    def test_empty_response(self):
        instances, unreachable, failed = _list_instances(_session(_ok()), _PROJECT)
        assert instances == []
        assert unreachable == []
        assert failed is False

    def test_instances_returned(self):
        inst = {"name": "projects/p/locations/us-central1/instances/i1", "state": "ACTIVE"}
        instances, _, _ = _list_instances(_session(_ok({"instances": [inst]})), _PROJECT)
        assert instances == [inst]

    def test_multiple_instances_in_single_page(self):
        inst_list = [
            {"name": f"projects/p/locations/us-central1/instances/i{i}", "state": "ACTIVE"}
            for i in range(3)
        ]
        instances, _, _ = _list_instances(_session(_ok({"instances": inst_list})), _PROJECT)
        assert instances == inst_list

    def test_page_size_100_in_initial_request(self):
        session = _session(_ok())
        _list_instances(session, _PROJECT)
        params = session.get.call_args.kwargs["params"]
        assert params["pageSize"] == 100

    def test_url_contains_project_id(self):
        session = _session(_ok())
        _list_instances(session, "target-project-xyz")
        url = session.get.call_args.args[0]
        assert "target-project-xyz" in url

    def test_url_uses_wildcard_location(self):
        session = _session(_ok())
        _list_instances(session, _PROJECT)
        url = session.get.call_args.args[0]
        assert "locations/-" in url

    def test_url_uses_v2_api(self):
        session = _session(_ok())
        _list_instances(session, _PROJECT)
        url = session.get.call_args.args[0]
        assert "/v2/" in url


class TestListInstancesPagination:
    def test_two_pages_accumulates_instances(self):
        inst1 = {"name": "projects/p/locations/us-central1/instances/i1", "state": "ACTIVE"}
        inst2 = {"name": "projects/p/locations/us-central1/instances/i2", "state": "ACTIVE"}
        session = _session(
            _ok({"instances": [inst1], "nextPageToken": "tok1"}),
            _ok({"instances": [inst2]}),
        )
        instances, _, _ = _list_instances(session, _PROJECT)
        assert instances == [inst1, inst2]

    def test_three_pages_all_accumulated(self):
        def _inst(i):
            return {"name": f"projects/p/locations/us-central1/instances/i{i}", "state": "ACTIVE"}
        session = _session(
            _ok({"instances": [_inst(1)], "nextPageToken": "t1"}),
            _ok({"instances": [_inst(2)], "nextPageToken": "t2"}),
            _ok({"instances": [_inst(3)]}),
        )
        instances, _, _ = _list_instances(session, _PROJECT)
        assert len(instances) == 3

    def test_page_token_forwarded_on_second_request(self):
        session = _session(
            _ok({"nextPageToken": "tok-abc"}),
            _ok({}),
        )
        _list_instances(session, _PROJECT)
        second_params = session.get.call_args_list[1].kwargs["params"]
        assert second_params.get("pageToken") == "tok-abc"

    def test_page_token_forwarded_on_third_request(self):
        session = _session(
            _ok({"nextPageToken": "t1"}),
            _ok({"nextPageToken": "t2"}),
            _ok({}),
        )
        _list_instances(session, _PROJECT)
        third_params = session.get.call_args_list[2].kwargs["params"]
        assert third_params.get("pageToken") == "t2"

    def test_stops_when_no_next_token(self):
        session = _session(_ok({}))
        _list_instances(session, _PROJECT)
        assert session.get.call_count == 1

    def test_exactly_two_calls_for_two_pages(self):
        session = _session(
            _ok({"nextPageToken": "t1"}),
            _ok({}),
        )
        _list_instances(session, _PROJECT)
        assert session.get.call_count == 2


class TestListInstancesUnreachable:
    def test_single_unreachable_location_collected(self):
        session = _session(_ok({"unreachable": ["asia-east1"]}))
        _, unreachable, _ = _list_instances(session, _PROJECT)
        assert "asia-east1" in unreachable

    def test_multiple_unreachable_locations(self):
        session = _session(_ok({"unreachable": ["asia-east1", "europe-west3"]}))
        _, unreachable, _ = _list_instances(session, _PROJECT)
        assert "asia-east1" in unreachable
        assert "europe-west3" in unreachable

    def test_unreachable_deduplicated_across_pages(self):
        session = _session(
            _ok({"unreachable": ["asia-east1"], "nextPageToken": "t1"}),
            _ok({"unreachable": ["asia-east1"]}),
        )
        _, unreachable, _ = _list_instances(session, _PROJECT)
        assert unreachable.count("asia-east1") == 1

    def test_empty_string_in_unreachable_skipped(self):
        session = _session(_ok({"unreachable": ["", "us-east1"]}))
        _, unreachable, _ = _list_instances(session, _PROJECT)
        assert "" not in unreachable
        assert "us-east1" in unreachable

    def test_no_unreachable_when_field_absent(self):
        session = _session(_ok({}))
        _, unreachable, _ = _list_instances(session, _PROJECT)
        assert unreachable == []

    def test_unreachable_from_multiple_pages_merged(self):
        session = _session(
            _ok({"unreachable": ["asia-east1"], "nextPageToken": "t1"}),
            _ok({"unreachable": ["europe-west3"]}),
        )
        _, unreachable, _ = _list_instances(session, _PROJECT)
        assert "asia-east1" in unreachable
        assert "europe-west3" in unreachable


class TestListInstancesErrors:
    def test_403_raises_permission_error(self):
        with pytest.raises(PermissionError, match="notebooks.instances.list"):
            _list_instances(_session(_err(403)), _PROJECT)

    def test_404_returns_empty_clean(self):
        instances, unreachable, failed = _list_instances(_session(_err(404)), _PROJECT)
        assert instances == []
        assert unreachable == []
        assert failed is False

    def test_400_returns_empty_with_discovery_failed(self):
        instances, unreachable, failed = _list_instances(_session(_err(400)), _PROJECT)
        assert instances == []
        assert unreachable == []
        assert failed is True

    def test_500_sets_discovery_failed(self):
        _, _, failed = _list_instances(_session(_err(500)), _PROJECT)
        assert failed is True

    def test_503_sets_discovery_failed(self):
        _, _, failed = _list_instances(_session(_err(503)), _PROJECT)
        assert failed is True

    def test_5xx_preserves_instances_from_earlier_pages(self):
        """Instances already fetched before a 5xx error must be returned."""
        inst = {"name": "projects/p/locations/us-central1/instances/i1", "state": "ACTIVE"}
        session = _session(
            _ok({"instances": [inst], "nextPageToken": "t1"}),
            _err(503),
        )
        instances, _, failed = _list_instances(session, _PROJECT)
        assert instances == [inst]
        assert failed is True

    def test_network_error_sets_discovery_failed(self):
        session = MagicMock()
        session.get.side_effect = ConnectionError("timeout")
        _, _, failed = _list_instances(session, _PROJECT)
        assert failed is True

    def test_network_error_preserves_earlier_instances(self):
        inst = {"name": "projects/p/locations/us-central1/instances/i1", "state": "ACTIVE"}
        session = _session(
            _ok({"instances": [inst], "nextPageToken": "t1"}),
        )
        session.get.side_effect = [
            _ok({"instances": [inst], "nextPageToken": "t1"}),
            ConnectionError("dropped"),
        ]
        instances, _, failed = _list_instances(session, _PROJECT)
        assert instances == [inst]
        assert failed is True

    def test_400_emits_warning_with_project(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _list_instances(_session(_err(400)), _PROJECT)
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert _PROJECT in msgs

    def test_500_emits_warning_with_status_code(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _list_instances(_session(_err(500)), _PROJECT)
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert "500" in msgs

    def test_network_error_emits_warning_with_project(self):
        session = MagicMock()
        session.get.side_effect = OSError("no route to host")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _list_instances(session, _PROJECT)
        msgs = " ".join(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert _PROJECT in msgs


# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------


class TestRuleMetadata:
    def test_rule_id(self):
        assert RULE_METADATA["id"] == "gcp.vertex.workbench.idle"

    def test_category(self):
        assert RULE_METADATA["category"] == "ai"

    def test_service(self):
        assert RULE_METADATA["service"] == "notebooks"

    def test_cost_impact(self):
        assert RULE_METADATA["cost_impact"] == "high"

    def test_rule_id_attribute_on_function(self):
        assert find_idle_workbench_instances.RULE_ID == "gcp.vertex.workbench.idle"
