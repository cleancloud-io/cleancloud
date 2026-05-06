"""
Tests for gcp.vertex.workbench.idle rule.

The rule is EMITTING_DISABLED and always returns an empty List[Finding].
Classification is performed and surfaced via UserWarning:
  - PARTIAL scope: unreachable[] locations or discovery failures.
  - NOT_EVALUABLE: ACTIVE candidates warn with resource names (NO_SIGNAL).
  - INVALID: malformed name or missing state; counted, not warned.
  - OUT_OF_SCOPE: non-ACTIVE instances; excluded silently.

Coverage:
  find_idle_workbench_instances (public API):
    - always returns []
    - idle_days validation
    - region_filter (exact match, no case folding)
    - ACTIVE instances warn NOT_EVALUABLE/NO_SIGNAL
    - unreachable locations warn PARTIAL scope
    - discovery_failed warns PARTIAL scope
    - INVALID resources (name/state) counted, not surfaced individually
    - OUT_OF_SCOPE (non-ACTIVE) excluded silently
    - 403/404/400/5xx/network HTTP error handling

  _list_instances (internal):
    - pagination, pageToken forwarding, pageSize
    - unreachable[] accumulation and deduplication
    - 404/400/5xx/network/403 error handling
    - URL shape (project ID, locations/- wildcard, v2)
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
_LOCATION = "us-central1"
_INSTANCE_NAME = f"projects/{_PROJECT}/locations/{_LOCATION}/instances/wb-1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(body: dict = None):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = body or {}
    resp.raise_for_status.return_value = None
    return resp


def _err(status_code: int):
    resp = MagicMock()
    resp.status_code = status_code
    return resp


def _session(*responses):
    mock = MagicMock()
    mock.get.side_effect = list(responses)
    return mock


def _run(instances, unreachable=None, discovery_failed=False, **kwargs):
    """
    Invoke find_idle_workbench_instances with _list_instances patched to return
    (instances, unreachable, discovery_failed).
    """
    with patch(
        "cleancloud.providers.gcp.rules.ai.workbench_idle._list_instances",
        return_value=(instances, unreachable or [], discovery_failed),
    ):
        return find_idle_workbench_instances(
            project_id=_PROJECT, credentials=MagicMock(), **kwargs
        )


def _run_with_warnings(instances, unreachable=None, discovery_failed=False, **kwargs):
    """Like _run but also captures warnings."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = _run(instances, unreachable, discovery_failed, **kwargs)
    return result, [w for w in caught if issubclass(w.category, UserWarning)]


def _active(name=_INSTANCE_NAME):
    return {"name": name, "state": "ACTIVE"}


def _invoke_http(mock_session, **kwargs):
    with patch(
        "cleancloud.providers.gcp.rules.ai.workbench_idle.AuthorizedSession",
        return_value=mock_session,
    ):
        return find_idle_workbench_instances(
            project_id=_PROJECT, credentials=MagicMock(), **kwargs
        )


def _invoke_http_with_warnings(mock_session, **kwargs):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = _invoke_http(mock_session, **kwargs)
    return result, [w for w in caught if issubclass(w.category, UserWarning)]


# ---------------------------------------------------------------------------
# Return value — always []
# ---------------------------------------------------------------------------


class TestReturnValue:
    def test_returns_list(self):
        assert isinstance(_run([]), list)

    def test_always_empty_no_instances(self):
        assert _run([]) == []

    def test_always_empty_with_active_instances(self):
        assert _run([_active()]) == []

    def test_always_empty_with_multiple_active(self):
        instances = [
            _active(f"projects/{_PROJECT}/locations/{_LOCATION}/instances/wb-{i}")
            for i in range(5)
        ]
        assert _run(instances) == []

    def test_always_empty_with_stopped_instances(self):
        assert _run([{"name": _INSTANCE_NAME, "state": "STOPPED"}]) == []


# ---------------------------------------------------------------------------
# idle_days validation
# ---------------------------------------------------------------------------


class TestIdleDaysValidation:
    def test_zero_raises(self):
        with pytest.raises(ValueError, match="idle_days must be >= 1"):
            find_idle_workbench_instances(
                project_id=_PROJECT, credentials=MagicMock(), idle_days=0
            )

    def test_negative_raises(self):
        with pytest.raises(ValueError, match="idle_days must be >= 1"):
            find_idle_workbench_instances(
                project_id=_PROJECT, credentials=MagicMock(), idle_days=-1
            )

    def test_error_message_includes_bad_value(self):
        with pytest.raises(ValueError, match="-3"):
            find_idle_workbench_instances(
                project_id=_PROJECT, credentials=MagicMock(), idle_days=-3
            )

    def test_one_is_valid(self):
        assert _run([], idle_days=1) == []

    def test_default_14_is_valid(self):
        assert _run([]) == []

    def test_large_value_is_valid(self):
        assert _run([], idle_days=365) == []


# ---------------------------------------------------------------------------
# NOT_EVALUABLE / NO_SIGNAL warning for ACTIVE candidates
# ---------------------------------------------------------------------------


class TestNotEvaluableWarning:
    def test_active_instance_emits_warning(self):
        _, warns = _run_with_warnings([_active()])
        assert len(warns) == 1

    def test_warning_is_user_warning(self):
        _, warns = _run_with_warnings([_active()])
        assert issubclass(warns[0].category, UserWarning)

    def test_warning_mentions_no_signal(self):
        _, warns = _run_with_warnings([_active()])
        assert "NO_SIGNAL" in str(warns[0].message)

    def test_warning_mentions_emitting_disabled(self):
        _, warns = _run_with_warnings([_active()])
        assert "EMITTING_DISABLED" in str(warns[0].message)

    def test_warning_mentions_project(self):
        _, warns = _run_with_warnings([_active()])
        assert _PROJECT in str(warns[0].message)

    def test_warning_mentions_resource_name(self):
        _, warns = _run_with_warnings([_active()])
        assert _INSTANCE_NAME in str(warns[0].message)

    def test_warning_mentions_count(self):
        instances = [
            _active(f"projects/{_PROJECT}/locations/{_LOCATION}/instances/wb-{i}")
            for i in range(3)
        ]
        _, warns = _run_with_warnings(instances)
        assert "3" in str(warns[0].message)

    def test_warning_mentions_all_resource_names_when_under_cap(self):
        inst1 = _active(f"projects/{_PROJECT}/locations/{_LOCATION}/instances/wb-1")
        inst2 = _active(f"projects/{_PROJECT}/locations/{_LOCATION}/instances/wb-2")
        _, warns = _run_with_warnings([inst1, inst2])
        msg = str(warns[0].message)
        assert "wb-1" in msg
        assert "wb-2" in msg

    def test_warning_caps_name_list_at_five(self):
        instances = [
            _active(f"projects/{_PROJECT}/locations/{_LOCATION}/instances/wb-{i}")
            for i in range(8)
        ]
        _, warns = _run_with_warnings(instances)
        msg = str(warns[0].message)
        assert "+3 more" in msg

    def test_warning_no_overflow_label_when_at_cap(self):
        instances = [
            _active(f"projects/{_PROJECT}/locations/{_LOCATION}/instances/wb-{i}")
            for i in range(5)
        ]
        _, warns = _run_with_warnings(instances)
        assert "more" not in str(warns[0].message)

    def test_no_warning_when_no_active_instances(self):
        _, warns = _run_with_warnings([])
        assert len(warns) == 0

    def test_no_warning_for_stopped_instances(self):
        _, warns = _run_with_warnings([{"name": _INSTANCE_NAME, "state": "STOPPED"}])
        assert len(warns) == 0


# ---------------------------------------------------------------------------
# PARTIAL scope warning — unreachable locations
# ---------------------------------------------------------------------------


class TestPartialScopeUnreachable:
    def test_unreachable_location_emits_warning(self):
        _, warns = _run_with_warnings([], unreachable=["asia-east1"])
        assert len(warns) == 1

    def test_warning_mentions_partial(self):
        _, warns = _run_with_warnings([], unreachable=["asia-east1"])
        assert "PARTIAL" in str(warns[0].message)

    def test_warning_mentions_unreachable_location(self):
        _, warns = _run_with_warnings([], unreachable=["asia-east1"])
        assert "asia-east1" in str(warns[0].message)

    def test_warning_mentions_project(self):
        _, warns = _run_with_warnings([], unreachable=["us-east1"])
        assert _PROJECT in str(warns[0].message)

    def test_multiple_unreachable_locations_in_single_warning(self):
        _, warns = _run_with_warnings([], unreachable=["asia-east1", "europe-west3"])
        assert len(warns) == 1
        msg = str(warns[0].message)
        assert "asia-east1" in msg
        assert "europe-west3" in msg

    def test_no_partial_warning_when_no_unreachable(self):
        _, warns = _run_with_warnings([])
        assert len(warns) == 0


# ---------------------------------------------------------------------------
# PARTIAL scope warning — discovery_failed
# ---------------------------------------------------------------------------


class TestPartialScopeDiscoveryFailed:
    def test_discovery_failed_emits_warning(self):
        _, warns = _run_with_warnings([], discovery_failed=True)
        assert len(warns) == 1

    def test_warning_mentions_partial(self):
        _, warns = _run_with_warnings([], discovery_failed=True)
        assert "PARTIAL" in str(warns[0].message)

    def test_warning_mentions_project(self):
        _, warns = _run_with_warnings([], discovery_failed=True)
        assert _PROJECT in str(warns[0].message)

    def test_both_partial_and_not_evaluable_can_warn(self):
        """ACTIVE instances + unreachable locations = two warnings."""
        _, warns = _run_with_warnings([_active()], unreachable=["asia-east1"])
        assert len(warns) == 2

    def test_discovery_failed_and_active_instances_both_warn(self):
        _, warns = _run_with_warnings([_active()], discovery_failed=True)
        assert len(warns) == 2


# ---------------------------------------------------------------------------
# INVALID resource classification
# ---------------------------------------------------------------------------


class TestInvalidResources:
    def test_empty_name_emits_invalid_warning(self):
        inst = {"name": "", "state": "ACTIVE"}
        _, warns = _run_with_warnings([inst])
        assert any("INVALID" in str(w.message) for w in warns)

    def test_missing_name_emits_invalid_warning(self):
        inst = {"state": "ACTIVE"}
        _, warns = _run_with_warnings([inst])
        assert any("INVALID" in str(w.message) for w in warns)

    def test_wrong_pattern_emits_invalid_warning(self):
        inst = {"name": "projects/p/locations/l/wrongType/id", "state": "ACTIVE"}
        _, warns = _run_with_warnings([inst])
        assert any("INVALID" in str(w.message) for w in warns)

    def test_extra_path_segments_emits_invalid_warning(self):
        inst = {"name": f"{_INSTANCE_NAME}/extra", "state": "ACTIVE"}
        _, warns = _run_with_warnings([inst])
        assert any("INVALID" in str(w.message) for w in warns)

    def test_empty_state_emits_invalid_warning(self):
        inst = {"name": _INSTANCE_NAME, "state": ""}
        _, warns = _run_with_warnings([inst])
        assert any("INVALID" in str(w.message) for w in warns)

    def test_missing_state_emits_invalid_warning(self):
        inst = {"name": _INSTANCE_NAME}
        _, warns = _run_with_warnings([inst])
        assert any("INVALID" in str(w.message) for w in warns)

    def test_invalid_warning_mentions_count(self):
        bad1 = {"name": "", "state": "ACTIVE"}
        bad2 = {"name": _INSTANCE_NAME, "state": ""}
        _, warns = _run_with_warnings([bad1, bad2])
        invalid_warn = next(w for w in warns if "INVALID" in str(w.message))
        assert "2" in str(invalid_warn.message)

    def test_invalid_warning_mentions_project(self):
        inst = {"name": "", "state": "ACTIVE"}
        _, warns = _run_with_warnings([inst])
        invalid_warn = next(w for w in warns if "INVALID" in str(w.message))
        assert _PROJECT in str(invalid_warn.message)

    def test_no_invalid_warning_when_all_valid(self):
        _, warns = _run_with_warnings([_active()])
        assert not any("INVALID" in str(w.message) for w in warns)

    def test_invalid_not_in_not_evaluable_candidates(self):
        """INVALID records must not appear in the NOT_EVALUABLE warning."""
        bad = {"name": "", "state": "ACTIVE"}
        good = _active()
        _, warns = _run_with_warnings([bad, good])
        not_eval_warn = next(w for w in warns if "NO_SIGNAL" in str(w.message))
        assert _INSTANCE_NAME in str(not_eval_warn.message)
        # count should be 1 (only the valid ACTIVE instance)
        assert "1 ACTIVE" in str(not_eval_warn.message)


# ---------------------------------------------------------------------------
# OUT_OF_SCOPE resources — non-ACTIVE states
# ---------------------------------------------------------------------------


class TestOutOfScope:
    def test_stopped_excluded_silently(self):
        _, warns = _run_with_warnings([{"name": _INSTANCE_NAME, "state": "STOPPED"}])
        assert len(warns) == 0

    def test_suspended_excluded_silently(self):
        _, warns = _run_with_warnings([{"name": _INSTANCE_NAME, "state": "SUSPENDED"}])
        assert len(warns) == 0

    def test_provisioning_excluded_silently(self):
        _, warns = _run_with_warnings(
            [{"name": _INSTANCE_NAME, "state": "PROVISIONING"}]
        )
        assert len(warns) == 0

    def test_mixed_active_and_stopped_only_active_warned(self):
        active = _active(f"projects/{_PROJECT}/locations/{_LOCATION}/instances/active")
        stopped = {"name": f"projects/{_PROJECT}/locations/{_LOCATION}/instances/stopped",
                   "state": "STOPPED"}
        _, warns = _run_with_warnings([active, stopped])
        assert len(warns) == 1
        msg = str(warns[0].message)
        assert "active" in msg
        assert "stopped" not in msg


# ---------------------------------------------------------------------------
# Region filter — exact string equality, no case folding
# ---------------------------------------------------------------------------


class TestRegionFilter:
    def test_matching_region_produces_warning(self):
        _, warns = _run_with_warnings([_active()], region_filter=_LOCATION)
        assert len(warns) == 1

    def test_non_matching_region_excluded(self):
        _, warns = _run_with_warnings([_active()], region_filter="europe-west1")
        assert len(warns) == 0

    def test_uppercase_region_does_not_match(self):
        """Exact equality — 'US-CENTRAL1' must NOT match 'us-central1'."""
        _, warns = _run_with_warnings([_active()], region_filter="US-CENTRAL1")
        assert len(warns) == 0

    def test_none_region_filter_includes_all(self):
        inst1 = _active("projects/p/locations/europe-west1/instances/i1")
        inst2 = _active("projects/p/locations/us-central1/instances/i2")
        _, warns = _run_with_warnings([inst1, inst2], region_filter=None)
        assert len(warns) == 1
        msg = str(warns[0].message)
        assert "i1" in msg
        assert "i2" in msg


# ---------------------------------------------------------------------------
# HTTP error handling (via AuthorizedSession)
# ---------------------------------------------------------------------------


class TestHttpErrors:
    def test_403_raises_permission_error(self):
        with pytest.raises(PermissionError, match="notebooks.instances.list"):
            _invoke_http(_session(_err(403)))

    def test_403_mentions_role(self):
        with pytest.raises(PermissionError, match="roles/notebooks.viewer"):
            _invoke_http(_session(_err(403)))

    def test_404_returns_empty_no_partial_warning(self):
        result, warns = _invoke_http_with_warnings(_session(_err(404)))
        assert result == []
        assert len(warns) == 0

    def test_400_returns_empty_with_partial_warning(self):
        result, warns = _invoke_http_with_warnings(_session(_err(400)))
        assert result == []
        # _list_instances warns about 400, caller warns about PARTIAL
        msgs = " ".join(str(w.message) for w in warns)
        assert "400" in msgs or "PARTIAL" in msgs

    def test_500_returns_empty_with_warning(self):
        result, warns = _invoke_http_with_warnings(_session(_err(500)))
        assert result == []
        msgs = " ".join(str(w.message) for w in warns)
        assert "500" in msgs or "PARTIAL" in msgs

    def test_503_returns_empty_with_warning(self):
        result, warns = _invoke_http_with_warnings(_session(_err(503)))
        assert result == []
        assert len(warns) >= 1

    def test_network_error_returns_empty_with_warning(self):
        session = MagicMock()
        session.get.side_effect = ConnectionError("timeout")
        result, warns = _invoke_http_with_warnings(session)
        assert result == []
        assert len(warns) >= 1


# ---------------------------------------------------------------------------
# _list_instances — direct unit tests
# ---------------------------------------------------------------------------


class TestListInstancesBasic:
    def test_empty_response(self):
        instances, unreachable, failed = _list_instances(_session(_ok()), _PROJECT)
        assert instances == [] and unreachable == [] and failed is False

    def test_instances_returned(self):
        inst = {"name": _INSTANCE_NAME, "state": "ACTIVE"}
        instances, _, _ = _list_instances(_session(_ok({"instances": [inst]})), _PROJECT)
        assert instances == [inst]

    def test_page_size_100_in_initial_request(self):
        session = _session(_ok())
        _list_instances(session, _PROJECT)
        assert session.get.call_args.kwargs["params"]["pageSize"] == 100

    def test_url_contains_project_id(self):
        session = _session(_ok())
        _list_instances(session, "target-project-xyz")
        assert "target-project-xyz" in session.get.call_args.args[0]

    def test_url_uses_wildcard_location(self):
        session = _session(_ok())
        _list_instances(session, _PROJECT)
        assert "locations/-" in session.get.call_args.args[0]

    def test_url_uses_v2_api(self):
        session = _session(_ok())
        _list_instances(session, _PROJECT)
        assert "/v2/" in session.get.call_args.args[0]


class TestListInstancesPagination:
    def test_two_pages_accumulates_instances(self):
        inst1 = {"name": f"projects/p/locations/us-central1/instances/i1", "state": "ACTIVE"}
        inst2 = {"name": f"projects/p/locations/us-central1/instances/i2", "state": "ACTIVE"}
        session = _session(
            _ok({"instances": [inst1], "nextPageToken": "tok1"}),
            _ok({"instances": [inst2]}),
        )
        instances, _, _ = _list_instances(session, _PROJECT)
        assert instances == [inst1, inst2]

    def test_three_pages_all_accumulated(self):
        pages = [
            _ok({"instances": [{"name": f"projects/p/locations/l/instances/i{i}", "state": "ACTIVE"}],
                 "nextPageToken": f"t{i}"} if i < 2 else
                {"instances": [{"name": f"projects/p/locations/l/instances/i{i}", "state": "ACTIVE"}]})
            for i in range(3)
        ]
        instances, _, _ = _list_instances(_session(*pages), _PROJECT)
        assert len(instances) == 3

    def test_page_token_forwarded_on_second_request(self):
        session = _session(_ok({"nextPageToken": "tok-abc"}), _ok({}))
        _list_instances(session, _PROJECT)
        assert session.get.call_args_list[1].kwargs["params"]["pageToken"] == "tok-abc"

    def test_stops_when_no_next_token(self):
        session = _session(_ok({}))
        _list_instances(session, _PROJECT)
        assert session.get.call_count == 1


class TestListInstancesUnreachable:
    def test_unreachable_location_collected(self):
        _, unreachable, _ = _list_instances(_session(_ok({"unreachable": ["asia-east1"]})), _PROJECT)
        assert "asia-east1" in unreachable

    def test_unreachable_deduplicated_across_pages(self):
        session = _session(
            _ok({"unreachable": ["asia-east1"], "nextPageToken": "t1"}),
            _ok({"unreachable": ["asia-east1"]}),
        )
        _, unreachable, _ = _list_instances(session, _PROJECT)
        assert unreachable.count("asia-east1") == 1

    def test_empty_string_in_unreachable_skipped(self):
        _, unreachable, _ = _list_instances(
            _session(_ok({"unreachable": ["", "us-east1"]})), _PROJECT
        )
        assert "" not in unreachable and "us-east1" in unreachable


class TestListInstancesErrors:
    def test_403_raises_permission_error(self):
        with pytest.raises(PermissionError, match="notebooks.instances.list"):
            _list_instances(_session(_err(403)), _PROJECT)

    def test_404_returns_clean_empty(self):
        instances, unreachable, failed = _list_instances(_session(_err(404)), _PROJECT)
        assert instances == [] and unreachable == [] and failed is False

    def test_400_sets_discovery_failed(self):
        _, _, failed = _list_instances(_session(_err(400)), _PROJECT)
        assert failed is True

    def test_500_sets_discovery_failed(self):
        _, _, failed = _list_instances(_session(_err(500)), _PROJECT)
        assert failed is True

    def test_5xx_preserves_earlier_instances(self):
        inst = {"name": _INSTANCE_NAME, "state": "ACTIVE"}
        session = _session(
            _ok({"instances": [inst], "nextPageToken": "t1"}),
            _err(503),
        )
        instances, _, failed = _list_instances(session, _PROJECT)
        assert instances == [inst] and failed is True

    def test_network_error_sets_discovery_failed(self):
        session = MagicMock()
        session.get.side_effect = ConnectionError("timeout")
        _, _, failed = _list_instances(session, _PROJECT)
        assert failed is True

    def test_network_error_preserves_earlier_instances(self):
        inst = {"name": _INSTANCE_NAME, "state": "ACTIVE"}
        session = MagicMock()
        session.get.side_effect = [
            _ok({"instances": [inst], "nextPageToken": "t1"}),
            ConnectionError("dropped"),
        ]
        instances, _, failed = _list_instances(session, _PROJECT)
        assert instances == [inst] and failed is True


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

    def test_rule_id_attribute(self):
        assert find_idle_workbench_instances.RULE_ID == "gcp.vertex.workbench.idle"
