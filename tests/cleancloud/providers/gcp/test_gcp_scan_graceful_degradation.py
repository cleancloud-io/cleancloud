"""
Tests for graceful degradation in GCP scan orchestration.

Verifies that:
- _scan_gcp_project handles PermissionError, PermissionDenied, GoogleAPICallError,
  and other rule failures without crashing the scan.
- scan_gcp_projects isolates project-level failures: one project failing does not
  affect other projects.
"""

from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import GoogleAPICallError, PermissionDenied

from cleancloud.core.finding import Finding
from cleancloud.providers.gcp.scan import (
    ProjectScanResult,
    _scan_gcp_project,
    scan_gcp_projects,
)


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        provider="gcp",
        rule_id="gcp.compute.disk.unattached",
        resource_type="gcp.compute.disk",
        resource_id="projects/p/zones/us-central1-a/disks/d",
        region="us-central1-a",
        title="Unattached disk",
        summary="Unattached disk",
        reason="No users",
    )
    defaults.update(kwargs)
    return MagicMock(spec=Finding, **defaults)


# ---------------------------------------------------------------------------
# Helper: rule factories
# ---------------------------------------------------------------------------


def _rule_returning(findings):
    """Return a callable that returns `findings` and has a human-readable name."""

    def rule(*, project_id, credentials, region_filter=None):
        return findings

    rule.__name__ = "mock_rule_ok"
    return rule


def _rule_raising(exc):
    """Return a callable that raises `exc`."""

    def rule(*, project_id, credentials, region_filter=None):
        raise exc

    rule.__name__ = "mock_rule_error"
    return rule


# ---------------------------------------------------------------------------
# Patch GCP_RULES for each test using monkeypatch
# ---------------------------------------------------------------------------


def test_all_rules_succeed(monkeypatch):
    """When all rules succeed, findings are returned and skipped_rules is empty."""
    f1 = _make_finding()
    f2 = _make_finding()
    monkeypatch.setattr(
        "cleancloud.providers.gcp.scan.GCP_RULES",
        [_rule_returning([f1]), _rule_returning([f2])],
    )
    findings, skipped, _, _ = _scan_gcp_project(
        project_id="proj-1",
        project_name="Project One",
        credentials=MagicMock(),
        region_filter=None,
    )
    assert len(findings) == 2
    assert skipped == []


def test_permission_error_recorded_as_skipped(monkeypatch):
    """PermissionError from a rule is recorded as a skipped rule, not raised."""
    monkeypatch.setattr(
        "cleancloud.providers.gcp.scan.GCP_RULES",
        [
            _rule_returning([_make_finding()]),
            _rule_raising(PermissionError("compute.disks.list denied")),
        ],
    )
    findings, skipped, _, _ = _scan_gcp_project(
        project_id="proj-1",
        project_name="Project One",
        credentials=MagicMock(),
        region_filter=None,
    )
    assert len(findings) == 1
    assert len(skipped) == 1
    assert "compute.disks.list" in skipped[0]["missing_permissions"]
    assert skipped[0]["project_id"] == "proj-1"


def test_permission_denied_recorded_as_skipped(monkeypatch):
    """GCP PermissionDenied from a rule is also recorded as a skipped rule."""
    monkeypatch.setattr(
        "cleancloud.providers.gcp.scan.GCP_RULES",
        [
            _rule_raising(PermissionDenied("403 compute.instances.list denied")),
        ],
    )
    findings, skipped, _, _ = _scan_gcp_project(
        project_id="proj-2",
        project_name="Project Two",
        credentials=MagicMock(),
        region_filter=None,
    )
    assert findings == []
    assert len(skipped) == 1
    assert "GCP permission denied" in skipped[0]["missing_permissions"]


def test_google_api_error_counted_but_not_skipped(monkeypatch):
    """A non-permission GoogleAPICallError increments failure count but doesn't skip."""
    err = GoogleAPICallError("Internal error")

    monkeypatch.setattr(
        "cleancloud.providers.gcp.scan.GCP_RULES",
        [
            _rule_returning([_make_finding()]),
            _rule_raising(err),
        ],
    )
    findings, skipped, _, _ = _scan_gcp_project(
        project_id="proj-1",
        project_name="Project One",
        credentials=MagicMock(),
        region_filter=None,
    )
    # The successful rule still returns findings
    assert len(findings) == 1
    # API errors are not added to skipped_rules (they're rule failures, not perm failures)
    assert skipped == []


def test_all_rules_fail_raises_runtime_error(monkeypatch):
    """If every rule fails with a non-permission error, RuntimeError is raised."""
    err = RuntimeError("network timeout")

    monkeypatch.setattr(
        "cleancloud.providers.gcp.scan.GCP_RULES",
        [_rule_raising(err), _rule_raising(err)],
    )
    with pytest.raises(RuntimeError, match="All"):
        _scan_gcp_project(
            project_id="proj-fail",
            project_name="Failing Project",
            credentials=MagicMock(),
            region_filter=None,
        )


def test_mixed_outcomes(monkeypatch):
    """A mix of success, PermissionError, and API error produces correct output."""
    monkeypatch.setattr(
        "cleancloud.providers.gcp.scan.GCP_RULES",
        [
            _rule_returning([_make_finding()]),
            _rule_raising(PermissionError("needs compute.viewer")),
            _rule_raising(GoogleAPICallError("transient error")),
        ],
    )
    findings, skipped, _, _ = _scan_gcp_project(
        project_id="proj-mix",
        project_name="Mixed Project",
        credentials=MagicMock(),
        region_filter=None,
    )
    assert len(findings) == 1
    assert len(skipped) == 1


def test_account_id_and_name_set_on_findings(monkeypatch):
    """Findings returned by rules have account_id and account_name set."""
    mock_finding = MagicMock()

    def rule(*, project_id, credentials, region_filter=None):
        return [mock_finding]

    rule.__name__ = "mock_rule"

    monkeypatch.setattr("cleancloud.providers.gcp.scan.GCP_RULES", [rule])
    _scan_gcp_project(
        project_id="proj-tag",
        project_name="Tagged Project",
        credentials=MagicMock(),
        region_filter=None,
    )
    assert mock_finding.account_id == "proj-tag"
    assert mock_finding.account_name == "Tagged Project"


def test_only_skipped_rules_no_error_does_not_raise(monkeypatch):
    """If all rules are PermissionError (all skipped, none failed), no RuntimeError raised."""
    monkeypatch.setattr(
        "cleancloud.providers.gcp.scan.GCP_RULES",
        [
            _rule_raising(PermissionError("perm 1")),
            _rule_raising(PermissionError("perm 2")),
        ],
    )
    # Should not raise — rules were skipped, not failed
    findings, skipped, _, _ = _scan_gcp_project(
        project_id="proj-noperms",
        project_name="No Perms Project",
        credentials=MagicMock(),
        region_filter=None,
    )
    assert findings == []
    assert len(skipped) == 2


# ---------------------------------------------------------------------------
# ProjectScanResult unit tests
# ---------------------------------------------------------------------------


def test_project_scan_result_estimated_cost():
    """estimated_monthly_cost sums findings with non-None costs."""
    f1 = MagicMock(estimated_monthly_cost_usd=10.0)
    f2 = MagicMock(estimated_monthly_cost_usd=None)
    f3 = MagicMock(estimated_monthly_cost_usd=5.50)

    result = ProjectScanResult(
        project_id="p1",
        project_name="Proj 1",
        status="success",
        findings=[f1, f2, f3],
    )
    assert result.estimated_monthly_cost == 15.50


# ---------------------------------------------------------------------------
# Project-level isolation: one project failing must not stop others
# ---------------------------------------------------------------------------


def _make_scan_project_fn(raise_exc=None, findings=None):
    """
    Return a drop-in replacement for _scan_gcp_project.
    Either raises `raise_exc` or returns (findings, []).
    """

    def fn(*, project_id, project_name, credentials, region_filter):
        if raise_exc is not None:
            raise raise_exc
        return findings or [], [], 1, 0

    return fn


def test_one_project_failure_does_not_stop_others(monkeypatch):
    """
    If one project's scan raises, the other projects still complete and their
    findings are returned. The failed project is recorded as status='failed'.
    """
    good_finding = MagicMock()

    call_order = []

    def scan_project(*, project_id, project_name, credentials, region_filter, rules=None):
        call_order.append(project_id)
        if project_id == "proj-bad":
            raise RuntimeError("All rules failed")
        return [good_finding], [], 1, 0

    monkeypatch.setattr("cleancloud.providers.gcp.scan._scan_gcp_project", scan_project)

    results = scan_gcp_projects(
        project_ids=["proj-good-1", "proj-bad", "proj-good-2"],
        project_name_map={
            "proj-good-1": "Good One",
            "proj-bad": "Bad Project",
            "proj-good-2": "Good Two",
        },
        credentials=MagicMock(),
        region_filter=None,
        concurrency=3,
    )

    statuses = {r.project_id: r.status for r in results}

    assert statuses["proj-good-1"] == "success"
    assert statuses["proj-good-2"] == "success"
    assert statuses["proj-bad"] == "failed"

    # All three projects were attempted
    assert len(results) == 3

    # Good projects' findings are present
    all_findings = [f for r in results for f in r.findings]
    assert len(all_findings) == 2


def test_all_projects_fail_returns_all_as_failed(monkeypatch):
    """Every project failing still returns a result entry for each — no exception raised."""

    def scan_project(*, project_id, project_name, credentials, region_filter, rules=None):
        raise RuntimeError("total failure")

    monkeypatch.setattr("cleancloud.providers.gcp.scan._scan_gcp_project", scan_project)

    results = scan_gcp_projects(
        project_ids=["p1", "p2", "p3"],
        project_name_map={"p1": "P1", "p2": "P2", "p3": "P3"},
        credentials=MagicMock(),
        region_filter=None,
        concurrency=3,
    )

    assert len(results) == 3
    assert all(r.status == "failed" for r in results)
    assert all(r.error for r in results)


def test_failed_project_error_message_recorded(monkeypatch):
    """The error message from a failed project is stored in ProjectScanResult.error."""

    def scan_project(*, project_id, project_name, credentials, region_filter, rules=None):
        raise RuntimeError("quota exceeded")

    monkeypatch.setattr("cleancloud.providers.gcp.scan._scan_gcp_project", scan_project)

    results = scan_gcp_projects(
        project_ids=["proj-quota"],
        project_name_map={"proj-quota": "Quota Project"},
        credentials=MagicMock(),
        region_filter=None,
    )

    assert results[0].status == "failed"
    assert "quota exceeded" in results[0].error


def test_concurrency_respected(monkeypatch):
    """scan_gcp_projects caps workers at min(concurrency, len(project_ids))."""
    import threading

    peak_concurrent = [0]
    current = [0]
    lock = threading.Lock()

    def scan_project(*, project_id, project_name, credentials, region_filter, rules=None):
        with lock:
            current[0] += 1
            peak_concurrent[0] = max(peak_concurrent[0], current[0])
        # simulate work
        import time

        time.sleep(0.05)
        with lock:
            current[0] -= 1
        return [], [], 1, 0

    monkeypatch.setattr("cleancloud.providers.gcp.scan._scan_gcp_project", scan_project)

    scan_gcp_projects(
        project_ids=[f"proj-{i}" for i in range(6)],
        project_name_map={f"proj-{i}": f"Project {i}" for i in range(6)},
        credentials=MagicMock(),
        region_filter=None,
        concurrency=2,  # cap at 2
    )

    assert peak_concurrent[0] <= 2
