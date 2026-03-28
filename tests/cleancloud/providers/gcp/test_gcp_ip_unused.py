"""Unit tests for gcp.compute.ip.unused rule."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import NotFound, PermissionDenied

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.providers.gcp.rules.ip_unused import find_unused_static_ips


def _make_address(
    name,
    status="RESERVED",
    address="34.1.2.3",
    address_type="EXTERNAL",
    labels=None,
    network_tier="PREMIUM",
    purpose="",
    creation_timestamp="2024-01-01T00:00:00+00:00",
):
    return SimpleNamespace(
        name=name,
        status=status,
        address=address,
        address_type=address_type,
        labels=labels or {},
        network_tier=network_tier,
        purpose=purpose,
        creation_timestamp=creation_timestamp,
    )


def _make_scoped_address_list(addresses):
    return SimpleNamespace(addresses=addresses)


def _mock_clients(region_address_map, monkeypatch, global_addresses=None):
    """Patch both AddressesClient (regional) and GlobalAddressesClient."""
    regional_mock = MagicMock()
    regional_mock.aggregated_list.return_value = [
        (scope, _make_scoped_address_list(addresses))
        for scope, addresses in region_address_map.items()
    ]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.AddressesClient",
        lambda credentials: regional_mock,
    )

    global_mock = MagicMock()
    global_mock.list.return_value = global_addresses or []
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.GlobalAddressesClient",
        lambda credentials: global_mock,
    )
    return regional_mock, global_mock


def test_reserved_regional_ip_flagged(monkeypatch):
    """A RESERVED regional IP produces a finding."""
    _mock_clients(
        {"regions/us-central1": [_make_address("unused-ip", status="RESERVED")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.compute.ip.unused"
    assert f.provider == "gcp"
    assert "unused-ip" in f.resource_id
    assert f.region == "us-central1"
    assert f.confidence == ConfidenceLevel.HIGH
    assert f.estimated_monthly_cost_usd == 7.20
    assert f.details["scope"] == "regional"


def test_in_use_regional_ip_not_flagged(monkeypatch):
    """An IN_USE regional IP should not be flagged."""
    _mock_clients(
        {"regions/us-central1": [_make_address("active-ip", status="IN_USE")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_reserved_global_ip_flagged(monkeypatch):
    """A RESERVED global IP produces a finding with region='global'."""
    _mock_clients(
        {},
        monkeypatch,
        global_addresses=[_make_address("global-ip", status="RESERVED")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    f = findings[0]
    assert f.region == "global"
    assert f.details["scope"] == "global"
    assert "global-ip" in f.resource_id
    assert f.estimated_monthly_cost_usd == 7.20


def test_in_use_global_ip_not_flagged(monkeypatch):
    """An IN_USE global IP should not produce a finding."""
    _mock_clients(
        {},
        monkeypatch,
        global_addresses=[_make_address("global-active", status="IN_USE")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_regional_and_global_both_returned(monkeypatch):
    """Both regional and global RESERVED IPs are returned together."""
    _mock_clients(
        {"regions/us-east1": [_make_address("regional-ip", status="RESERVED")]},
        monkeypatch,
        global_addresses=[_make_address("global-ip", status="RESERVED")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 2
    scopes = {f.details["scope"] for f in findings}
    assert scopes == {"regional", "global"}


def test_region_filter_excludes_other_regions(monkeypatch):
    """region_filter restricts results to the matching region only."""
    _mock_clients(
        {
            "regions/us-central1": [_make_address("central-ip", status="RESERVED")],
            "regions/eu-west1": [_make_address("eu-ip", status="RESERVED")],
        },
        monkeypatch,
    )
    findings = find_unused_static_ips(
        project_id="proj-1", credentials=MagicMock(), region_filter="eu-west1"
    )

    assert len(findings) == 1
    assert "eu-ip" in findings[0].resource_id


def test_region_filter_skips_global_ips(monkeypatch):
    """When region_filter is set, global IPs are not scanned."""
    regional_mock, global_mock = _mock_clients(
        {"regions/us-central1": [_make_address("r-ip", status="RESERVED")]},
        monkeypatch,
        global_addresses=[_make_address("g-ip", status="RESERVED")],
    )
    find_unused_static_ips(
        project_id="proj-1", credentials=MagicMock(), region_filter="us-central1"
    )
    global_mock.list.assert_not_called()


def test_empty_region_skipped(monkeypatch):
    """A region scope with no addresses causes no error."""
    _mock_clients({"regions/us-central1": []}, monkeypatch)
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_regional_permission_denied_raises(monkeypatch):
    """PermissionDenied during regional iteration raises PermissionError."""
    regional_mock = MagicMock()
    regional_mock.aggregated_list.return_value = iter(
        _RaiseOnIter(PermissionDenied("compute.addresses.list denied"))
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.AddressesClient",
        lambda credentials: regional_mock,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.GlobalAddressesClient",
        lambda credentials: MagicMock(),
    )
    with pytest.raises(PermissionError, match="compute.addresses.list"):
        find_unused_static_ips(project_id="proj-1", credentials=MagicMock())


def test_regional_not_found_returns_empty(monkeypatch):
    """NotFound (Compute API not enabled) during regional scan returns empty list."""
    regional_mock = MagicMock()
    regional_mock.aggregated_list.return_value = iter(
        _RaiseOnIter(NotFound("Compute Engine API not enabled"))
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.AddressesClient",
        lambda credentials: regional_mock,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.GlobalAddressesClient",
        lambda credentials: MagicMock(),
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_global_permission_denied_returns_regional_only(monkeypatch):
    """PermissionDenied on global IPs is silently swallowed; regional findings returned."""
    global_mock = MagicMock()
    global_mock.list.return_value = iter(
        _RaiseOnIter(PermissionDenied("compute.globalAddresses.list denied"))
    )

    regional_mock = MagicMock()
    regional_mock.aggregated_list.return_value = [
        ("regions/us-central1", _make_scoped_address_list([_make_address("r-ip")]))
    ]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.AddressesClient",
        lambda credentials: regional_mock,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.GlobalAddressesClient",
        lambda credentials: global_mock,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    # Regional finding returned, global error silently swallowed
    assert len(findings) == 1
    assert findings[0].details["scope"] == "regional"


def test_labels_in_details(monkeypatch):
    """Labels on reserved IPs appear in finding details."""
    _mock_clients(
        {
            "regions/us-central1": [
                _make_address("labeled-ip", labels={"team": "infra", "env": "prod"})
            ]
        },
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["labels"] == {"team": "infra", "env": "prod"}


# ---------------------------------------------------------------------------
# is_regional, network_tier, and "estimated" wording
# ---------------------------------------------------------------------------


def test_regional_ip_has_is_regional_true(monkeypatch):
    """Regional IP details should include is_regional=True."""
    _mock_clients(
        {"regions/us-central1": [_make_address("r-ip")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["is_regional"] is True


def test_global_ip_has_is_regional_false(monkeypatch):
    """Global IP details should include is_regional=False."""
    _mock_clients(
        {},
        monkeypatch,
        global_addresses=[_make_address("g-ip")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["is_regional"] is False


def test_network_tier_in_details(monkeypatch):
    """network_tier should appear in finding details."""
    _mock_clients(
        {"regions/us-central1": [_make_address("std-ip", network_tier="STANDARD")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["network_tier"] == "STANDARD"


def test_standard_tier_cost_note_in_signals(monkeypatch):
    """STANDARD tier IPs should include a note about lower actual cost."""
    _mock_clients(
        {"regions/us-central1": [_make_address("std-ip", network_tier="STANDARD")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    not_checked = findings[0].evidence.signals_not_checked
    assert any("STANDARD" in s for s in not_checked)


def test_premium_tier_no_extra_cost_note(monkeypatch):
    """PREMIUM tier IPs should not have the STANDARD cost note."""
    _mock_clients(
        {"regions/us-central1": [_make_address("prem-ip", network_tier="PREMIUM")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    not_checked = findings[0].evidence.signals_not_checked
    assert not any("STANDARD tier IPs cost less" in s for s in not_checked)


def test_purpose_in_details(monkeypatch):
    """purpose field should appear in details to aid triage."""
    _mock_clients(
        {"regions/us-central1": [_make_address("lb-ip", purpose="SHARED_LOADBALANCER_VIP")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["purpose"] == "SHARED_LOADBALANCER_VIP"


def test_empty_purpose_stored_as_none(monkeypatch):
    """An empty purpose string should be stored as None, not an empty string."""
    _mock_clients(
        {"regions/us-central1": [_make_address("plain-ip", purpose="")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["purpose"] is None


def test_creation_timestamp_in_details(monkeypatch):
    """creation_timestamp should appear in details for both regional and global IPs."""
    ts = "2023-06-15T10:00:00+00:00"
    _mock_clients(
        {"regions/us-central1": [_make_address("old-ip", creation_timestamp=ts)]},
        monkeypatch,
        global_addresses=[_make_address("old-global-ip", creation_timestamp=ts)],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert all(f.details["creation_timestamp"] == ts for f in findings)


def test_internal_ip_not_flagged(monkeypatch):
    """INTERNAL addresses are not subject to external IP reservation billing — skip them."""
    _mock_clients(
        {
            "regions/us-central1": [
                _make_address("internal-ip", status="RESERVED", address_type="INTERNAL"),
                _make_address("external-ip", status="RESERVED", address_type="EXTERNAL"),
            ]
        },
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["address_name"] == "external-ip"


def test_summary_contains_estimated(monkeypatch):
    """Summary should include 'estimated' for both regional and global IPs."""
    _mock_clients(
        {"regions/us-central1": [_make_address("r-ip")]},
        monkeypatch,
        global_addresses=[_make_address("g-ip")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert all("estimated" in f.summary for f in findings)


# ---------------------------------------------------------------------------
# Helper: iterator that raises on first __next__ call
# ---------------------------------------------------------------------------


class _RaiseOnIter:
    """Iterable that raises the given exception on the first iteration."""

    def __init__(self, exc):
        self._exc = exc

    def __iter__(self):
        raise self._exc
        yield  # make it a generator
