"""Unit tests for gcp.compute.ip.unused rule."""

import warnings
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import NotFound, PermissionDenied

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.providers.gcp.rules.ip_unused import find_unused_static_ips

_EXPECTED_COST = 7.30  # spec 9.7: $0.01/hr × 730h


def _make_address(
    name,
    status="RESERVED",
    address="34.1.2.3",
    address_type="EXTERNAL",
    ip_version="IPV4",
    labels=None,
    network_tier="PREMIUM",
    purpose="",
    creation_timestamp="2024-01-01T00:00:00+00:00",
    users=None,
):
    return SimpleNamespace(
        name=name,
        status=status,
        address=address,
        address_type=address_type,
        ip_version=ip_version,
        labels=labels or {},
        network_tier=network_tier,
        purpose=purpose,
        creation_timestamp=creation_timestamp,
        users=users or [],
    )


def _make_scoped_address_list(addresses, warning=None):
    return SimpleNamespace(addresses=addresses, warning=warning)


def _make_page(scope_to_addrs, page_warning=None, unreachables=None):
    """Build one page of aggregated_list results.

    scope_to_addrs: {scope_key: list_of_addresses} or {scope_key: ScopedList}.
    page_warning: optional page-level warning SimpleNamespace.
    unreachables: optional list of unreachable scope strings.
    """
    items = {}
    for scope, val in scope_to_addrs.items():
        if isinstance(val, list):
            items[scope] = _make_scoped_address_list(val)
        else:
            items[scope] = val  # pre-built ScopedList (carries its own warning)
    return SimpleNamespace(items=items, warning=page_warning, unreachables=unreachables or [])


def _make_pager(pages):
    """Wrap a list of pages in a mock pager with a .pages attribute."""
    pager = MagicMock()
    pager.pages = pages
    return pager


def _mock_clients(region_address_map, monkeypatch, global_addresses=None):
    """Patch AddressesClient (regional pager) and GlobalAddressesClient."""
    regional_mock = MagicMock()
    regional_mock.aggregated_list.return_value = _make_pager([_make_page(region_address_map)])
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


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------


def test_reserved_regional_ip_flagged(monkeypatch):
    """A RESERVED regional IPv4 EXTERNAL IP produces a finding."""
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
    assert f.estimated_monthly_cost_usd == _EXPECTED_COST
    assert f.details["scope"] == "regional"


def test_estimated_cost_is_7_30(monkeypatch):
    """Estimated monthly cost must be exactly $7.30 (spec 9.7: $0.01/hr × 730h)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("ip")]},
        monkeypatch,
        global_addresses=[_make_address("g-ip")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert all(f.estimated_monthly_cost_usd == 7.30 for f in findings)


def test_in_use_regional_ip_not_flagged(monkeypatch):
    """An IN_USE regional IP should not be flagged."""
    _mock_clients(
        {"regions/us-central1": [_make_address("active-ip", status="IN_USE")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_reserving_status_not_flagged(monkeypatch):
    """RESERVING status must not produce a finding (spec 9.2.3)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("ip", status="RESERVING")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_reserved_global_ip_flagged(monkeypatch):
    """A RESERVED global IPv4 EXTERNAL IP produces a finding with region='global'."""
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
    assert f.estimated_monthly_cost_usd == _EXPECTED_COST


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


# ---------------------------------------------------------------------------
# Spec 8.6 / 9.3: addressType must be exactly "EXTERNAL"
# ---------------------------------------------------------------------------


def test_internal_ip_not_flagged(monkeypatch):
    """INTERNAL addresses are out of scope (spec 8.6, 9.3)."""
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


def test_absent_address_type_skipped(monkeypatch):
    """Absent / empty addressType must skip — unknown is not 'EXTERNAL' (spec 8.6)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("ip", address_type="")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_global_absent_address_type_skipped(monkeypatch):
    """Global address with absent addressType must skip (spec 8.6)."""
    _mock_clients(
        {},
        monkeypatch,
        global_addresses=[_make_address("g-ip", address_type="")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Spec 8.7 / 9.3: ipVersion must be exactly "IPV4"
# ---------------------------------------------------------------------------


def test_ipv6_regional_ip_not_flagged(monkeypatch):
    """IPv6 addresses are out of scope (spec 8.7, 9.3)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("ipv6-ip", ip_version="IPV6")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_absent_ip_version_skipped(monkeypatch):
    """Absent / empty ipVersion must skip — unknown is not 'IPV4' (spec 8.7)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("ip", ip_version="")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_ipv6_global_ip_not_flagged(monkeypatch):
    """Global IPv6 addresses are out of scope (spec 8.7)."""
    _mock_clients(
        {},
        monkeypatch,
        global_addresses=[_make_address("g-ipv6", ip_version="IPV6")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_ip_version_in_details(monkeypatch):
    """ip_version must appear in finding details (spec 11.3)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("ip")]},
        monkeypatch,
        global_addresses=[_make_address("g-ip")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert all(f.details["ip_version"] == "IPV4" for f in findings)


# ---------------------------------------------------------------------------
# Spec 8.8 / 9.4: NAT_AUTO exclusion
# ---------------------------------------------------------------------------


def test_nat_auto_regional_ip_not_flagged(monkeypatch):
    """purpose == NAT_AUTO must be excluded (spec 8.8, 9.4)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("nat-ip", purpose="NAT_AUTO")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_nat_auto_global_ip_not_flagged(monkeypatch):
    """Global purpose == NAT_AUTO must be excluded (spec 8.8)."""
    _mock_clients(
        {},
        monkeypatch,
        global_addresses=[_make_address("nat-g-ip", purpose="NAT_AUTO")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_other_purpose_regional_ip_flagged(monkeypatch):
    """Non-NAT_AUTO purpose should not block detection."""
    _mock_clients(
        {"regions/us-central1": [_make_address("lb-ip", purpose="SHARED_LOADBALANCER_VIP")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Spec 8.9 / 9.5: users[] contradictory current-use evidence
# ---------------------------------------------------------------------------


def test_non_empty_users_regional_skipped(monkeypatch):
    """Non-empty users[] is contradictory evidence — must skip (spec 8.9)."""
    _mock_clients(
        {
            "regions/us-central1": [
                _make_address("in-use-ip", users=["projects/p/zones/z/instances/vm1"]),
            ]
        },
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_non_empty_users_global_skipped(monkeypatch):
    """Global address with non-empty users[] must skip (spec 8.9)."""
    _mock_clients(
        {},
        monkeypatch,
        global_addresses=[
            _make_address("g-in-use", users=["projects/p/global/forwardingRules/fr1"])
        ],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_empty_users_regional_flagged(monkeypatch):
    """Empty users[] with RESERVED status should still emit a finding."""
    _mock_clients(
        {"regions/us-central1": [_make_address("ip", users=[])]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Spec 8.1: malformed records
# ---------------------------------------------------------------------------


def test_absent_name_regional_skipped(monkeypatch):
    """Address record with absent / empty name must skip (spec 8.1)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_absent_name_global_skipped(monkeypatch):
    """Global address record with absent / empty name must skip (spec 8.1)."""
    _mock_clients(
        {},
        monkeypatch,
        global_addresses=[_make_address("")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Spec 8.2: scope key validation
# ---------------------------------------------------------------------------


def test_malformed_scope_key_skipped(monkeypatch):
    """Scope key that is not exactly 'regions/REGION' must be skipped (spec 8.2)."""
    _mock_clients(
        {"global": [_make_address("bad-ip")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_extra_segment_scope_key_skipped(monkeypatch):
    """Scope key with >2 segments (e.g. 'regions/us-central1/extra') must be skipped (spec 8.2)."""
    _mock_clients(
        {"regions/us-central1/extra": [_make_address("ip")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_zones_scope_key_skipped(monkeypatch):
    """Scope key of form 'zones/...' must be skipped — not a regional address scope."""
    _mock_clients(
        {"zones/us-central1-a": [_make_address("ip")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Spec 9.1.2: returnPartialSuccess=True
# ---------------------------------------------------------------------------


def test_aggregated_list_called_with_return_partial_success(monkeypatch):
    """aggregated_list must be called with return_partial_success=True (spec 9.1.2)."""
    regional_mock, _ = _mock_clients({}, monkeypatch)
    find_unused_static_ips(project_id="proj-1", credentials=MagicMock())
    call_kwargs = regional_mock.aggregated_list.call_args.kwargs
    # return_partial_success is passed inside the request dict
    request = call_kwargs.get("request") or {}
    assert request.get("return_partial_success") is True


# ---------------------------------------------------------------------------
# Spec 9.1.6-7: partial coverage warnings (scope, page-level, unreachables)
# ---------------------------------------------------------------------------


def test_scope_level_warning_is_emitted(monkeypatch):
    """Scope-level warning from aggregated_list must be surfaced as UserWarning (spec 9.1.6)."""
    scope_warning = SimpleNamespace(code="NO_RESULTS_ON_PAGE", message="partial")
    scoped_list = _make_scoped_address_list([], warning=scope_warning)
    regional_mock = MagicMock()
    regional_mock.aggregated_list.return_value = _make_pager(
        [_make_page({"regions/us-central1": scoped_list})]
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.AddressesClient",
        lambda credentials: regional_mock,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.GlobalAddressesClient",
        lambda credentials: MagicMock(list=lambda project: []),
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
    assert len(user_warnings) == 1
    assert "regions/us-central1" in str(user_warnings[0].message)
    assert "NO_RESULTS_ON_PAGE" in str(user_warnings[0].message)


def test_top_level_page_warning_is_emitted(monkeypatch):
    """Page-level (top-level) warning must be surfaced as UserWarning (spec 9.1.6)."""
    page_warning = SimpleNamespace(code="UNREACHABLE", message="some scopes unreachable")
    regional_mock = MagicMock()
    regional_mock.aggregated_list.return_value = _make_pager(
        [_make_page({}, page_warning=page_warning)]
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.AddressesClient",
        lambda credentials: regional_mock,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.GlobalAddressesClient",
        lambda credentials: MagicMock(list=lambda project: []),
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
    assert len(user_warnings) == 1
    assert "top-level" in str(user_warnings[0].message)
    assert "UNREACHABLE" in str(user_warnings[0].message)


def test_unreachable_scope_warning_is_emitted(monkeypatch):
    """Each unreachable scope in the page must be surfaced as a UserWarning (spec 9.1.6-7)."""
    regional_mock = MagicMock()
    regional_mock.aggregated_list.return_value = _make_pager(
        [_make_page({}, unreachables=["regions/us-east1", "regions/europe-west1"])]
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.AddressesClient",
        lambda credentials: regional_mock,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.GlobalAddressesClient",
        lambda credentials: MagicMock(list=lambda project: []),
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
    assert len(user_warnings) == 2
    warning_texts = [str(w.message) for w in user_warnings]
    assert any("regions/us-east1" in t for t in warning_texts)
    assert any("regions/europe-west1" in t for t in warning_texts)


def test_no_warning_emitted_on_clean_page(monkeypatch):
    """A page with no warning or unreachables must not emit UserWarnings."""
    _mock_clients({"regions/us-central1": []}, monkeypatch)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert not any(issubclass(w.category, UserWarning) for w in caught)


# ---------------------------------------------------------------------------
# Region filter (spec 8.3, 8.4, 9.6)
# ---------------------------------------------------------------------------


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
    """When region_filter is set, global IPs are not scanned (spec 8.4, 9.6)."""
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


# ---------------------------------------------------------------------------
# Failure behavior (spec 9.8)
# ---------------------------------------------------------------------------


def test_regional_permission_denied_raises(monkeypatch):
    """PermissionDenied during regional page iteration raises PermissionError (spec 9.8.1)."""
    regional_mock = MagicMock()
    pager = MagicMock()
    pager.pages = _RaiseOnIter(PermissionDenied("compute.addresses.list denied"))
    regional_mock.aggregated_list.return_value = pager
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
    """NotFound (Compute API not enabled) during regional scan returns empty list (spec 9.8.3)."""
    regional_mock = MagicMock()
    pager = MagicMock()
    pager.pages = _RaiseOnIter(NotFound("Compute Engine API not enabled"))
    regional_mock.aggregated_list.return_value = pager
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


def test_global_permission_denied_raises(monkeypatch):
    """PermissionDenied on global IPs must surface as PermissionError (spec 9.8.2)."""
    global_mock = MagicMock()
    global_mock.list.return_value = iter(
        _RaiseOnIter(PermissionDenied("compute.globalAddresses.list denied"))
    )
    regional_mock = MagicMock()
    regional_mock.aggregated_list.return_value = _make_pager([_make_page({})])
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.AddressesClient",
        lambda credentials: regional_mock,
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.ip_unused.compute_v1.GlobalAddressesClient",
        lambda credentials: global_mock,
    )
    with pytest.raises(PermissionError, match="compute.globalAddresses.list"):
        find_unused_static_ips(project_id="proj-1", credentials=MagicMock())


# ---------------------------------------------------------------------------
# Details, evidence, and signals
# ---------------------------------------------------------------------------


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


def test_absent_regional_network_tier_stored_as_none(monkeypatch):
    """Absent regional network_tier must not be guessed — stored as None (spec 7)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("ip", network_tier="")]},
        monkeypatch,
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["network_tier"] is None


def test_absent_global_network_tier_stored_as_none(monkeypatch):
    """Absent global network_tier must not be guessed — stored as None (spec 7)."""
    _mock_clients(
        {},
        monkeypatch,
        global_addresses=[_make_address("g-ip", network_tier="")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["network_tier"] is None


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


def test_summary_contains_estimated(monkeypatch):
    """Summary should include 'estimated' for both regional and global IPs."""
    _mock_clients(
        {"regions/us-central1": [_make_address("r-ip")]},
        monkeypatch,
        global_addresses=[_make_address("g-ip")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    assert all("estimated" in f.summary for f in findings)


def test_signals_used_include_ipv4_and_external(monkeypatch):
    """signals_used must disclose address type and IP version (spec 11.2)."""
    _mock_clients(
        {"regions/us-central1": [_make_address("ip")]},
        monkeypatch,
        global_addresses=[_make_address("g-ip")],
    )
    findings = find_unused_static_ips(project_id="proj-1", credentials=MagicMock())

    for f in findings:
        signals = " ".join(f.evidence.signals_used)
        assert "EXTERNAL" in signals
        assert "IPv4" in signals


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
