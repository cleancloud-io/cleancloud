"""Unit tests for gcp.compute.disk.unattached rule."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.providers.gcp.rules.disk_unattached import find_unattached_disks


def _make_disk(
    name,
    status="READY",
    users=None,
    disk_type="pd-standard",
    size_gb=100,
    labels=None,
    last_detach_timestamp="",
    last_attach_timestamp="",
    creation_timestamp="2024-01-01T00:00:00+00:00",
):
    return SimpleNamespace(
        name=name,
        status=status,
        users=users or [],
        type_=f"zones/us-central1-a/diskTypes/{disk_type}",
        size_gb=size_gb,
        labels=labels or {},
        last_detach_timestamp=last_detach_timestamp,
        last_attach_timestamp=last_attach_timestamp,
        creation_timestamp=creation_timestamp,
    )


def _make_scoped_disk_list(disks):
    return SimpleNamespace(disks=disks)


def _mock_client(zone_disk_map, monkeypatch):
    """Patch compute_v1.DisksClient to return the given zone->disk mapping."""
    mock = MagicMock()
    mock.aggregated_list.return_value = [
        (zone, _make_scoped_disk_list(disks)) for zone, disks in zone_disk_map.items()
    ]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    return mock


def test_unattached_disk_is_flagged(monkeypatch):
    """An unattached READY disk with no users should produce a finding."""
    _mock_client(
        {"zones/us-central1-a": [_make_disk("orphan-disk", users=[])]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "gcp.compute.disk.unattached"
    assert f.provider == "gcp"
    assert "orphan-disk" in f.resource_id
    assert f.region == "us-central1-a"
    assert f.confidence == ConfidenceLevel.HIGH


def test_attached_disk_not_flagged(monkeypatch):
    """A disk with users (attached to a VM) should NOT be flagged."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_disk("attached-disk", users=["zones/us-central1-a/instances/my-vm"])
            ]
        },
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_non_ready_disk_not_flagged(monkeypatch):
    """A disk in CREATING or DELETING state should not be flagged."""
    _mock_client(
        {"zones/us-central1-a": [_make_disk("creating-disk", status="CREATING")]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_estimated_monthly_cost_is_none(monkeypatch):
    """spec 9.5.1: estimated_monthly_cost_usd must always be None (pricing varies by region/currency)."""
    _mock_client(
        {"zones/us-central1-a": [_make_disk("std-disk", disk_type="pd-ssd", size_gb=500)]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].estimated_monthly_cost_usd is None


def test_region_filter_excludes_other_zones(monkeypatch):
    """region_filter='us-east1' should skip us-central1 zones."""
    _mock_client(
        {
            "zones/us-central1-a": [_make_disk("central-disk")],
            "zones/us-east1-b": [_make_disk("east-disk")],
        },
        monkeypatch,
    )
    findings = find_unattached_disks(
        project_id="proj-1", credentials=MagicMock(), region_filter="us-east1"
    )

    assert len(findings) == 1
    assert "east-disk" in findings[0].resource_id


def test_empty_zone_skipped(monkeypatch):
    """A zone with no disks should not cause errors."""
    _mock_client({"zones/us-central1-a": []}, monkeypatch)
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_multiple_zones_multiple_disks(monkeypatch):
    """All unattached disks across zones should be returned."""
    _mock_client(
        {
            "zones/us-central1-a": [_make_disk("disk-a1"), _make_disk("disk-a2")],
            "zones/eu-west1-b": [
                _make_disk("disk-eu", users=["vm-uri"]),  # attached, skip
                _make_disk("disk-eu-orphan"),
            ],
        },
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    resource_ids = [f.resource_id for f in findings]
    assert any("disk-a1" in r for r in resource_ids)
    assert any("disk-a2" in r for r in resource_ids)
    assert any("disk-eu-orphan" in r for r in resource_ids)
    assert not any("disk-eu" in r and "orphan" not in r for r in resource_ids)


def test_permission_denied_raises_permission_error(monkeypatch):
    """PermissionDenied during iteration should be re-raised as PermissionError."""
    mock = MagicMock()
    mock.aggregated_list.return_value = iter(
        _RaiseOnIter(PermissionDenied("403 compute.disks.list denied"))
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    with pytest.raises(PermissionError, match="compute.disks.list"):
        find_unattached_disks(project_id="proj-1", credentials=MagicMock())


def test_forbidden_raises_permission_error(monkeypatch):
    """Forbidden (HTTP 403) should be re-raised as PermissionError."""
    mock = MagicMock()
    mock.aggregated_list.return_value = iter(_RaiseOnIter(Forbidden("403 Forbidden")))
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    with pytest.raises(PermissionError):
        find_unattached_disks(project_id="proj-1", credentials=MagicMock())


def test_not_found_returns_empty(monkeypatch):
    """NotFound (Compute API not enabled) should return empty, not raise."""
    mock = MagicMock()
    mock.aggregated_list.return_value = iter(
        _RaiseOnIter(NotFound("404 Compute Engine API not enabled"))
    )
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_labels_included_in_details(monkeypatch):
    """Labels on the disk should appear in finding details."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_disk("labeled-disk", labels={"team": "platform", "env": "dev"})
            ]
        },
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["labels"] == {"team": "platform", "env": "dev"}


# ---------------------------------------------------------------------------
# Regional disk handling (Point 1)
# ---------------------------------------------------------------------------


def test_regional_disk_flagged_with_medium_confidence(monkeypatch):
    """Regional disks (regions/ scope) should be flagged with MEDIUM confidence."""
    _mock_client(
        {"regions/us-central1": [_make_disk("regional-orphan")]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == ConfidenceLevel.MEDIUM
    assert "regions/us-central1" in f.resource_id
    assert f.region == "us-central1"


def test_regional_disk_resource_id_uses_regions_path(monkeypatch):
    """Regional disk resource_id must use 'regions/' not 'zones/'."""
    _mock_client(
        {"regions/europe-west1": [_make_disk("reg-disk")]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].resource_id == "projects/proj-1/regions/europe-west1/disks/reg-disk"


def test_regional_disk_region_filter_respected(monkeypatch):
    """region_filter should correctly match regional disks by region name."""
    _mock_client(
        {
            "regions/us-central1": [_make_disk("central-regional")],
            "regions/us-east1": [_make_disk("east-regional")],
        },
        monkeypatch,
    )
    findings = find_unattached_disks(
        project_id="proj-1", credentials=MagicMock(), region_filter="us-east1"
    )

    assert len(findings) == 1
    assert "east-regional" in findings[0].resource_id


# ---------------------------------------------------------------------------
# Confidence modulation by detach age (Point 2)
# ---------------------------------------------------------------------------


def test_recently_detached_disk_confidence_low(monkeypatch):
    """A disk detached < 24h ago should have LOW confidence."""
    from datetime import timedelta

    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    _mock_client(
        {"zones/us-central1-a": [_make_disk("fresh-detach", last_detach_timestamp=recent)]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].confidence == ConfidenceLevel.LOW


def test_midrange_detached_disk_confidence_medium(monkeypatch):
    """A zonal disk detached 24h–7d ago should have MEDIUM confidence."""
    from datetime import timedelta

    mid = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    _mock_client(
        {"zones/us-central1-a": [_make_disk("mid-detach", last_detach_timestamp=mid)]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].confidence == ConfidenceLevel.MEDIUM


def test_stale_detached_disk_confidence_high(monkeypatch):
    """A zonal disk detached > 7 days ago should have HIGH confidence."""
    from datetime import timedelta

    old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    _mock_client(
        {"zones/us-central1-a": [_make_disk("old-detach", last_detach_timestamp=old)]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].confidence == ConfidenceLevel.HIGH


def test_last_detach_timestamp_in_details(monkeypatch):
    """last_detach_timestamp should appear in finding details when present."""
    ts = "2024-06-01T12:00:00+00:00"
    _mock_client(
        {"zones/us-central1-a": [_make_disk("disk-ts", last_detach_timestamp=ts)]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert findings[0].details["last_detach_timestamp"] == ts


def test_no_last_detach_timestamp_not_in_details(monkeypatch):
    """When last_detach_timestamp is absent, it should not appear in details."""
    _mock_client(
        {"zones/us-central1-a": [_make_disk("disk-no-ts", last_detach_timestamp="")]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert "last_detach_timestamp" not in findings[0].details


# ---------------------------------------------------------------------------
# Hyperdisk cost note (Point 5)
# ---------------------------------------------------------------------------


def test_hyperdisk_iops_note_in_signals_not_checked(monkeypatch):
    """Hyperdisk findings should note that IOPS/throughput charges are billed separately."""
    _mock_client(
        {
            "zones/us-central1-a": [
                _make_disk("hd-disk", disk_type="hyperdisk-balanced", size_gb=500)
            ]
        },
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    not_checked = findings[0].evidence.signals_not_checked
    assert any("IOPS" in s for s in not_checked)


# ---------------------------------------------------------------------------
# Spec 7: disk_type normalization
# ---------------------------------------------------------------------------


def test_disk_type_fallback_is_unknown(monkeypatch):
    """spec 7: when disk type URL is absent, disk_type should be 'unknown', not a guessed default."""
    disk = _make_disk("no-type-disk")
    disk.type_ = ""  # empty URL
    mock = MagicMock()
    mock.aggregated_list.return_value = [("zones/us-central1-a", SimpleNamespace(disks=[disk]))]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["disk_type"] == "unknown"


# ---------------------------------------------------------------------------
# Spec 8.1: malformed disk name
# ---------------------------------------------------------------------------


def test_absent_disk_name_is_skipped(monkeypatch):
    """spec 8.1: disk records with absent/empty name must be skipped."""
    disk = _make_disk("placeholder")
    disk.name = ""  # absent name
    mock = MagicMock()
    mock.aggregated_list.return_value = [("zones/us-central1-a", SimpleNamespace(disks=[disk]))]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Spec 8.2: malformed scope key
# ---------------------------------------------------------------------------


def test_malformed_scope_key_is_skipped(monkeypatch):
    """spec 8.2: scope keys without a '/' (e.g. 'global') must be skipped, not crash."""
    disk = _make_disk("disk-global")
    mock = MagicMock()
    mock.aggregated_list.return_value = [
        ("global", SimpleNamespace(disks=[disk]))  # no slash — len == 1, != 2
    ]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_extra_segment_scope_key_is_skipped(monkeypatch):
    """spec 8.2: only exactly 'zones/ZONE' or 'regions/REGION' are supported;
    a key like 'zones/us-central1-a/extra' has 3 segments and must be skipped."""
    disk = _make_disk("disk-extra")
    mock = MagicMock()
    mock.aggregated_list.return_value = [
        ("zones/us-central1-a/extra", SimpleNamespace(disks=[disk]))  # len == 3, != 2
    ]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Spec 8.5: unresolvable users field
# ---------------------------------------------------------------------------


def test_none_users_is_skipped(monkeypatch):
    """spec 8.5: disk.users=None is not equivalent to an empty list — must skip."""
    disk = _make_disk("null-users-disk")
    disk.users = None  # bypass the _make_disk default
    mock = MagicMock()
    mock.aggregated_list.return_value = [("zones/us-central1-a", SimpleNamespace(disks=[disk]))]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Spec 9.5 / 10.2: cost blind-spot disclosure
# ---------------------------------------------------------------------------


def test_exact_pricing_blind_spot_in_signals_not_checked(monkeypatch):
    """spec 9.5/10.2: signals_not_checked must disclose that exact pricing is unavailable."""
    _mock_client(
        {"zones/us-central1-a": [_make_disk("billing-disk", disk_type="pd-ssd", size_gb=100)]},
        monkeypatch,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    not_checked = findings[0].evidence.signals_not_checked
    assert any(
        "cost" in s.lower() or "pricing" in s.lower() or "billing" in s.lower() for s in not_checked
    )


# ---------------------------------------------------------------------------
# Issue 1: Partial aggregated coverage (spec 9.1.8-9 / 9.6)
# ---------------------------------------------------------------------------


def test_partial_coverage_warning_is_emitted(monkeypatch):
    """spec 9.1.8-9: a scope with a warning code must emit a UserWarning, not silently pass."""
    disk = _make_disk("disk-partial")
    scope_with_warning = SimpleNamespace(
        disks=[disk],
        warning=SimpleNamespace(code="NO_RESULTS_ON_PAGE", message="partial"),
    )
    mock = MagicMock()
    mock.aggregated_list.return_value = [("zones/us-central1-a", scope_with_warning)]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    with pytest.warns(UserWarning, match="partial coverage"):
        find_unattached_disks(project_id="proj-1", credentials=MagicMock())


def test_scope_without_warning_attr_does_not_warn(monkeypatch):
    """No warning attribute on scope_disks must not raise and must not warn."""
    # _make_scoped_disk_list returns a SimpleNamespace with no 'warning' attribute
    _mock_client({"zones/us-central1-a": [_make_disk("quiet-disk")]}, monkeypatch)
    import warnings as _w

    with _w.catch_warnings():
        _w.simplefilter("error")  # any warning → error
        findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Issue 2: users[] strict list check (spec 8.5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_users",
    [
        {},  # dict — falsy but not a list
        (),  # tuple — falsy but not a list
        "",  # string — falsy but not a list
        0,  # int — falsy but not a list
    ],
    ids=["dict", "tuple", "str", "int"],
)
def test_non_list_users_is_skipped(monkeypatch, bad_users):
    """spec 8.5: only an explicit empty list means unattached; other falsy types must skip."""
    disk = _make_disk("bad-users-disk")
    disk.users = bad_users
    mock = MagicMock()
    mock.aggregated_list.return_value = [("zones/us-central1-a", SimpleNamespace(disks=[disk]))]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Issue 3: zone-to-region parsing strictness (spec 8.2 / 7)
# ---------------------------------------------------------------------------


def test_zone_scope_without_zone_letter_is_skipped(monkeypatch):
    """spec 8.2/7: a zonal scope like zones/us-central1 (no single-letter suffix) must skip.

    rsplit alone would silently derive 'us' as the region, which is a silent wrong guess.
    """
    disk = _make_disk("region-only-zone")
    mock = MagicMock()
    mock.aggregated_list.return_value = [
        ("zones/us-central1", SimpleNamespace(disks=[disk]))  # missing zone letter
    ]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


def test_zone_scope_with_multi_char_suffix_is_skipped(monkeypatch):
    """spec 8.2/7: a zone suffix longer than one character must skip (not a valid GCP zone)."""
    disk = _make_disk("bad-suffix-disk")
    mock = MagicMock()
    mock.aggregated_list.return_value = [
        ("zones/us-central1-ab", SimpleNamespace(disks=[disk]))  # two-char suffix
    ]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())
    assert findings == []


# ---------------------------------------------------------------------------
# Issue 4: malformed record hardening (spec 9.6)
# ---------------------------------------------------------------------------


def test_malformed_size_gb_uses_zero(monkeypatch):
    """spec 9.6: non-numeric size_gb must not crash; the disk should still be emitted with size 0."""
    disk = _make_disk("bad-size-disk")
    disk.size_gb = "not-a-number"
    mock = MagicMock()
    mock.aggregated_list.return_value = [("zones/us-central1-a", SimpleNamespace(disks=[disk]))]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    assert findings[0].details["size_gb"] == 0


def test_non_string_last_detach_timestamp_keeps_baseline_confidence(monkeypatch):
    """spec 9.6 / 7: non-string last_detach_timestamp must not crash; baseline confidence kept."""
    disk = _make_disk("ts-type-disk")
    disk.last_detach_timestamp = 12345  # integer, not a string
    mock = MagicMock()
    mock.aggregated_list.return_value = [("zones/us-central1-a", SimpleNamespace(disks=[disk]))]
    monkeypatch.setattr(
        "cleancloud.providers.gcp.rules.disk_unattached.compute_v1.DisksClient",
        lambda credentials: mock,
    )
    findings = find_unattached_disks(project_id="proj-1", credentials=MagicMock())

    assert len(findings) == 1
    # Non-string timestamp treated as absent → zonal baseline confidence = HIGH
    assert findings[0].confidence == ConfidenceLevel.HIGH
    assert "last_detach_timestamp" not in findings[0].details


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
