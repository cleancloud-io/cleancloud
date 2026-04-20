"""
Tests for aws.cloudwatch.logs.infinite_retention rule.

Every test references its governing spec section in
docs/specs/aws/cloudwatch_logs_no_retention.md
"""

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.risk import RiskLevel
from cleancloud.providers.aws.rules.cloudwatch_logs_no_retention import (
    find_cloudwatch_logs_no_retention,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CREATION_TIME_MS = 1_000_000_000_000  # arbitrary, well in the past


def _run(mock_boto3_session, log_groups, pages=None):
    """Feed log groups through one or more paginator pages."""
    logs = mock_boto3_session._logs
    paginator = logs.get_paginator.return_value
    if pages is not None:
        paginator.paginate.return_value = pages
    else:
        paginator.paginate.return_value = [{"logGroups": log_groups}]
    return find_cloudwatch_logs_no_retention(mock_boto3_session, "us-east-1")


def _lg(name, log_group_class="STANDARD", **kwargs):
    """Build a minimal log group dict. Defaults to STANDARD class (eligible by spec §2).
    Pass log_group_class=None to omit the field entirely (tests missing-class behaviour)."""
    d = {"logGroupName": name}
    if log_group_class is not None:
        d["logGroupClass"] = log_group_class
    d.update(kwargs)
    return d


# ---------------------------------------------------------------------------
# §15 Must emit
# ---------------------------------------------------------------------------


class TestMustEmit:
    """Spec §15 — must emit."""

    def test_standard_class_no_retention(self, mock_boto3_session):
        """STANDARD log group without retentionInDays → emit (§15 scenario 1)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/app/logs", log_group_class="STANDARD", storedBytes=0)],
        )
        assert len(findings) == 1
        assert findings[0].resource_id == "/app/logs"

    def test_infrequent_access_class_no_retention(self, mock_boto3_session):
        """INFREQUENT_ACCESS log group without retentionInDays → emit (§15 scenario 2)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/ia/logs", log_group_class="INFREQUENT_ACCESS", storedBytes=0)],
        )
        assert len(findings) == 1
        assert findings[0].resource_id == "/ia/logs"

    def test_stored_bytes_zero_still_emits(self, mock_boto3_session):
        """storedBytes == 0 does not suppress finding (§15 scenario 3, §4)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/empty", storedBytes=0)],
        )
        assert len(findings) == 1

    def test_stored_bytes_positive_emits(self, mock_boto3_session):
        """storedBytes > 0 emits (§15 scenario 4)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/large", storedBytes=2 * 1024**3)],
        )
        assert len(findings) == 1

    def test_missing_creation_time_does_not_suppress(self, mock_boto3_session):
        """Missing creationTime MUST NOT suppress detection (§3, §15 must-not-happen 4)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/no-ctime", storedBytes=0)],  # no creationTime key
        )
        assert len(findings) == 1
        assert findings[0].details["creation_time"] is None
        assert findings[0].details["age_days"] is None

    def test_multiple_no_retention_groups_all_emit(self, mock_boto3_session):
        """All eligible no-retention groups emit; groups with retention are skipped."""
        findings = _run(
            mock_boto3_session,
            [
                _lg("/no-retention-1", storedBytes=0),
                _lg("/no-retention-2", storedBytes=1024),
                _lg("/has-retention", retentionInDays=30, storedBytes=0),
            ],
        )
        ids = {f.resource_id for f in findings}
        assert "/no-retention-1" in ids
        assert "/no-retention-2" in ids
        assert "/has-retention" not in ids


# ---------------------------------------------------------------------------
# §15 Must skip
# ---------------------------------------------------------------------------


class TestMustSkip:
    """Spec §15 — must skip."""

    def test_skip_when_retention_set(self, mock_boto3_session):
        """retentionInDays set → skip (§15 must-skip 1, §4A)."""
        for days in (1, 7, 30, 90, 180, 365, 3653):
            findings = _run(
                mock_boto3_session,
                [_lg(f"/app/{days}", retentionInDays=days, storedBytes=0)],
            )
            assert findings == [], f"Expected no finding for retentionInDays={days}"

    def test_skip_delivery_class_no_retention(self, mock_boto3_session):
        """DELIVERY class log group → skip even if retentionInDays absent (§15 must-skip 2, §2, §4A)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/delivery/logs", log_group_class="DELIVERY", storedBytes=0)],
        )
        assert findings == []

    def test_skip_delivery_class_with_data(self, mock_boto3_session):
        """DELIVERY class with large storedBytes → still skip."""
        findings = _run(
            mock_boto3_session,
            [_lg("/delivery/big", log_group_class="DELIVERY", storedBytes=10 * 1024**3)],
        )
        assert findings == []

    def test_skip_malformed_record_no_log_group_name(self, mock_boto3_session):
        """Missing logGroupName → skip (§15 must-skip 3, §2)."""
        findings = _run(
            mock_boto3_session,
            [{"storedBytes": 0, "retentionInDays": None}],  # no logGroupName key
        )
        assert findings == []

    def test_skip_malformed_record_empty_log_group_name(self, mock_boto3_session):
        """Empty logGroupName → skip (§2)."""
        findings = _run(
            mock_boto3_session,
            [{"logGroupName": "", "storedBytes": 0}],
        )
        assert findings == []

    def test_skip_explicit_null_retention_in_days(self, mock_boto3_session):
        """retentionInDays key present with explicit null → skip (spec §4A key-presence rule).

        The spec defines no-retention as 'retentionInDays is not present in the returned
        log group object'. A response that includes the key (even with null value) means
        the key was returned and must be treated as set.
        """
        findings = _run(
            mock_boto3_session,
            [
                {
                    "logGroupName": "/grp",
                    "logGroupClass": "STANDARD",
                    "storedBytes": 0,
                    "retentionInDays": None,
                }
            ],
        )
        assert findings == []

    def test_skip_missing_log_group_class(self, mock_boto3_session):
        """logGroupClass absent → skip; only STANDARD and INFREQUENT_ACCESS are in scope (spec §2).

        An allowlist is required — unknown or missing class must not be treated as eligible.
        """
        findings = _run(
            mock_boto3_session,
            [_lg("/no-class", log_group_class=None, storedBytes=0)],
        )
        assert findings == []

    def test_skip_unknown_log_group_class(self, mock_boto3_session):
        """Unexpected logGroupClass value → skip (spec §2 allowlist enforcement)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/unknown-class", log_group_class="CUSTOM_FUTURE_CLASS", storedBytes=0)],
        )
        assert findings == []


# ---------------------------------------------------------------------------
# §15 Must NOT happen
# ---------------------------------------------------------------------------


class TestMustNotHappen:
    """Spec §15 — must-not-happen scenarios."""

    def test_delivery_class_not_labeled_infinite_retention(self, mock_boto3_session):
        """DELIVERY class must produce no finding at all (§15 must-not-happen 1)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/delivery", log_group_class="DELIVERY")],
        )
        assert findings == []

    def test_zero_stored_bytes_not_treated_as_inactive(self, mock_boto3_session):
        """storedBytes == 0 must still produce a finding (§15 must-not-happen 2, §4)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/zero-bytes", storedBytes=0)],
        )
        assert len(findings) == 1

    def test_stored_bytes_not_used_to_suppress_findings(self, mock_boto3_session):
        """No storedBytes value should suppress a finding (§4 — not an activity signal)."""
        for stored in (0, 1, 1024, 1024**3, 10 * 1024**3):
            findings = _run(
                mock_boto3_session,
                [_lg(f"/group/{stored}", storedBytes=stored)],
            )
            assert len(findings) == 1, f"Expected finding for storedBytes={stored}"


# ---------------------------------------------------------------------------
# §7 Confidence model
# ---------------------------------------------------------------------------


class TestConfidenceModel:
    """Spec §7 — confidence must always be HIGH."""

    def test_confidence_is_high_for_all_eligible_groups(self, mock_boto3_session):
        """All eligible no-retention findings must carry HIGH confidence (§7)."""
        for stored in (0, 512 * 1024, 2 * 1024**3):
            findings = _run(
                mock_boto3_session,
                [_lg("/grp", storedBytes=stored)],
            )
            assert (
                findings[0].confidence == ConfidenceLevel.HIGH
            ), f"Expected HIGH confidence for storedBytes={stored}"


# ---------------------------------------------------------------------------
# §8 Risk model
# ---------------------------------------------------------------------------


class TestRiskModel:
    """Spec §8 — risk based on stored size."""

    def test_risk_high_for_one_gb_or_more(self, mock_boto3_session):
        """stored_gb >= 1.0 → HIGH risk (§8)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/large", storedBytes=1024**3)],  # exactly 1 GB
        )
        assert findings[0].risk == RiskLevel.HIGH

    def test_risk_high_for_two_gb(self, mock_boto3_session):
        """2 GB stored → HIGH risk (§8)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/huge", storedBytes=2 * 1024**3)],
        )
        assert findings[0].risk == RiskLevel.HIGH

    def test_risk_medium_for_sub_gb_non_zero(self, mock_boto3_session):
        """0 < stored_bytes < 1 GB → MEDIUM risk (§8)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/small", storedBytes=512 * 1024)],  # 512 KB
        )
        assert findings[0].risk == RiskLevel.MEDIUM

    def test_risk_low_for_zero_stored_bytes(self, mock_boto3_session):
        """storedBytes == 0 → LOW risk (§8)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/empty", storedBytes=0)],
        )
        assert findings[0].risk == RiskLevel.LOW

    def test_risk_low_for_absent_stored_bytes(self, mock_boto3_session):
        """storedBytes absent (null) → LOW risk (§8)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/no-bytes-field")],  # storedBytes key not present
        )
        assert findings[0].risk == RiskLevel.LOW


# ---------------------------------------------------------------------------
# §12 Evidence contract
# ---------------------------------------------------------------------------


class TestEvidenceContract:
    """Spec §12 — all evidence fields must be present (null allowed, never omitted)."""

    def _finding(self, mock_boto3_session, **kwargs):
        findings = _run(
            mock_boto3_session,
            [_lg("/test-group", **kwargs)],
        )
        assert len(findings) == 1
        return findings[0]

    def test_evaluation_path_is_no_retention(self, mock_boto3_session):
        """evaluation_path must be exactly 'no-retention' (§12)."""
        f = self._finding(mock_boto3_session, storedBytes=0)
        assert f.details["evaluation_path"] == "no-retention"

    def test_log_group_name_present(self, mock_boto3_session):
        """log_group_name must be present (§12)."""
        f = self._finding(mock_boto3_session, storedBytes=0)
        assert f.details["log_group_name"] == "/test-group"

    def test_log_group_class_present(self, mock_boto3_session):
        """log_group_class must be present (§12)."""
        f = self._finding(mock_boto3_session, log_group_class="STANDARD", storedBytes=0)
        assert f.details["log_group_class"] == "STANDARD"

    def test_log_group_class_infrequent_access_recorded(self, mock_boto3_session):
        """INFREQUENT_ACCESS class is recorded correctly in details (§12).

        Note: absent logGroupClass now means skip (allowlist enforcement, spec §2),
        so the null-when-absent scenario is no longer reachable in the finding path.
        """
        findings = _run(
            mock_boto3_session,
            [_lg("/ia", log_group_class="INFREQUENT_ACCESS", storedBytes=0)],
        )
        assert len(findings) == 1
        assert findings[0].details["log_group_class"] == "INFREQUENT_ACCESS"

    def test_retention_state_present(self, mock_boto3_session):
        """retention_state must be present (§12)."""
        f = self._finding(mock_boto3_session, storedBytes=0)
        assert "retention_state" in f.details
        assert f.details["retention_state"] is not None

    def test_creation_time_present_when_available(self, mock_boto3_session):
        """creation_time populated when creationTime is in API response (§12)."""
        f = self._finding(mock_boto3_session, creationTime=_CREATION_TIME_MS, storedBytes=0)
        assert f.details["creation_time"] is not None
        assert "T" in f.details["creation_time"]  # ISO-8601 format

    def test_creation_time_null_when_absent(self, mock_boto3_session):
        """creation_time is null when creationTime not in response (§12)."""
        f = self._finding(mock_boto3_session, storedBytes=0)
        assert "creation_time" in f.details
        assert f.details["creation_time"] is None

    def test_age_days_present_when_creation_time_available(self, mock_boto3_session):
        """age_days computed when creationTime present (§12)."""
        f = self._finding(mock_boto3_session, creationTime=_CREATION_TIME_MS, storedBytes=0)
        assert f.details["age_days"] is not None
        assert isinstance(f.details["age_days"], int)

    def test_age_days_null_when_creation_time_absent(self, mock_boto3_session):
        """age_days is null when creationTime not in response (§12)."""
        f = self._finding(mock_boto3_session, storedBytes=0)
        assert "age_days" in f.details
        assert f.details["age_days"] is None

    def test_stored_bytes_present_when_returned(self, mock_boto3_session):
        """stored_bytes is the raw API value (§12)."""
        f = self._finding(mock_boto3_session, storedBytes=12345)
        assert f.details["stored_bytes"] == 12345

    def test_stored_bytes_null_when_absent(self, mock_boto3_session):
        """stored_bytes is null when not returned by API (§12)."""
        f = self._finding(mock_boto3_session)
        assert "stored_bytes" in f.details
        assert f.details["stored_bytes"] is None

    def test_stored_gb_present_when_stored_bytes_returned(self, mock_boto3_session):
        """stored_gb is computed when stored_bytes available (§12)."""
        f = self._finding(mock_boto3_session, storedBytes=1024**3)
        assert f.details["stored_gb"] is not None
        assert abs(f.details["stored_gb"] - 1.0) < 0.0001

    def test_stored_gb_null_when_stored_bytes_absent(self, mock_boto3_session):
        """stored_gb is null when stored_bytes absent (§12)."""
        f = self._finding(mock_boto3_session)
        assert "stored_gb" in f.details
        assert f.details["stored_gb"] is None

    def test_no_detail_fields_omitted(self, mock_boto3_session):
        """All required detail fields must be present; none may be omitted (§12)."""
        f = self._finding(mock_boto3_session, storedBytes=0)
        required = {
            "evaluation_path",
            "log_group_name",
            "log_group_class",
            "retention_state",
            "creation_time",
            "age_days",
            "stored_bytes",
            "stored_gb",
        }
        for field in required:
            assert field in f.details, f"Missing required details field: {field}"


# ---------------------------------------------------------------------------
# §13 Title and reason contract
# ---------------------------------------------------------------------------


class TestTitleAndReasonContract:
    """Spec §13 — exact title and reason strings."""

    def test_title_is_exact(self, mock_boto3_session):
        """Title must be exactly 'CloudWatch log group with no retention policy' (§13)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/grp", storedBytes=0)],
        )
        assert findings[0].title == "CloudWatch log group with no retention policy"

    def test_reason_is_exact(self, mock_boto3_session):
        """Reason must be exactly 'Retention is not configured; log events do not expire' (§13)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/grp", storedBytes=0)],
        )
        assert findings[0].reason == "Retention is not configured; log events do not expire"

    def test_title_not_idle_or_inactive(self, mock_boto3_session):
        """Title must not describe the group as idle or inactive (§13)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/grp", storedBytes=0)],
        )
        title_lower = findings[0].title.lower()
        assert "idle" not in title_lower
        assert "inactive" not in title_lower
        assert "unused" not in title_lower

    def test_reason_does_not_call_group_unused(self, mock_boto3_session):
        """Zero storedBytes must not produce a 'unused' reason (§13)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/empty", storedBytes=0)],
        )
        assert "unused" not in findings[0].reason.lower()


# ---------------------------------------------------------------------------
# §10 Pagination
# ---------------------------------------------------------------------------


class TestPagination:
    """Spec §10 — must paginate until nextToken is exhausted."""

    def test_multi_page_all_findings_collected(self, mock_boto3_session):
        """Findings from all pages are returned (§10 mandatory pagination)."""
        pages = [
            {"logGroups": [_lg("/page1/a", storedBytes=0), _lg("/page1/b", storedBytes=0)]},
            {"logGroups": [_lg("/page2/c", storedBytes=0)]},
            {"logGroups": []},
        ]
        findings = _run(mock_boto3_session, log_groups=None, pages=pages)
        ids = {f.resource_id for f in findings}
        assert "/page1/a" in ids
        assert "/page1/b" in ids
        assert "/page2/c" in ids

    def test_multi_page_mixed_retention(self, mock_boto3_session):
        """Groups with retention set on any page are skipped; others emit."""
        pages = [
            {"logGroups": [_lg("/has-retention", retentionInDays=30, storedBytes=0)]},
            {"logGroups": [_lg("/no-retention", storedBytes=0)]},
        ]
        findings = _run(mock_boto3_session, log_groups=None, pages=pages)
        ids = {f.resource_id for f in findings}
        assert "/has-retention" not in ids
        assert "/no-retention" in ids


# ---------------------------------------------------------------------------
# §9 Cost model
# ---------------------------------------------------------------------------


class TestCostModel:
    """Spec §9 — cost is informational only; must not influence detection or confidence."""

    def test_zero_stored_bytes_no_cost_estimate(self, mock_boto3_session):
        """Zero storedBytes → estimated_monthly_cost_usd is None (§9)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/empty", storedBytes=0)],
        )
        assert findings[0].estimated_monthly_cost_usd is None

    def test_positive_stored_bytes_has_cost_estimate(self, mock_boto3_session):
        """Non-zero storedBytes → estimated_monthly_cost_usd is a positive float (§9)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/big", storedBytes=1024**3)],  # 1 GB
        )
        assert findings[0].estimated_monthly_cost_usd is not None
        assert findings[0].estimated_monthly_cost_usd > 0

    def test_absent_stored_bytes_no_cost_estimate(self, mock_boto3_session):
        """Absent storedBytes → estimated_monthly_cost_usd is None (§9)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/no-bytes")],
        )
        assert findings[0].estimated_monthly_cost_usd is None

    def test_cost_does_not_influence_confidence(self, mock_boto3_session):
        """Confidence is HIGH regardless of stored size (§7, §9)."""
        for stored in (0, 1024**3, 100 * 1024**3):
            findings = _run(
                mock_boto3_session,
                [_lg(f"/grp/{stored}", storedBytes=stored)],
            )
            assert findings[0].confidence == ConfidenceLevel.HIGH


# ---------------------------------------------------------------------------
# §11 Blind spots / signals_not_checked
# ---------------------------------------------------------------------------


class TestBlindSpots:
    """Spec §11 — signals_not_checked must disclose all defined blind spots."""

    def test_signals_not_checked_cross_account(self, mock_boto3_session):
        """Cross-account blind spot must be disclosed (§11)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/grp", storedBytes=0)],
        )
        not_checked = " ".join(findings[0].evidence.signals_not_checked).lower()
        assert "cross-account" in not_checked

    def test_signals_not_checked_compliance_intent(self, mock_boto3_session):
        """Compliance/audit/security intent blind spot must be disclosed (§11)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/grp", storedBytes=0)],
        )
        not_checked = " ".join(findings[0].evidence.signals_not_checked).lower()
        assert "compliance" in not_checked or "audit" in not_checked or "security" in not_checked

    def test_signals_not_checked_delivery_class_note(self, mock_boto3_session):
        """DELIVERY class exclusion must be disclosed (§11)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/grp", storedBytes=0)],
        )
        not_checked = " ".join(findings[0].evidence.signals_not_checked).lower()
        assert "delivery" in not_checked


# ---------------------------------------------------------------------------
# §2 Scope — class handling
# ---------------------------------------------------------------------------


class TestScope:
    """Spec §2 — scope enforcement."""

    def test_standard_class_in_scope(self, mock_boto3_session):
        """STANDARD class is in scope (§2)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/std", log_group_class="STANDARD", storedBytes=0)],
        )
        assert len(findings) == 1

    def test_infrequent_access_class_in_scope(self, mock_boto3_session):
        """INFREQUENT_ACCESS class is in scope (§2)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/ia", log_group_class="INFREQUENT_ACCESS", storedBytes=0)],
        )
        assert len(findings) == 1

    def test_delivery_class_out_of_scope(self, mock_boto3_session):
        """DELIVERY class is out of scope (§2)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/del", log_group_class="DELIVERY", storedBytes=0)],
        )
        assert findings == []

    def test_log_group_class_recorded_in_details(self, mock_boto3_session):
        """logGroupClass must appear in details (§12)."""
        findings = _run(
            mock_boto3_session,
            [_lg("/std", log_group_class="STANDARD", storedBytes=0)],
        )
        assert findings[0].details["log_group_class"] == "STANDARD"
