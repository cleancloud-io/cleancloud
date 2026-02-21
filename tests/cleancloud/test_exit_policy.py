from dataclasses import dataclass
from typing import Optional

from cleancloud.policy.exit_policy import determine_exit_code


@dataclass
class FakeResult:
    confidence: str
    estimated_monthly_cost_usd: Optional[float] = None


def test_exit_policy_no_issues():
    results = []
    assert determine_exit_code(results) == 0


def test_exit_policy_low_only():
    results = [FakeResult(confidence="Low")]
    assert determine_exit_code(results) == 0


def test_exit_policy_medium_only():
    results = [FakeResult(confidence="Medium")]
    assert determine_exit_code(results) == 0


def test_exit_policy_high_only():
    results = [FakeResult(confidence="High")]
    # Default behavior: report-only (don't fail)
    assert determine_exit_code(results) == 0
    # With explicit flag: fail on HIGH
    assert determine_exit_code(results, fail_on_confidence="HIGH") == 2


def test_exit_policy_mixed_low_medium():
    results = [
        FakeResult(confidence="Low"),
        FakeResult(confidence="Medium"),
    ]
    assert determine_exit_code(results) == 0


def test_exit_policy_mixed_medium_high():
    results = [
        FakeResult(confidence="Medium"),
        FakeResult(confidence="High"),
    ]
    # Default behavior: report-only (don't fail)
    assert determine_exit_code(results) == 0
    # With explicit flag: fail on HIGH
    assert determine_exit_code(results, fail_on_confidence="HIGH") == 2
    # With explicit flag: fail on MEDIUM or higher
    assert determine_exit_code(results, fail_on_confidence="MEDIUM") == 2


def test_exit_policy_all_levels():
    results = [
        FakeResult(confidence="Low"),
        FakeResult(confidence="Medium"),
        FakeResult(confidence="High"),
    ]
    # Default behavior: report-only (don't fail)
    assert determine_exit_code(results) == 0
    # With explicit flag: fail on HIGH
    assert determine_exit_code(results, fail_on_confidence="HIGH") == 2
    # With explicit flag: fail on MEDIUM or higher
    assert determine_exit_code(results, fail_on_confidence="MEDIUM") == 2
    # With explicit flag: fail on LOW or higher (all findings)
    assert determine_exit_code(results, fail_on_confidence="LOW") == 2
    # With fail_on_findings: fail on any finding
    assert determine_exit_code(results, fail_on_findings=True) == 2


# --fail-on-cost tests


def test_fail_on_cost_exceeds_threshold():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=10.0),
        FakeResult(confidence="Low", estimated_monthly_cost_usd=15.0),
    ]
    assert determine_exit_code(results, fail_on_cost=20.0) == 2


def test_fail_on_cost_below_threshold():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=5.0),
        FakeResult(confidence="Low", estimated_monthly_cost_usd=3.0),
    ]
    assert determine_exit_code(results, fail_on_cost=20.0) == 0


def test_fail_on_cost_exactly_at_threshold():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=10.0),
    ]
    # >= semantics: exactly at threshold triggers violation
    assert determine_exit_code(results, fail_on_cost=10.0) == 2


def test_fail_on_cost_no_cost_estimates():
    results = [
        FakeResult(confidence="Low"),
        FakeResult(confidence="Medium"),
    ]
    # No cost data on findings → total is 0 → no violation
    assert determine_exit_code(results, fail_on_cost=5.0) == 0


def test_fail_on_cost_not_set():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=100.0),
    ]
    # Without --fail-on-cost, no violation
    assert determine_exit_code(results) == 0


def test_fail_on_confidence_triggers_before_cost():
    results = [
        FakeResult(confidence="High", estimated_monthly_cost_usd=1.0),
    ]
    # Confidence triggers even though cost is below threshold
    assert determine_exit_code(results, fail_on_confidence="HIGH", fail_on_cost=999.0) == 2


def test_fail_on_cost_triggers_when_confidence_passes():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=200.0),
    ]
    # Confidence check passes (LOW < HIGH threshold), but cost exceeds threshold
    assert determine_exit_code(results, fail_on_confidence="HIGH", fail_on_cost=100.0) == 2


def test_fail_on_findings_takes_precedence_over_cost():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=0.01),
    ]
    # --fail-on-findings triggers even with negligible cost
    assert determine_exit_code(results, fail_on_findings=True, fail_on_cost=999.0) == 2


def test_both_confidence_and_cost_pass():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=5.0),
    ]
    # Confidence below threshold AND cost below threshold → pass
    assert determine_exit_code(results, fail_on_confidence="HIGH", fail_on_cost=100.0) == 0


def test_all_three_flags_confidence_triggers():
    results = [
        FakeResult(confidence="High", estimated_monthly_cost_usd=1.0),
    ]
    # All three flags set — confidence triggers first
    assert (
        determine_exit_code(
            results, fail_on_findings=False, fail_on_confidence="HIGH", fail_on_cost=999.0
        )
        == 2
    )


def test_all_three_flags_findings_triggers():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=0.01),
    ]
    # All three flags set — fail_on_findings triggers first
    assert (
        determine_exit_code(
            results, fail_on_findings=True, fail_on_confidence="HIGH", fail_on_cost=999.0
        )
        == 2
    )


def test_all_three_flags_cost_triggers():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=500.0),
    ]
    # All three flags set — only cost exceeds threshold
    assert (
        determine_exit_code(
            results, fail_on_findings=False, fail_on_confidence="HIGH", fail_on_cost=100.0
        )
        == 2
    )


def test_all_three_flags_all_pass():
    results = [
        FakeResult(confidence="Low", estimated_monthly_cost_usd=5.0),
    ]
    # All three flags set — none trigger
    assert (
        determine_exit_code(
            results, fail_on_findings=False, fail_on_confidence="HIGH", fail_on_cost=100.0
        )
        == 0
    )
