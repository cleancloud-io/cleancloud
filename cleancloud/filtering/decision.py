"""
Vocabulary constants for SuppressedFinding.decision_path entries and suppression reasons.

Use these instead of raw strings to ensure consistency across all
filtering stages and make analytics/UI integration straightforward.
"""


class DecisionStep:
    EVALUATED = "EVALUATED"
    PASSED_EXCEPTIONS = "PASSED_EXCEPTIONS"
    PASSED_POLICY_FILTERS = "PASSED_POLICY_FILTERS"
    EXCEPTION_MATCHED = "EXCEPTION_MATCHED"
    EXCEPTION_EXPIRED = "EXCEPTION_EXPIRED"  # exception would have matched but is past expires_at
    MIN_COST_FILTERED = "MIN_COST_FILTERED"
    CONFIDENCE_FILTERED = "CONFIDENCE_FILTERED"
    TAG_FILTERED = "TAG_FILTERED"
    RISK_OVERRIDDEN = "RISK_OVERRIDDEN"
    SUPPRESSED = "SUPPRESSED"
    KEPT = "KEPT"


class SuppressionReason:
    """
    Fixed taxonomy for SuppressedFinding.suppression_reason.

    These constants are the authoritative vocabulary — never use raw strings.
    Analytics, JSON output, and suppression_summary keys all use these values.
    """

    EXCEPTION_MATCH = "exception"  # Human-approved exception; bypasses ALL other filters
    EXCEPTION_EXPIRED = "exception_expired"  # Exception would have matched but is past expires_at
    BELOW_MIN_COST = "min_cost"  # Estimated cost below configured min_cost threshold
    LOW_CONFIDENCE = "confidence"  # Confidence level below configured minimum
    TAG_EXCLUDED = "tag"  # Resource tag/label matched an ignore_tags rule
