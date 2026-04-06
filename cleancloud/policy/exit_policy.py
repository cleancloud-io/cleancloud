from typing import List, Optional

from cleancloud.core.confidence import CONFIDENCE_ORDER

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_POLICY_VIOLATION = 2
EXIT_PERMISSION_ERROR = 3


def determine_exit_code(
    findings: List[object],
    *,
    fail_on_findings: bool = False,
    fail_on_confidence: Optional[str] = None,
    fail_on_cost: Optional[float] = None,
) -> int:
    """
    Determine process exit code based on findings and policy thresholds.

    Rules (in order of precedence):

    1. No findings → EXIT_OK
    2. --fail-on-findings → any finding fails
    3. --fail-on-confidence X → any finding with confidence >= X fails
    4. --fail-on-cost X → total estimated waste >= X fails
    5. Default behavior (no flags) → EXIT_OK (report-only, safe by default)
    """

    if not findings:
        return EXIT_OK

    # Hard override: fail on any finding
    if fail_on_findings:
        return EXIT_POLICY_VIOLATION

    # Confidence-based evaluation (only when explicitly configured)
    if fail_on_confidence:
        threshold = CONFIDENCE_ORDER.get(fail_on_confidence.upper())

        for f in findings:
            confidence = getattr(f, "confidence", None)
            if not confidence:
                continue

            # Handle both ConfidenceLevel enum and string confidence
            if hasattr(confidence, "value"):
                confidence_str = confidence.value.upper()
            else:
                confidence_str = str(confidence).upper()

            if CONFIDENCE_ORDER.get(confidence_str, 0) >= threshold:
                return EXIT_POLICY_VIOLATION

    # Cost-based evaluation (only when explicitly configured)
    if fail_on_cost is not None:
        total_cost = sum(
            getattr(f, "estimated_monthly_cost_usd", None) or 0
            for f in findings
            if getattr(f, "estimated_monthly_cost_usd", None) is not None
        )
        if total_cost >= fail_on_cost:
            return EXIT_POLICY_VIOLATION

    return EXIT_OK
