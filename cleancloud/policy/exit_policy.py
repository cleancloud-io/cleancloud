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
) -> int:
    """
    Determine process exit code based on findings and confidence thresholds.

    Rules (in order of precedence):

    1. No findings → EXIT_OK
    2. --fail-on-findings → any finding fails
    3. --fail-on-confidence X → any finding with confidence >= X fails
    4. Default behavior → HIGH confidence findings fail
    """

    if not findings:
        return EXIT_OK

    # Hard override: fail on any finding
    if fail_on_findings:
        return EXIT_POLICY_VIOLATION

    # Normalize confidence threshold
    threshold = (
        CONFIDENCE_ORDER.get(fail_on_confidence.upper())
        if fail_on_confidence
        else CONFIDENCE_ORDER["HIGH"]
    )

    # Confidence-based evaluation
    for f in findings:
        confidence = getattr(f, "confidence", None) or f.confidence
        if not confidence:
            continue

        if CONFIDENCE_ORDER.get(confidence.upper(), 0) >= threshold:
            return EXIT_POLICY_VIOLATION

    return EXIT_OK
