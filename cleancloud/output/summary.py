from collections import Counter
from typing import Dict, List

from cleancloud.core.finding import Finding


def build_summary(findings: List[Finding]) -> Dict[str, object]:
    by_provider = Counter(f.provider for f in findings)
    by_risk = Counter(f.risk for f in findings)
    by_confidence = Counter(f.confidence for f in findings)

    return {
        "total_findings": len(findings),
        "by_provider": dict(by_provider),
        "by_risk": dict(by_risk),
        "by_confidence": dict(by_confidence),
    }
