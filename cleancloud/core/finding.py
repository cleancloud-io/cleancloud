from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

from cleancloud.core.confidence import ConfidenceLevel
from cleancloud.core.evidence import Evidence
from cleancloud.core.risk import RiskLevel


@dataclass
class Finding:
    provider: str
    rule_id: str
    resource_type: str
    resource_id: str
    region: Optional[str]

    title: str
    summary: str
    reason: str

    risk: RiskLevel
    confidence: ConfidenceLevel

    detected_at: datetime
    details: Dict[str, Any]
    evidence: Evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "rule_id": self.rule_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "title": self.title,
            "summary": self.summary,
            "reason": self.reason,
            "risk": self.risk.value,
            "confidence": self.confidence.value,
            "detected_at": self.detected_at.isoformat(),
            "details": self.details,
            "evidence": self.evidence,
        }
