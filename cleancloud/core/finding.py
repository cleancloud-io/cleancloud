from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

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

    estimated_monthly_cost_usd: Optional[float] = None
    account_id: Optional[str] = None
    account_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
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
        if self.estimated_monthly_cost_usd is not None:
            d["estimated_monthly_cost_usd"] = self.estimated_monthly_cost_usd
        if self.account_id is not None:
            d["account_id"] = self.account_id
        if self.account_name is not None:
            d["account_name"] = self.account_name
        return d


@dataclass
class SuppressedFinding:
    """A finding that was suppressed by the filtering pipeline.

    Carries the original finding alongside structured suppression metadata so that
    suppression decisions are auditable, exportable, and queryable — not ephemeral.
    """

    finding: Finding
    suppression_reason: str  # "exception" | "min_cost" | "confidence" | "tag"
    suppression_detail: (
        str  # human-readable explanation of why this specific finding was suppressed
    )
    decision_path: List[str]  # ordered trace: ["evaluated", "<what happened>", "suppressed"]

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "rule_id": self.finding.rule_id,
            "resource_id": self.finding.resource_id,
            "region": self.finding.region,
            "title": self.finding.title,
            "confidence": self.finding.confidence.value,
            "suppression_reason": self.suppression_reason,
            "suppression_detail": self.suppression_detail,
            "decision_path": self.decision_path,
        }
        if self.finding.estimated_monthly_cost_usd is not None:
            d["estimated_monthly_cost_usd"] = self.finding.estimated_monthly_cost_usd
        if self.finding.account_id is not None:
            d["account_id"] = self.finding.account_id
        if self.finding.account_name is not None:
            d["account_name"] = self.finding.account_name
        return d
