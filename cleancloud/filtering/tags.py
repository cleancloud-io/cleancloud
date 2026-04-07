from dataclasses import dataclass, field
from typing import Dict, List

from cleancloud.config.schema import IgnoreTagRuleConfig
from cleancloud.core.finding import Finding, SuppressedFinding
from cleancloud.filtering.decision import DecisionStep, SuppressionReason


@dataclass(frozen=True)
class IgnoreTagRule:
    key: str
    values: List[str] = field(default_factory=list)  # empty = match any value (key-only)

    def matches(self, tags: Dict[str, str]) -> bool:
        if self.key not in tags:
            return False
        if not self.values:  # key-only match
            return True
        return tags.get(self.key) in self.values


@dataclass
class TagFilterResult:
    kept: List[Finding]
    suppressed: List[SuppressedFinding]  # was: ignored: List[Finding]


def compile_rules(config_rules: List[IgnoreTagRuleConfig]) -> List[IgnoreTagRule]:
    return [IgnoreTagRule(key=r.key, values=r.values) for r in config_rules]


def filter_findings_by_tags(
    findings: List[Finding],
    ignore_rules: List[IgnoreTagRule],
) -> TagFilterResult:
    if not ignore_rules:
        return TagFilterResult(kept=findings, suppressed=[])

    kept: List[Finding] = []
    suppressed: List[SuppressedFinding] = []

    for finding in findings:
        # AWS/Azure use "tags"; GCP uses "labels" — check both
        raw_tags = finding.details.get("tags") or finding.details.get("labels") or {}

        # normalize tags to dict[str,str]
        if isinstance(raw_tags, list):
            tags = {t["Key"]: t.get("Value", "") for t in raw_tags}
        elif isinstance(raw_tags, dict):
            tags = raw_tags
        else:
            tags = {}

        matched_rule = None
        for rule in ignore_rules:
            if rule.matches(tags):
                matched_rule = rule
                break

        if matched_rule is not None:
            value_matched = tags.get(matched_rule.key, "")
            if matched_rule.values:
                detail = (
                    f"tag {matched_rule.key}={value_matched} matches values {matched_rule.values}"
                )
            else:
                detail = f"tag key '{matched_rule.key}' present (key-only match)"
            suppressed.append(
                SuppressedFinding(
                    finding=finding,
                    suppression_reason=SuppressionReason.TAG_EXCLUDED,
                    suppression_detail=detail,
                    decision_path=[
                        DecisionStep.EVALUATED,
                        DecisionStep.PASSED_EXCEPTIONS,
                        DecisionStep.PASSED_POLICY_FILTERS,
                        f"{DecisionStep.TAG_FILTERED}: {detail}",
                        DecisionStep.SUPPRESSED,
                    ],
                )
            )
        else:
            kept.append(finding)

    return TagFilterResult(kept=kept, suppressed=suppressed)
