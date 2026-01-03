from dataclasses import dataclass
from typing import Dict, List, Optional

from cleancloud.config.schema import IgnoreTagRuleConfig
from cleancloud.core.finding import Finding


@dataclass(frozen=True)
class IgnoreTagRule:
    key: str
    value: Optional[str] = None

    def matches(self, tags: Dict[str, str]) -> bool:
        if self.key not in tags:
            return False
        if self.value is None:
            return True
        return tags.get(self.key) == self.value


@dataclass
class TagFilterResult:
    kept: List[Finding]
    ignored: List[Finding]


def compile_rules(config_rules: List[IgnoreTagRuleConfig]) -> List[IgnoreTagRule]:
    return [IgnoreTagRule(key=r.key, value=r.value) for r in config_rules]


def filter_findings_by_tags(
    findings: List[Finding],
    ignore_rules: List[IgnoreTagRule],
) -> TagFilterResult:
    if not ignore_rules:
        return TagFilterResult(kept=findings, ignored=[])

    kept: List[Finding] = []
    ignored: List[Finding] = []

    for finding in findings:
        raw_tags = finding.details.get("tags", {}) or {}

        # normalize tags to dict[str,str]
        if isinstance(raw_tags, list):
            tags = {t["Key"]: t.get("Value", "") for t in raw_tags}
        elif isinstance(raw_tags, dict):
            tags = raw_tags
        else:
            tags = {}

        if any(rule.matches(tags) for rule in ignore_rules):
            ignored.append(finding)
        else:
            kept.append(finding)

    return TagFilterResult(kept=kept, ignored=ignored)
