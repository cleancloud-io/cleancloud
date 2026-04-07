from dataclasses import dataclass, field
from datetime import date as _date
from typing import Any, Dict, List, Optional

_VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
_VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH"}
_VALID_TAG_MODES = {"exclude"}  # "include" (allowlist) planned for a future release
_VALID_CATEGORIES = {"hygiene", "ai", "all"}
_VALID_PROVIDERS = {"aws", "azure", "gcp"}


@dataclass(frozen=True)
class IgnoreTagRuleConfig:
    key: str
    values: List[str] = field(default_factory=list)  # empty = key-only match (any value)


@dataclass
class TagFilteringConfig:
    enabled: bool
    ignore: List[IgnoreTagRuleConfig]
    mode: str = "exclude"  # "exclude" suppresses findings on matched resources
    # "include" (allowlist) is planned — not yet supported


@dataclass
class RuleConfig:
    enabled: bool = True
    # min_cost: per-finding filter using estimated_monthly_cost_usd.
    # Findings with a cost below this threshold are suppressed (cost=None findings are kept).
    min_cost: Optional[float] = None
    params: Dict[str, Any] = field(default_factory=dict)
    # confidence: minimum signal strength to report. Findings below this are suppressed.
    # Accepted values: LOW | MEDIUM | HIGH (case-insensitive, normalised to uppercase).
    confidence: Optional[str] = None
    # override_risk_level: Overrides the `risk` field on matching findings (display/reporting only).
    # Does NOT affect confidence-based CI/CD thresholds.
    override_risk_level: Optional[str] = None


@dataclass
class DefaultsConfig:
    # Same semantics as per-rule min_cost/confidence/override_risk_level — applied globally
    # when a rule has no explicit setting.
    min_cost: Optional[float] = None  # per-finding, uses estimated_monthly_cost_usd
    confidence: Optional[str] = None  # global minimum confidence filter
    override_risk_level: Optional[str] = (
        None  # global risk level override (rarely used; prefer per-rule)
    )


@dataclass(frozen=True)
class ExceptionConfig:
    rule_id: str
    resource_id: str  # supports glob patterns: *, ?, [seq] — e.g. "test-*", "*-staging"
    reason: Optional[str] = None
    account_id: Optional[str] = (
        None  # narrow to a specific AWS account / GCP project / Azure subscription ID
    )
    region: Optional[str] = (
        None  # narrow to a specific region (e.g. "us-east-1"); omit to match all regions
    )
    expires_at: Optional[str] = (
        None  # ISO date "YYYY-MM-DD" — exception skipped with warning after this date
    )


@dataclass(frozen=True)
class CategoriesConfig:
    include: List[str]  # e.g. ["hygiene"], ["ai"], ["hygiene", "ai"]

    def resolved(self) -> str:
        """Return the equivalent --category value: hygiene | ai | all."""
        s = set(self.include)
        if "all" in s or ({"hygiene", "ai"} <= s):
            return "all"
        if "ai" in s:
            return "ai"
        return "hygiene"


@dataclass
class ScanConfig:
    """Execution context defaults — overridden by CLI flags (CLI always wins).

    scan:
      provider: aws               # default provider (overridden by --provider)
      regions: auto               # auto-detect active regions (--all-regions)
      regions: us-east-1          # single region (--region)
      regions:                    # explicit list — not yet supported; use 'auto' for multi-region
        - us-east-1
    """

    provider: Optional[str] = None
    regions: Optional[Any] = None  # "auto" | single region string | list (validated at scan time)


@dataclass
class ThresholdsConfig:
    fail_on_confidence: Optional[str] = None
    fail_on_cost: Optional[float] = None
    fail_on_findings: bool = False


@dataclass
class CleanCloudConfig:
    tag_filtering: Optional[TagFilteringConfig] = None
    rules: Dict[str, RuleConfig] = field(default_factory=dict)
    exceptions: List[ExceptionConfig] = field(default_factory=list)
    thresholds: Optional[ThresholdsConfig] = None
    defaults: Optional[DefaultsConfig] = None
    categories: Optional[CategoriesConfig] = None
    scan: Optional[ScanConfig] = None

    @classmethod
    def empty(cls) -> "CleanCloudConfig":
        return cls()


def load_config(data: Dict[str, Any]) -> CleanCloudConfig:
    allowed_top_level = {
        "version",
        "tag_filtering",
        "rules",
        "exceptions",
        "thresholds",
        "defaults",
        "categories",
        "scan",
    }
    unknown = set(data.keys()) - allowed_top_level
    if unknown:
        raise ValueError(f"Unknown config fields: {unknown}")

    # --- tag_filtering ---
    tag_filtering = None
    tf = data.get("tag_filtering")
    if tf:
        if not isinstance(tf, dict):
            raise ValueError("tag_filtering must be a mapping")
        enabled = tf.get("enabled", True)
        mode = str(tf.get("mode", "exclude")).lower()
        if mode not in _VALID_TAG_MODES:
            raise ValueError(
                f"tag_filtering.mode '{mode}' is not supported. "
                f"Valid values: {sorted(_VALID_TAG_MODES)}"
            )
        ignore = tf.get("ignore", [])
        if not isinstance(ignore, list):
            raise ValueError("tag_filtering.ignore must be a list")
        tag_rules: List[IgnoreTagRuleConfig] = []
        for entry in ignore:
            if not isinstance(entry, dict):
                raise ValueError("Each ignore entry must be a mapping")
            if "key" not in entry:
                raise ValueError("ignore entry must contain 'key'")
            raw_values: List[str] = []
            if "values" in entry:
                v = entry["values"]
                if not isinstance(v, list):
                    raise ValueError("tag_filtering.ignore[].values must be a list")
                raw_values = [str(x) for x in v]
            elif "value" in entry:
                raw_values = [str(entry["value"])]
            # else: empty = key-only match (any value)
            tag_rules.append(IgnoreTagRuleConfig(key=str(entry["key"]), values=raw_values))
        tag_filtering = TagFilteringConfig(enabled=bool(enabled), ignore=tag_rules, mode=mode)

    # --- rules ---
    rules: Dict[str, RuleConfig] = {}
    raw_rules = data.get("rules") or {}
    if not isinstance(raw_rules, dict):
        raise ValueError("rules must be a mapping")
    for rule_id, rule_data in raw_rules.items():
        if not isinstance(rule_data, dict):
            raise ValueError(f"rules.{rule_id} must be a mapping")
        enabled = rule_data.get("enabled", True)
        min_cost = rule_data.get("min_cost")
        if min_cost is not None and not isinstance(min_cost, (int, float)):
            raise ValueError(f"rules.{rule_id}.min_cost must be a number")
        raw_params = rule_data.get("params") or {}
        if not isinstance(raw_params, dict):
            raise ValueError(f"rules.{rule_id}.params must be a mapping")

        raw_confidence = rule_data.get("confidence")
        if raw_confidence and str(raw_confidence).upper() not in _VALID_CONFIDENCE:
            raise ValueError(
                f"rules.{rule_id}.confidence must be low, medium, or high (case-insensitive)"
            )

        raw_override = rule_data.get("override_risk_level")
        if raw_override and str(raw_override).upper() not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"rules.{rule_id}.override_risk_level must be low, medium, or high (case-insensitive)"
            )

        rules[str(rule_id)] = RuleConfig(
            enabled=bool(enabled),
            min_cost=float(min_cost) if min_cost is not None else None,
            params=dict(raw_params),
            confidence=str(raw_confidence).upper() if raw_confidence else None,
            override_risk_level=str(raw_override).upper() if raw_override else None,
        )

    # --- exceptions ---
    exceptions: List[ExceptionConfig] = []
    raw_exceptions = data.get("exceptions") or []
    if not isinstance(raw_exceptions, list):
        raise ValueError("exceptions must be a list")
    for i, entry in enumerate(raw_exceptions):
        if not isinstance(entry, dict):
            raise ValueError(f"exceptions[{i}] must be a mapping")
        if "rule_id" not in entry:
            raise ValueError(f"exceptions[{i}] must contain 'rule_id'")
        if "resource_id" not in entry:
            raise ValueError(f"exceptions[{i}] must contain 'resource_id'")
        expires_at_raw = entry.get("expires_at")
        expires_at = None
        if expires_at_raw is not None:
            expires_at = str(expires_at_raw)
            try:
                _date.fromisoformat(expires_at)
            except ValueError:
                raise ValueError(
                    f"exceptions[{i}].expires_at '{expires_at}' is not a valid ISO date (use YYYY-MM-DD)"
                )
        exceptions.append(
            ExceptionConfig(
                rule_id=str(entry["rule_id"]),
                resource_id=str(entry["resource_id"]),
                reason=str(entry["reason"]) if "reason" in entry else None,
                account_id=str(entry["account_id"]) if "account_id" in entry else None,
                region=str(entry["region"]) if "region" in entry else None,
                expires_at=expires_at,
            )
        )

    # --- thresholds ---
    thresholds = None
    raw_thresholds = data.get("thresholds")
    if raw_thresholds:
        if not isinstance(raw_thresholds, dict):
            raise ValueError("thresholds must be a mapping")
        foc = raw_thresholds.get("fail_on_confidence")
        foc_cost = raw_thresholds.get("fail_on_cost")
        fof = raw_thresholds.get("fail_on_findings", False)
        if foc and str(foc).upper() not in ("LOW", "MEDIUM", "HIGH"):
            raise ValueError(
                "thresholds.fail_on_confidence must be low, medium, or high (case-insensitive)"
            )
        if foc_cost is not None and not isinstance(foc_cost, (int, float)):
            raise ValueError("thresholds.fail_on_cost must be a number")
        thresholds = ThresholdsConfig(
            fail_on_confidence=str(foc).upper() if foc else None,
            fail_on_cost=float(foc_cost) if foc_cost is not None else None,
            fail_on_findings=bool(fof),
        )

    # --- defaults ---
    defaults = None
    raw_defaults = data.get("defaults")
    if raw_defaults:
        if not isinstance(raw_defaults, dict):
            raise ValueError("defaults must be a mapping")
        d_min_cost = raw_defaults.get("min_cost")
        d_confidence = raw_defaults.get("confidence")
        d_override_risk_level = raw_defaults.get("override_risk_level")
        if d_confidence and str(d_confidence).upper() not in _VALID_CONFIDENCE:
            raise ValueError("defaults.confidence must be low, medium, or high (case-insensitive)")
        if d_override_risk_level and str(d_override_risk_level).upper() not in _VALID_RISK_LEVELS:
            raise ValueError(
                "defaults.override_risk_level must be low, medium, or high (case-insensitive)"
            )
        if d_min_cost is not None and not isinstance(d_min_cost, (int, float)):
            raise ValueError("defaults.min_cost must be a number")
        defaults = DefaultsConfig(
            min_cost=float(d_min_cost) if d_min_cost is not None else None,
            confidence=str(d_confidence).upper() if d_confidence else None,
            override_risk_level=(
                str(d_override_risk_level).upper() if d_override_risk_level else None
            ),
        )

    # --- categories ---
    categories = None
    raw_categories = data.get("categories")
    if raw_categories:
        if not isinstance(raw_categories, dict):
            raise ValueError("categories must be a mapping")
        raw_include = raw_categories.get("include", [])
        if not isinstance(raw_include, list):
            raise ValueError("categories.include must be a list")
        for c in raw_include:
            if str(c).lower() not in _VALID_CATEGORIES:
                raise ValueError(
                    f"categories.include contains unknown value '{c}'. "
                    f"Valid values: {sorted(_VALID_CATEGORIES)}"
                )
        categories = CategoriesConfig(include=[str(c).lower() for c in raw_include])

    # --- scan ---
    scan_cfg = None
    raw_scan = data.get("scan")
    if raw_scan:
        if not isinstance(raw_scan, dict):
            raise ValueError("scan must be a mapping")
        scan_provider = raw_scan.get("provider")
        if scan_provider is not None and str(scan_provider).lower() not in _VALID_PROVIDERS:
            raise ValueError(
                f"scan.provider '{scan_provider}' is not valid. "
                f"Valid values: {sorted(_VALID_PROVIDERS)}"
            )
        scan_regions = raw_scan.get("regions")
        if scan_regions is not None:
            if isinstance(scan_regions, str):
                if scan_regions != "auto":
                    raise ValueError(
                        "scan.regions string value must be 'auto'. "
                        "For a specific region use a list: regions: [us-east-1]"
                    )
            elif not isinstance(scan_regions, list):
                raise ValueError(
                    "scan.regions must be 'auto' or a list of regions: [us-east-1, us-west-2]"
                )
        scan_cfg = ScanConfig(
            provider=str(scan_provider).lower() if scan_provider else None,
            regions=scan_regions,
        )

    return CleanCloudConfig(
        tag_filtering=tag_filtering,
        rules=rules,
        exceptions=exceptions,
        thresholds=thresholds,
        defaults=defaults,
        categories=categories,
        scan=scan_cfg,
    )
