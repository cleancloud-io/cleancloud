from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class IgnoreTagRuleConfig:
    key: str
    value: Optional[str] = None


@dataclass
class TagFilteringConfig:
    enabled: bool
    ignore: List[IgnoreTagRuleConfig]


@dataclass
class CleanCloudConfig:
    tag_filtering: Optional[TagFilteringConfig] = None

    @classmethod
    def empty(cls) -> "CleanCloudConfig":
        return cls(tag_filtering=None)


def load_config(data: Dict[str, Any]) -> CleanCloudConfig:
    allowed_top_level = {"version", "tag_filtering"}
    unknown = set(data.keys()) - allowed_top_level
    if unknown:
        raise ValueError(f"Unknown config fields: {unknown}")

    tf = data.get("tag_filtering")
    if not tf:
        return CleanCloudConfig.empty()

    if not isinstance(tf, dict):
        raise ValueError("tag_filtering must be a mapping")

    enabled = tf.get("enabled", True)
    ignore = tf.get("ignore", [])

    if not isinstance(ignore, list):
        raise ValueError("tag_filtering.ignore must be a list")

    rules: List[IgnoreTagRuleConfig] = []
    for entry in ignore:
        if not isinstance(entry, dict):
            raise ValueError("Each ignore entry must be a mapping")

        if "key" not in entry:
            raise ValueError("ignore entry must contain 'key'")

        rules.append(
            IgnoreTagRuleConfig(
                key=str(entry["key"]),
                value=str(entry["value"]) if "value" in entry else None,
            )
        )

    return CleanCloudConfig(
        tag_filtering=TagFilteringConfig(
            enabled=bool(enabled),
            ignore=rules,
        )
    )
