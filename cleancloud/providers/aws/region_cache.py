"""
File-based cache for active region discovery.

Keyed by AWS account ID. TTL defaults to 24 hours — regions rarely change
(governed orgs require SCP changes to add/remove regions).

Cache location: ~/.cleancloud/region_cache.json
"""

import json
import time
from pathlib import Path
from typing import List, Optional

CACHE_PATH = Path.home() / ".cleancloud" / "region_cache.json"
CACHE_TTL_SECONDS = 86400  # 24 hours


def _load() -> dict:
    try:
        return json.loads(CACHE_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(data, indent=2))


def get_cached_regions(account_id: str) -> Optional[List[str]]:
    data = _load()
    entry = data.get(account_id)
    if not entry:
        return None
    if time.time() - entry["cached_at"] > CACHE_TTL_SECONDS:
        return None
    return entry["regions"]


def set_cached_regions(account_id: str, regions: List[str]) -> None:
    data = _load()
    data[account_id] = {"cached_at": time.time(), "regions": regions}
    _save(data)
