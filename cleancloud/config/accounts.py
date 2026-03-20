from dataclasses import dataclass
from typing import List, Optional

import yaml


@dataclass
class AccountConfig:
    id: str
    name: str = ""

    def __post_init__(self):
        self.id = str(self.id)
        if not self.name:
            self.name = self.id


@dataclass
class MultiAccountConfig:
    accounts: List[AccountConfig]
    role_name: str = "CleanCloudReadOnlyRole"
    external_id: Optional[str] = None
    scan_timeout: int = 3600


def load_accounts_config(path: str) -> MultiAccountConfig:
    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    accounts = []
    for a in raw.get("accounts", []):
        accounts.append(
            AccountConfig(
                id=str(a["id"]),
                name=a.get("name", str(a["id"])),
            )
        )

    if not accounts:
        raise ValueError(f"No accounts found in {path} — add at least one account entry")

    return MultiAccountConfig(
        accounts=accounts,
        role_name=raw.get("role_name", "CleanCloudReadOnlyRole"),
        external_id=raw.get("external_id"),
        scan_timeout=int(raw.get("scan_timeout", 3600)),
    )


def parse_inline_accounts(accounts_str: str) -> List[AccountConfig]:
    """Parse comma-separated account IDs: '111111111111,222222222222'"""
    ids = [a.strip() for a in accounts_str.split(",") if a.strip()]
    if not ids:
        raise ValueError("--accounts must be a comma-separated list of account IDs")
    return [AccountConfig(id=a) for a in ids]
