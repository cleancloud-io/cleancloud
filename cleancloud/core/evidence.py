from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Evidence:
    signals_used: List[str]
    signals_not_checked: List[str]
    time_window: Optional[str] = None
