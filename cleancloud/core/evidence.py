from dataclasses import dataclass
from typing import Any, List, Optional


@dataclass
class Evidence:
    signals_used: List[str]
    signals_not_checked: List[Any]  # str for blind-spots; dict for structured diagnostics
    time_window: Optional[str] = None
