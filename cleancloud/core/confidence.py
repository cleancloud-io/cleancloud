from enum import Enum


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


CONFIDENCE_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}
