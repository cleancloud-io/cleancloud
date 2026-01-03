import csv
from pathlib import Path
from typing import List

from cleancloud.core.finding import Finding

CSV_FIELDS = [
    "provider",
    "rule_id",
    "resource_type",
    "resource_id",
    "region",
    "title",
    "summary",
    "reason",
    "risk",
    "confidence",
    "detected_at",
]


def write_csv(findings: List[Finding], output_file: Path):
    with output_file.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for finding in findings:
            row = finding.to_dict()

            # flatten only top-level fields
            writer.writerow({k: row.get(k) for k in CSV_FIELDS})
