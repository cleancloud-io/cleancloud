import csv
from pathlib import Path
from typing import List

from cleancloud.core.finding import Finding

CSV_FIELDS = [
    "account_id",
    "account_name",
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
    "estimated_monthly_cost_usd",
]


def write_csv(findings: List[Finding], output_file: Path):
    with output_file.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for finding in findings:
            if not isinstance(finding, Finding):
                raise TypeError(
                    f"write_csv only accepts Finding objects, got {type(finding).__name__}"
                )
            row = finding.to_dict()

            # flatten only top-level fields
            writer.writerow({k: row.get(k) for k in CSV_FIELDS})
