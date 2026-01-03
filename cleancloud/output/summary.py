from collections import Counter
from typing import Dict, List

import click

from cleancloud.core.finding import Finding


def build_summary(findings: List[Finding]) -> Dict[str, object]:
    by_provider = Counter(f.provider for f in findings)
    by_risk = Counter(f.risk for f in findings)
    by_confidence = Counter(f.confidence for f in findings)

    return {
        "total_findings": len(findings),
        "by_provider": dict(by_provider),
        "by_risk": dict(by_risk),
        "by_confidence": dict(by_confidence),
    }


def _format_enum_counts(data: dict) -> dict[str, int]:
    result = {}
    for key, value in data.items():
        if hasattr(key, "value"):
            result[key.value] = value
        else:
            result[str(key)] = value
    return result


def _print_summary(summary: dict, region_selection_mode: str = None):
    click.echo("\n--- Scan Summary ---")
    click.echo(f"Total findings: {summary['total_findings']}")

    # By risk
    by_risk = _format_enum_counts(summary.get("by_risk", {}))
    if by_risk:
        click.echo("\nBy risk:")
        for risk in sorted(by_risk):
            click.echo(f"  {risk}: {by_risk[risk]}")

    # By confidence
    by_conf = _format_enum_counts(summary.get("by_confidence", {}))
    if by_conf:
        click.echo("\nBy confidence:")
        for conf in sorted(by_conf):
            click.echo(f"  {conf}: {by_conf[conf]}")

    # Regions scanned
    regions_scanned = summary.get("regions_scanned", [])
    if isinstance(regions_scanned, list):
        regions_str = ", ".join(regions_scanned)
    else:
        regions_str = str(regions_scanned)

    click.echo(f"\nRegions scanned: {regions_str}", nl=False)

    if region_selection_mode == "all-regions":
        click.echo(" (auto-detected)")
    elif region_selection_mode == "explicit":
        click.echo(" (explicit)")
    else:
        click.echo()

    click.echo(f"Scanned at: {summary['scanned_at']}")

    # Tag filtering visibility
    if summary.get("ignored_by_tag_policy", 0) > 0:
        click.echo(f"Ignored by tag policy: {summary['ignored_by_tag_policy']}")

    # Success message
    if summary["total_findings"] == 0:
        click.echo()
        click.echo("🎉 No hygiene issues detected")
        click.echo()
