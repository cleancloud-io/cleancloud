from datetime import datetime, timezone
from typing import Optional

import click

from cleancloud.demo.findings import ALL_FINDINGS, AWS_FINDINGS, AZURE_FINDINGS, GCP_FINDINGS
from cleancloud.output.human import print_human
from cleancloud.output.summary import _print_summary, build_summary


@click.command("demo")
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure", "gcp"]),
    default=None,
    help="Show demo findings for a specific provider (default: all)",
)
def demo(provider: Optional[str]):
    """Show realistic sample findings without cloud credentials."""
    click.echo()
    click.echo("=" * 60)
    click.echo("  DEMO MODE — sample findings (no cloud access required)")
    click.echo("  Run 'cleancloud scan --provider aws' to scan your own environment")
    click.echo("=" * 60)

    if provider == "aws":
        findings = AWS_FINDINGS
        regions = ["us-east-1", "us-west-2", "eu-west-1"]
        region_mode = "all-regions"
    elif provider == "azure":
        findings = AZURE_FINDINGS
        regions = ["Production", "Staging"]
        region_mode = "all"
    elif provider == "gcp":
        findings = GCP_FINDINGS
        regions = ["us-central1", "us-central1-a", "us-central1-b", "global"]
        region_mode = "all-regions"
    else:
        findings = ALL_FINDINGS
        regions = ["us-east-1", "us-west-2", "eu-west-1", "eastus", "westeurope", "us-central1"]
        region_mode = "all-regions"

    print_human(findings)

    summary = build_summary(findings)
    summary["scanned_at"] = datetime.now(timezone.utc).isoformat()
    summary["provider"] = provider or "mixed"
    summary["regions_scanned"] = regions

    _print_summary(summary, region_selection_mode=region_mode)

    click.echo()
    click.echo("  In a typical mid-size environment, patterns like these represent")
    click.echo("  $2,000–$10,000/month in avoidable waste across all regions and accounts.")
    click.echo()
    click.echo("=" * 60)
    click.echo("  Ready to scan your real environment?")
    click.echo()
    click.echo("  AWS:   cleancloud scan --provider aws --all-regions")
    click.echo("  Azure: cleancloud scan --provider azure")
    click.echo("  GCP:   cleancloud scan --provider gcp --project YOUR_PROJECT_ID")
    click.echo("=" * 60)
    click.echo()
