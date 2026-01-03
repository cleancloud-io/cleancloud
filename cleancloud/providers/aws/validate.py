import sys
from typing import Optional

import click

from cleancloud.policy.exit_policy import EXIT_ERROR


def validate_region_params(region: Optional[str], all_regions: bool):

    if not region and not all_regions:
        click.echo("❌ Error: Must specify either --region or --all-regions for AWS")
        click.echo()
        click.echo("Examples:")
        click.echo("  cleancloud scan --provider aws --region us-east-1")
        click.echo("  cleancloud scan --provider aws --all-regions")
        click.echo()
        click.echo("💡 Tip: Use --all-regions to automatically detect and scan")
        click.echo("   regions with resources (volumes, snapshots, logs)")
        sys.exit(EXIT_ERROR)

    if region and all_regions:
        click.echo("❌ Error: Cannot specify both --region and --all-regions")
        click.echo()
        click.echo("Choose one:")
        click.echo("  --region us-east-1        # Scan specific region")
        click.echo("  --all-regions             # Scan all active regions")
        sys.exit(EXIT_ERROR)
