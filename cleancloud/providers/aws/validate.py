import sys
from typing import Optional

import click

from cleancloud.policy.exit_policy import EXIT_ERROR

# Known AWS regions (as of 2025)
KNOWN_AWS_REGIONS = {
    # US
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    # Canada
    "ca-central-1",
    # Europe
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "eu-central-2",
    # Asia Pacific
    "ap-south-1",
    "ap-south-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-east-1",
    # South America
    "sa-east-1",
    # Middle East
    "me-south-1",
    "me-central-1",
    # Africa
    "af-south-1",
    # GovCloud
    "us-gov-east-1",
    "us-gov-west-1",
    # China (separate partition, requires special credentials)
    "cn-north-1",
    "cn-northwest-1",
}


def validate_region_params(region: Optional[str], all_regions: bool):
    # Validate region name if provided
    if region and region not in KNOWN_AWS_REGIONS:
        click.echo(f"Error: '{region}' is not a valid AWS region")
        click.echo()
        click.echo("Common AWS regions:")
        click.echo("  us-east-1, us-east-2, us-west-1, us-west-2")
        click.echo("  eu-west-1, eu-central-1, ap-southeast-1, ap-northeast-1")
        click.echo()
        click.echo("All known regions:")
        regions_list = sorted(KNOWN_AWS_REGIONS)
        for i in range(0, len(regions_list), 4):
            click.echo("  " + ", ".join(regions_list[i : i + 4]))
        click.echo()
        sys.exit(EXIT_ERROR)

    if not region and not all_regions:
        click.echo("Error: Must specify either --region or --all-regions for AWS")
        click.echo()
        click.echo("Examples:")
        click.echo("  cleancloud scan --provider aws --region us-east-1")
        click.echo("  cleancloud scan --provider aws --all-regions")
        click.echo()
        click.echo("Tip: Use --all-regions to automatically detect and scan")
        click.echo("   regions with resources (volumes, snapshots, logs)")
        sys.exit(EXIT_ERROR)

    if region and all_regions:
        click.echo("Error: Cannot specify both --region and --all-regions")
        click.echo()
        click.echo("Choose one:")
        click.echo("  --region us-east-1        # Scan specific region")
        click.echo("  --all-regions             # Scan all active regions")
        sys.exit(EXIT_ERROR)
