import sys
from typing import List, Optional

import click

from cleancloud.policy.exit_policy import EXIT_ERROR

# Known Azure locations (as of 2025)
KNOWN_AZURE_LOCATIONS = {
    # United States
    "eastus",
    "eastus2",
    "westus",
    "westus2",
    "westus3",
    "centralus",
    "northcentralus",
    "southcentralus",
    "westcentralus",
    # Europe
    "northeurope",
    "westeurope",
    # UK
    "uksouth",
    "ukwest",
    # Asia Pacific
    "southeastasia",
    "eastasia",
    # Australia
    "australiaeast",
    "australiasoutheast",
    "australiacentral",
    "australiacentral2",
    # Japan
    "japaneast",
    "japanwest",
    # India
    "centralindia",
    "southindia",
    "westindia",
    # Canada
    "canadacentral",
    "canadaeast",
    # Korea
    "koreacentral",
    "koreasouth",
    # France
    "francecentral",
    "francesouth",
    # Germany
    "germanynorth",
    "germanywestcentral",
    # Norway
    "norwayeast",
    "norwaywest",
    # Switzerland
    "switzerlandnorth",
    "switzerlandwest",
    # UAE
    "uaenorth",
    "uaecentral",
    # Brazil
    "brazilsouth",
    "brazilsoutheast",
    # South Africa
    "southafricanorth",
    "southafricawest",
    # Sweden
    "swedencentral",
    "swedensouth",
    # Qatar
    "qatarcentral",
    # Poland
    "polandcentral",
    # Italy
    "italynorth",
}


def validate_subscription_params(
    subscriptions: Optional[List[str]], all_subscriptions: bool
) -> None:
    """Validate Azure subscription parameters.

    Default behavior (no flags): scan all subscriptions
    --subscription <id>: scan specific subscription(s)
    --all-subscriptions: explicit all (same as default)
    """

    # Both flags specified - this is redundant but acceptable
    if subscriptions and all_subscriptions:
        click.echo("Warning: --all-subscriptions flag is redundant with --subscription")
        click.echo("   Will scan the specified subscriptions only")
        click.echo()


def validate_region_params(region: Optional[str]) -> None:
    if region and region not in KNOWN_AZURE_LOCATIONS:
        click.echo(f"Error: '{region}' is not a valid Azure location")
        click.echo()
        click.echo("Common Azure locations:")
        click.echo("  eastus, eastus2, westus, westus2, centralus")
        click.echo("  northeurope, westeurope, uksouth, ukwest")
        click.echo("  southeastasia, eastasia, australiaeast, japaneast")
        click.echo()
        click.echo("All known locations:")
        locations_list = sorted(KNOWN_AZURE_LOCATIONS)
        for i in range(0, len(locations_list), 4):
            click.echo("  " + ", ".join(locations_list[i : i + 4]))
        click.echo()
        click.echo("Tip: Azure uses location names like 'eastus', not 'us-east-1'")
        click.echo("   Leave out --region to scan all locations")
        sys.exit(EXIT_ERROR)
