import sys
from typing import List, Optional

import click

from cleancloud.policy.exit_policy import EXIT_ERROR

# Known GCP regions (as of 2025)
KNOWN_GCP_REGIONS = {
    # Americas
    "us-central1",
    "us-east1",
    "us-east4",
    "us-east5",
    "us-south1",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
    "northamerica-northeast1",
    "northamerica-northeast2",
    "southamerica-east1",
    "southamerica-west1",
    # Europe
    "europe-central2",
    "europe-north1",
    "europe-southwest1",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "europe-west8",
    "europe-west9",
    "europe-west10",
    "europe-west12",
    # Asia Pacific
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast2",
    "asia-northeast3",
    "asia-south1",
    "asia-south2",
    "asia-southeast1",
    "asia-southeast2",
    "australia-southeast1",
    "australia-southeast2",
    # Middle East & Africa
    "me-central1",
    "me-central2",
    "me-west1",
    "africa-south1",
}


def validate_project_params(projects: Optional[List[str]], all_projects: bool) -> None:
    """Validate GCP project parameters.

    Default behavior (no flags): scan all accessible projects
    --project <id>: scan specific project(s)
    --all-projects: explicit all (same as default)
    """
    if projects and all_projects:
        click.echo("Warning: --all-projects flag is redundant with --project")
        click.echo("   Will scan the specified projects only")
        click.echo()


def validate_region_params(region: Optional[str]) -> None:
    if region and region not in KNOWN_GCP_REGIONS:
        click.echo(f"Error: '{region}' is not a valid GCP region")
        click.echo()
        click.echo("Common GCP regions:")
        click.echo("  us-central1, us-east1, us-west1, us-west2")
        click.echo("  europe-west1, europe-west2, europe-west3, europe-west4")
        click.echo("  asia-east1, asia-northeast1, asia-southeast1, australia-southeast1")
        click.echo()
        click.echo("All known regions:")
        regions_list = sorted(KNOWN_GCP_REGIONS)
        for i in range(0, len(regions_list), 3):
            click.echo("  " + ", ".join(regions_list[i : i + 3]))
        click.echo()
        click.echo("Tip: GCP uses region names like 'us-central1', not 'us-east-1'")
        click.echo("   Leave out --region to scan all regions")
        sys.exit(EXIT_ERROR)
