from typing import Optional

import click
import yaml

from cleancloud.config.schema import CleanCloudConfig, load_config
from cleancloud.doctor.runner import run_doctor


@click.command("doctor")
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["aws", "azure"]),
    help="Cloud provider to validate (omit to check both)",
)
@click.option("--region", default="us-east-1", help="AWS region for validation")
@click.option("--profile", default=None, help="AWS profile name")
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to cleancloud.yaml",
)
def doctor(provider: Optional[str], region: str, profile: Optional[str], config: Optional[str]):
    click.echo("🩺 Running CleanCloud doctor")
    click.echo()

    run_doctor(provider=provider, profile=profile, region=region)

    try:
        cfg = CleanCloudConfig.empty()
        if config:
            with open(config) as f:
                raw = yaml.safe_load(f) or {}
                cfg = load_config(raw)

        if cfg.tag_filtering and cfg.tag_filtering.enabled:
            click.echo()
            click.echo("ℹ️  Tag filtering is enabled — some findings may be intentionally ignored")
            click.echo()

    except Exception as e:
        # Config validation failure is not fatal for doctor command
        click.echo(f"⚠️  Config validation warning: {e}")
        click.echo()
