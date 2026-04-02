from typing import Optional

import click
import yaml

from cleancloud.config.schema import CleanCloudConfig, load_config
from cleancloud.doctor.runner import run_doctor


@click.command("doctor")
@click.option(
    "--provider",
    default=None,
    type=click.Choice(["aws", "azure", "gcp"]),
    help="Cloud provider to validate (omit to check all)",
)
@click.option("--region", default=None, help="AWS region for validation (default: us-east-1)")
@click.option("--profile", default=None, help="AWS profile name")
@click.option(
    "--project",
    default=None,
    help="GCP project ID to probe permissions against (GCP only)",
)
@click.option(
    "--category",
    default="hygiene",
    type=click.Choice(["hygiene", "ai", "all"]),
    help="Permission set to validate: hygiene (default), ai (SageMaker), or all",
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to cleancloud.yaml",
)
@click.option(
    "--multi-account",
    "multi_account_file",
    type=click.Path(exists=True),
    default=None,
    help="Validate cross-account role access for each account in .cleancloud/accounts.yaml",
)
@click.option(
    "--role-name",
    default="CleanCloudReadOnlyRole",
    show_default=True,
    help="IAM role name to validate in each target account",
)
def doctor(
    provider: Optional[str],
    region: str,
    profile: Optional[str],
    project: Optional[str],
    category: str,
    config: Optional[str],
    multi_account_file: Optional[str],
    role_name: str,
):
    click.echo("Running CleanCloud doctor")
    click.echo()

    if category == "ai" and provider not in (None, "aws", "azure", "gcp"):
        raise click.UsageError("--category ai is only supported with --provider aws, azure, or gcp")

    if multi_account_file:
        if provider != "aws" and provider is not None:
            click.echo("Error: --multi-account is only supported with --provider aws")
            import sys

            sys.exit(1)
        from cleancloud.config.accounts import load_accounts_config
        from cleancloud.doctor.aws import run_aws_multi_account_doctor

        ma_config = load_accounts_config(multi_account_file)
        if role_name != "CleanCloudReadOnlyRole":
            ma_config.role_name = role_name
        run_aws_multi_account_doctor(ma_config, profile=profile, region=region)
        return

    run_doctor(
        provider=provider, profile=profile, region=region, project=project, category=category
    )

    try:
        cfg = CleanCloudConfig.empty()
        if config:
            with open(config) as f:
                raw = yaml.safe_load(f) or {}
                cfg = load_config(raw)

        if cfg.tag_filtering and cfg.tag_filtering.enabled:
            click.echo()
            click.echo(
                "Note: Tag filtering is enabled - some findings may be intentionally ignored"
            )
            click.echo()

    except Exception as e:
        # Config validation failure is not fatal for doctor command
        click.echo(f"Warning: Config validation warning: {e}")
        click.echo()
