import sys
from importlib.metadata import version as pkg_version

import click

from cleancloud.doctor.command import doctor
from cleancloud.scan.command import scan


def _version_info():
    """Build version string with provider availability."""
    ver = pkg_version("cleancloud")
    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    # Check installed providers
    providers = []
    try:
        import boto3  # noqa: F401

        providers.append("aws")
    except ImportError:
        pass
    try:
        import azure.identity  # noqa: F401

        providers.append("azure")
    except ImportError:
        pass

    lines = [
        f"cleancloud {ver}",
        f"Python {py}",
        f"Providers: {', '.join(providers) if providers else 'none installed'}",
    ]

    if not providers:
        lines.append("")
        lines.append("Install providers: pipx install cleancloud --force")

    return "\n".join(lines)


@click.group()
@click.version_option(
    version=pkg_version("cleancloud"), prog_name="cleancloud", message=_version_info()
)
def cli():
    """CleanCloud – Safe cloud hygiene scanner"""
    pass


cli.add_command(doctor)
cli.add_command(scan)


def main():
    cli()


if __name__ == "__main__":
    main()
