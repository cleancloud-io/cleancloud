import json
import sys
from datetime import datetime
from typing import List, Tuple

import click
import botocore.exceptions

from cleancloud.providers.aws.session import create_aws_session
from cleancloud.providers.aws.rules.ebs_unattached import find_unattached_ebs_volumes


@click.group()
def cli():
    """
    CleanCloud - Cloud hygiene scanner (safe by design).
    """
    pass


# -------------------------------------------------------------------
# HUMAN OUTPUT (INLINE TO AVOID IMPORT ISSUES)
# -------------------------------------------------------------------
def _print_human_readable(result: dict):
    print("\nCleanCloud Scan Results")
    print("=" * 25)
    print(f"Provider: {result['provider']}")
    print(f"Account:  {result['account_id']}")
    print(f"Region:   {result['region']}")
    print(f"Scan at:  {result['scan_time']}")
    print()

    findings = result.get("findings", [])
    if not findings:
        print("✅ No issues found.")
        return

    for f in findings:
        print(f"- [{f['confidence']}] {f['summary']}")
        print(f"  Rule: {f['rule_id']}")
        print(f"  Resource: {f['resource_id']}")
        print(f"  Risk: {f['risk']}")
        print()


# -------------------------------------------------------------------
# SCAN COMMAND
# -------------------------------------------------------------------
@cli.command()
@click.option(
    "--provider",
    default="aws",
    type=click.Choice(["aws", "azure"]),
    help="Cloud provider (default: aws)",
)
@click.option(
    "--profile",
    default=None,
    help="Cloud credentials profile (AWS only for now)",
)
@click.option(
    "--region",
    default="us-east-1",
    help="Cloud region (AWS only for now)",
)
@click.option(
    "--output",
    default="human",
    type=click.Choice(["human", "json"]),
    help="Output format",
)
def scan(provider: str, profile: str, region: str, output: str):
    """
    Scan cloud resources for hygiene issues.
    """
    scan_time = datetime.utcnow().isoformat() + "Z"

    if provider == "aws":
        findings, account_id = _scan_aws(profile=profile, region=region)
    elif provider == "azure":
        click.echo("Azure scanning is not implemented yet.")
        sys.exit(0)
    else:
        click.echo(f"Unsupported provider: {provider}")
        sys.exit(1)

    result = {
        "provider": provider,
        "account_id": account_id,
        "region": region,
        "scan_time": scan_time,
        "findings": findings,
    }

    if output == "json":
        click.echo(json.dumps(result, indent=2, default=str))
    else:
        _print_human_readable(result)


def _scan_aws(profile: str, region: str) -> Tuple[List[dict], str]:
    """
    Run AWS hygiene scans for a single region.
    """
    session = create_aws_session(profile=profile, region=region)

    sts = session.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]

    findings: List[dict] = []

    click.echo("Scanning for unattached EBS volumes...")
    findings.extend(
        find_unattached_ebs_volumes(
            session=session,
            region=region,
        )
    )

    return findings, account_id


# -------------------------------------------------------------------
# DOCTOR COMMAND
# -------------------------------------------------------------------
@cli.command()
@click.option(
    "--provider",
    default="aws",
    type=click.Choice(["aws", "azure"]),
    help="Cloud provider (default: aws)",
)
@click.option(
    "--profile",
    default=None,
    help="Cloud credentials profile (AWS only for now)",
)
@click.option(
    "--region",
    default="us-east-1",
    help="Cloud region (AWS only for now)",
)
def doctor(provider: str, profile: str, region: str):
    """
    Preflight check: validate credentials and required permissions.
    """
    click.echo("🩺 Running CleanCloud doctor...")

    if provider == "aws":
        _doctor_aws(profile=profile, region=region)
    elif provider == "azure":
        click.echo("Azure doctor is not implemented yet.")
        sys.exit(0)
    else:
        click.echo(f"Unsupported provider: {provider}")
        sys.exit(1)


def _doctor_aws(profile: str, region: str):
    try:
        session = create_aws_session(profile=profile, region=region)

        sts = session.client("sts")
        identity = sts.get_caller_identity()

        click.echo("✅ AWS credentials valid")
        click.echo(f"Account ID: {identity['Account']}")
        click.echo(f"ARN: {identity['Arn']}")

        ec2 = session.client("ec2")
        ec2.describe_volumes(MaxResults=6)

        click.echo("✅ Required EC2 permissions present (DescribeVolumes)")
        click.echo("\n🎉 Environment is ready to run CleanCloud scans")

    except botocore.exceptions.NoCredentialsError:
        click.echo("❌ No AWS credentials found")
        click.echo("Fix: configure credentials or specify --profile")
        sys.exit(1)

    except botocore.exceptions.ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code in ("UnauthorizedOperation", "AccessDenied"):
            click.echo("❌ Missing required AWS permissions")
            click.echo("Fix: attach CleanCloudReadOnlyAWS policy")
        else:
            click.echo(f"❌ AWS error: {e}")

        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
