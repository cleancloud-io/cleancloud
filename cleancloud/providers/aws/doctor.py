from typing import Optional

import click

from cleancloud.providers.aws.session import create_aws_session


def run_aws_doctor(profile: Optional[str], region: str):
    session = create_aws_session(profile=profile, region=region)

    sts = session.client("sts")
    identity = sts.get_caller_identity()

    click.echo("✅ AWS credentials valid")
    click.echo(f"Account: {identity['Account']}")
    click.echo(f"ARN: {identity['Arn']}")

    ec2 = session.client("ec2")
    ec2.describe_volumes(MaxResults=6)
    ec2.describe_snapshots(OwnerIds=["self"], MaxResults=5)
    ec2.describe_regions()

    logs = session.client("logs")
    logs.describe_log_groups(limit=1)

    s3 = session.client("s3")
    s3.list_buckets()

    click.echo("🎉 AWS environment is ready for CleanCloud")
