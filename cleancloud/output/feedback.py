import os

import click


def should_show_feedback(no_feedback: bool) -> bool:
    if no_feedback:
        return False
    if os.getenv("CI", "").lower() == "true":
        return False
    return True


def show_feedback_prompt():
    click.echo()
    click.echo("-" * 70)
    click.echo("CleanCloud feedback")
    click.echo("-" * 70)
    click.echo()
    click.echo("If this scan surfaced useful (or confusing) findings, we'd love to hear about it.")
    click.echo()
    click.echo(
        "Share feedback or feature requests: https://github.com/cleancloud-io/cleancloud/discussions"
    )
    click.echo()
    click.echo("Report any issues: https://github.com/cleancloud-io/cleancloud/issues")
    click.echo()
    click.echo("Or email: suresh@sure360.io")
    click.echo()
