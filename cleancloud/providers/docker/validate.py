"""Validation for Docker provider parameters."""

import click


def validate_docker_params(host: str = None) -> None:
    """Validate Docker provider parameters before scanning.

    Raises click.UsageError if parameters are invalid.
    """
    # Docker provider has minimal validation — connection is verified in session.py
    pass
