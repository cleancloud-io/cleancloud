"""
Tests that provider-specific CLI flags are rejected when used with the wrong provider.
CleanCloud fails fast before any API calls so users get a clear error immediately.
"""

import pytest
from click.testing import CliRunner

from cleancloud.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# GCP-only flags rejected for AWS and Azure
# ---------------------------------------------------------------------------


def test_all_projects_rejected_for_aws(runner):
    result = runner.invoke(cli, ["scan", "--provider", "aws", "--all-projects"])
    assert result.exit_code != 0
    assert "--all-projects" in result.output
    assert "gcp" in result.output.lower()


def test_all_projects_rejected_for_azure(runner):
    result = runner.invoke(cli, ["scan", "--provider", "azure", "--all-projects"])
    assert result.exit_code != 0
    assert "--all-projects" in result.output
    assert "gcp" in result.output.lower()


def test_project_rejected_for_aws(runner):
    result = runner.invoke(cli, ["scan", "--provider", "aws", "--project", "my-project"])
    assert result.exit_code != 0
    assert "--project" in result.output
    assert "gcp" in result.output.lower()


def test_project_rejected_for_azure(runner):
    result = runner.invoke(cli, ["scan", "--provider", "azure", "--project", "my-project"])
    assert result.exit_code != 0
    assert "--project" in result.output
    assert "gcp" in result.output.lower()


# ---------------------------------------------------------------------------
# Azure-only flags rejected for AWS and GCP
# ---------------------------------------------------------------------------


def test_all_subscriptions_rejected_for_aws(runner):
    result = runner.invoke(cli, ["scan", "--provider", "aws", "--all-subscriptions"])
    assert result.exit_code != 0
    assert "--all-subscriptions" in result.output
    assert "azure" in result.output.lower()


def test_all_subscriptions_rejected_for_gcp(runner):
    result = runner.invoke(cli, ["scan", "--provider", "gcp", "--all-subscriptions"])
    assert result.exit_code != 0
    assert "--all-subscriptions" in result.output
    assert "azure" in result.output.lower()


def test_subscription_rejected_for_aws(runner):
    result = runner.invoke(cli, ["scan", "--provider", "aws", "--subscription", "sub-123"])
    assert result.exit_code != 0
    assert "--subscription" in result.output
    assert "azure" in result.output.lower()


def test_subscription_rejected_for_gcp(runner):
    result = runner.invoke(cli, ["scan", "--provider", "gcp", "--subscription", "sub-123"])
    assert result.exit_code != 0
    assert "--subscription" in result.output
    assert "azure" in result.output.lower()


def test_management_group_rejected_for_aws(runner):
    result = runner.invoke(cli, ["scan", "--provider", "aws", "--management-group", "mg-123"])
    assert result.exit_code != 0
    assert "--management-group" in result.output
    assert "azure" in result.output.lower()


def test_management_group_rejected_for_gcp(runner):
    result = runner.invoke(cli, ["scan", "--provider", "gcp", "--management-group", "mg-123"])
    assert result.exit_code != 0
    assert "--management-group" in result.output
    assert "azure" in result.output.lower()


# ---------------------------------------------------------------------------
# AWS-only flags rejected for Azure and GCP
# ---------------------------------------------------------------------------


def test_all_regions_rejected_for_azure(runner):
    result = runner.invoke(cli, ["scan", "--provider", "azure", "--all-regions"])
    assert result.exit_code != 0
    assert "--all-regions" in result.output
    assert "aws" in result.output.lower()


def test_all_regions_rejected_for_gcp(runner):
    result = runner.invoke(cli, ["scan", "--provider", "gcp", "--all-regions"])
    assert result.exit_code != 0
    assert "--all-regions" in result.output
    assert "aws" in result.output.lower()


def test_profile_rejected_for_azure(runner):
    result = runner.invoke(cli, ["scan", "--provider", "azure", "--profile", "myprofile"])
    assert result.exit_code != 0
    assert "--profile" in result.output
    assert "aws" in result.output.lower()


def test_profile_rejected_for_gcp(runner):
    result = runner.invoke(cli, ["scan", "--provider", "gcp", "--profile", "myprofile"])
    assert result.exit_code != 0
    assert "--profile" in result.output
    assert "aws" in result.output.lower()


def test_org_rejected_for_azure(runner):
    result = runner.invoke(cli, ["scan", "--provider", "azure", "--org"])
    assert result.exit_code != 0
    assert "--org" in result.output
    assert "aws" in result.output.lower()


def test_org_rejected_for_gcp(runner):
    result = runner.invoke(cli, ["scan", "--provider", "gcp", "--org"])
    assert result.exit_code != 0
    assert "--org" in result.output
    assert "aws" in result.output.lower()


def test_accounts_rejected_for_azure(runner):
    result = runner.invoke(
        cli, ["scan", "--provider", "azure", "--accounts", "111111111111"]
    )
    assert result.exit_code != 0
    assert "--accounts" in result.output
    assert "aws" in result.output.lower()


def test_accounts_rejected_for_gcp(runner):
    result = runner.invoke(
        cli, ["scan", "--provider", "gcp", "--accounts", "111111111111"]
    )
    assert result.exit_code != 0
    assert "--accounts" in result.output
    assert "aws" in result.output.lower()


def test_external_id_rejected_for_azure(runner):
    result = runner.invoke(cli, ["scan", "--provider", "azure", "--external-id", "abc123"])
    assert result.exit_code != 0
    assert "--external-id" in result.output
    assert "aws" in result.output.lower()


def test_external_id_rejected_for_gcp(runner):
    result = runner.invoke(cli, ["scan", "--provider", "gcp", "--external-id", "abc123"])
    assert result.exit_code != 0
    assert "--external-id" in result.output
    assert "aws" in result.output.lower()


def test_per_account_regions_rejected_for_azure(runner):
    result = runner.invoke(cli, ["scan", "--provider", "azure", "--per-account-regions"])
    assert result.exit_code != 0
    assert "--per-account-regions" in result.output
    assert "aws" in result.output.lower()


def test_per_account_regions_rejected_for_gcp(runner):
    result = runner.invoke(cli, ["scan", "--provider", "gcp", "--per-account-regions"])
    assert result.exit_code != 0
    assert "--per-account-regions" in result.output
    assert "aws" in result.output.lower()
