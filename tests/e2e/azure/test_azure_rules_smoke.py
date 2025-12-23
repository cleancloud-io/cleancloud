# tests/e2e/azure/test_azure_rules_smoke.py
from datetime import datetime

import pytest

from cleancloud.models.finding import Finding
from cleancloud.providers.azure.rules.ebs_snapshots_old import find_old_snapshots
from cleancloud.providers.azure.rules.public_ip_unused import find_unused_public_ips
from cleancloud.providers.azure.rules.unattached_managed_disks import find_unattached_managed_disks
from cleancloud.providers.azure.rules.untagged_resources import find_untagged_resources
from cleancloud.providers.azure.session import create_azure_session


@pytest.mark.e2e
@pytest.mark.azure
def test_azure_rules_run_without_error():
    """
    End-to-end smoke test for all Azure rules.
    Ensures each rule executes and returns a list of findings without crashing.
    """

    # ---- Get first available subscription ----
    session = create_azure_session()
    subscription_ids = session.list_subscription_ids()
    assert subscription_ids, "No Azure subscriptions available for E2E test"

    sub_id = subscription_ids[0]
    credential = session.credential

    region_filter = "eastus"  # optional, restrict scan region

    # ---- Execute each rule ----
    all_rules = [
        find_unattached_managed_disks(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        ),
        find_old_snapshots(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        ),
        find_untagged_resources(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        ),
        find_unused_public_ips(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        ),
    ]

    # ---- Assert each rule returned a list ----
    for rule_results in all_rules:
        assert isinstance(rule_results, list), f"Rule returned {type(rule_results)} instead of list"

        # ---- Optional: check structure if there are any findings ----
        for f in rule_results:
            assert isinstance(f, Finding), f"Unexpected type {type(f)} in findings"
            assert f.provider == "azure"
            assert f.rule_id.startswith("azure.")
            assert f.resource_id
            assert f.region
            assert f.detected_at and isinstance(f.detected_at, datetime)
