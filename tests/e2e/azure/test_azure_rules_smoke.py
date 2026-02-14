from datetime import datetime

import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.azure.rules.app_gateway_no_backends import find_app_gateway_no_backends
from cleancloud.providers.azure.rules.app_service_plan_empty import find_empty_app_service_plans
from cleancloud.providers.azure.rules.ebs_snapshots_old import find_old_snapshots
from cleancloud.providers.azure.rules.lb_no_backends import find_lb_no_backends
from cleancloud.providers.azure.rules.public_ip_unused import find_unused_public_ips
from cleancloud.providers.azure.rules.unattached_managed_disks import find_unattached_managed_disks
from cleancloud.providers.azure.rules.untagged_resources import find_untagged_resources
from cleancloud.providers.azure.rules.vm_stopped_not_deallocated import (
    find_stopped_not_deallocated_vms,
)
from cleancloud.providers.azure.rules.vnet_gateway_idle import find_idle_vnet_gateways
from cleancloud.providers.azure.session import create_azure_session


@pytest.mark.e2e
@pytest.mark.azure
def test_azure_rules_run_without_error():
    session = create_azure_session()
    subscription_ids = session.list_subscription_ids()
    assert subscription_ids, "No Azure subscriptions available for E2E test"

    sub_id = subscription_ids[0]
    credential = session.credential

    region_filter = "eastus"  # optional, restrict scan region

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
        find_empty_app_service_plans(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        ),
        find_lb_no_backends(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        ),
        find_app_gateway_no_backends(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        ),
        find_idle_vnet_gateways(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        ),
        find_stopped_not_deallocated_vms(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        ),
    ]

    for rule_results in all_rules:
        assert isinstance(rule_results, list), f"Rule returned {type(rule_results)} instead of list"

        for f in rule_results:
            assert isinstance(f, Finding), f"Unexpected type {type(f)} in findings"
            assert f.provider == "azure"
            assert f.rule_id.startswith("azure.")
            assert f.resource_id
            assert f.region
            assert f.detected_at and isinstance(f.detected_at, datetime)
