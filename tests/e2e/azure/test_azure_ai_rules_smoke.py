from datetime import datetime

import pytest

from cleancloud.core.finding import Finding
from cleancloud.providers.azure.rules.aml_compute_idle import find_idle_aml_compute
from cleancloud.providers.azure.rules.aml_compute_instance_idle import (
    find_idle_aml_compute_instances,
)
from cleancloud.providers.azure.session import create_azure_session


@pytest.mark.e2e
@pytest.mark.azure
def test_azure_ai_rules_run_without_error():
    session = create_azure_session()
    subscriptions = session.list_subscriptions()
    assert subscriptions, "No Azure subscriptions available for E2E test"

    sub_id = subscriptions[0]["id"]
    credential = session.credential

    region_filter = "eastus"  # optional, restrict scan region

    rules = [
        find_idle_aml_compute,
        find_idle_aml_compute_instances,
    ]

    all_results = []
    for rule in rules:
        rule_results = rule(
            subscription_id=sub_id, credential=credential, region_filter=region_filter
        )
        assert isinstance(
            rule_results, list
        ), f"{rule.__name__} returned {type(rule_results)} instead of list"
        all_results.extend(rule_results)

    for f in all_results:
        assert isinstance(f, Finding)
        assert f.provider == "azure"
        assert f.rule_id.startswith("azure.")
        assert f.resource_id
        assert f.region
        assert f.detected_at and isinstance(f.detected_at, datetime)
