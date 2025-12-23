from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.public_ip_unused import find_unused_public_ips


@pytest.fixture
def mock_network_client(mocker):
    pip_old = SimpleNamespace(
        id="pip-1",
        name="pip-unused",
        ip_address="1.2.3.4",
        ip_configuration=None,
        location="eastus",
        tags=None,
    )
    pip_in_use = SimpleNamespace(
        id="pip-2",
        name="pip-used",
        ip_address="5.6.7.8",
        ip_configuration={"id": "some-config"},
        location="eastus",
        tags={"env": "prod"},
    )

    client = mocker.MagicMock()
    client.public_ip_addresses.list_all.return_value = [pip_old, pip_in_use]
    return client


def test_find_unused_public_ips(mock_network_client):
    findings = find_unused_public_ips(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=mock_network_client,
    )
    resource_ids = [f.resource_id for f in findings]
    assert "pip-1" in resource_ids
    assert "pip-2" not in resource_ids
