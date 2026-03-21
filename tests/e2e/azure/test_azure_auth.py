import pytest

from cleancloud.providers.azure.session import create_azure_session


@pytest.mark.e2e
@pytest.mark.azure
def test_azure_auth_and_list_subscriptions():

    session = create_azure_session()
    subs = session.list_subscriptions()

    assert isinstance(subs, list)
    assert len(subs) >= 1
    assert all("id" in s and "name" in s for s in subs)
