import pytest

from cleancloud.providers.gcp.session import create_gcp_session


@pytest.mark.e2e
@pytest.mark.gcp
def test_gcp_auth_and_list_projects():
    session = create_gcp_session()
    projects = session.list_projects()

    assert isinstance(projects, list)
    assert len(projects) >= 1
    assert all("id" in p and "name" in p for p in projects)
