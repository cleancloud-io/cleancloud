from types import SimpleNamespace

import pytest

from cleancloud.providers.azure.rules.sql_database_idle import (
    find_idle_sql_databases,
)


def _make_server(name, location="eastus"):
    return SimpleNamespace(
        id=f"/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Sql/servers/{name}",
        name=name,
        location=location,
    )


def _make_database(
    server_name,
    db_name,
    sku_name="S0",
    sku_tier="Standard",
    location="eastus",
    max_size_bytes=268435456000,
    tags=None,
):
    return SimpleNamespace(
        id=(
            f"/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Sql/servers"
            f"/{server_name}/databases/{db_name}"
        ),
        name=db_name,
        location=location,
        sku=SimpleNamespace(name=sku_name, tier=sku_tier),
        max_size_bytes=max_size_bytes,
        tags=tags,
    )


def _make_metric_response(total_value=0):
    """Create a mock Azure Monitor metrics response."""
    data_point = SimpleNamespace(total=total_value)
    timeseries = SimpleNamespace(data=[data_point])
    metric = SimpleNamespace(timeseries=[timeseries])
    return SimpleNamespace(value=[metric])


@pytest.fixture
def mock_sql_client(mocker):
    return mocker.MagicMock()


@pytest.fixture
def mock_monitor_client(mocker):
    return mocker.MagicMock()


def test_idle_db_detected(mock_sql_client, mock_monitor_client):
    """Standard tier DB with zero connections should be flagged."""
    server = _make_server("sql-server-1")
    db = _make_database("sql-server-1", "app-db", sku_name="S0", sku_tier="Standard")

    mock_sql_client.servers.list.return_value = [server]
    mock_sql_client.databases.list_by_server.return_value = [db]
    mock_monitor_client.metrics.list.return_value = _make_metric_response(total_value=0)

    findings = find_idle_sql_databases(
        subscription_id="sub-123",
        credential=None,
        client=mock_sql_client,
        monitor_client=mock_monitor_client,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.provider == "azure"
    assert finding.rule_id == "azure.sql_database.idle"
    assert finding.resource_type == "azure.sql_database"
    assert finding.confidence.value == "high"
    assert finding.risk.value == "high"
    assert finding.details["db_name"] == "app-db"
    assert finding.details["server_name"] == "sql-server-1"
    assert finding.details["sku_name"] == "S0"
    assert finding.details["sku_tier"] == "Standard"
    assert finding.details["connections_14d"] == 0
    assert "$15/month" in finding.details["estimated_monthly_cost"]


def test_active_db_skipped(mock_sql_client, mock_monitor_client):
    """DB with non-zero connections should NOT be flagged."""
    server = _make_server("sql-server-1")
    db = _make_database("sql-server-1", "active-db", sku_name="S2", sku_tier="Standard")

    mock_sql_client.servers.list.return_value = [server]
    mock_sql_client.databases.list_by_server.return_value = [db]
    mock_monitor_client.metrics.list.return_value = _make_metric_response(total_value=42)

    findings = find_idle_sql_databases(
        subscription_id="sub-123",
        credential=None,
        client=mock_sql_client,
        monitor_client=mock_monitor_client,
    )

    assert len(findings) == 0


def test_basic_tier_skipped(mock_sql_client, mock_monitor_client):
    """Basic tier DBs should NOT be flagged (< $5/month)."""
    server = _make_server("sql-server-1")
    db = _make_database("sql-server-1", "cheap-db", sku_name="Basic", sku_tier="Basic")

    mock_sql_client.servers.list.return_value = [server]
    mock_sql_client.databases.list_by_server.return_value = [db]

    findings = find_idle_sql_databases(
        subscription_id="sub-123",
        credential=None,
        client=mock_sql_client,
        monitor_client=mock_monitor_client,
    )

    assert len(findings) == 0
    # Monitor should not even be queried for Basic tier
    mock_monitor_client.metrics.list.assert_not_called()


def test_system_db_skipped(mock_sql_client, mock_monitor_client):
    """System database 'master' should NOT be flagged."""
    server = _make_server("sql-server-1")
    db = _make_database("sql-server-1", "master", sku_name="S0", sku_tier="Standard")

    mock_sql_client.servers.list.return_value = [server]
    mock_sql_client.databases.list_by_server.return_value = [db]

    findings = find_idle_sql_databases(
        subscription_id="sub-123",
        credential=None,
        client=mock_sql_client,
        monitor_client=mock_monitor_client,
    )

    assert len(findings) == 0
    mock_monitor_client.metrics.list.assert_not_called()


def test_region_filter(mock_sql_client, mock_monitor_client):
    """Only servers in the filtered region should be checked."""
    server_east = _make_server("sql-east", location="eastus")
    server_west = _make_server("sql-west", location="westus")
    db_east = _make_database("sql-east", "db-east", location="eastus")
    db_west = _make_database("sql-west", "db-west", location="westus")

    mock_sql_client.servers.list.return_value = [server_east, server_west]
    mock_sql_client.databases.list_by_server.side_effect = lambda rg, name: {
        "sql-east": [db_east],
        "sql-west": [db_west],
    }[name]
    mock_monitor_client.metrics.list.return_value = _make_metric_response(total_value=0)

    findings = find_idle_sql_databases(
        subscription_id="sub-123",
        credential=None,
        region_filter="eastus",
        client=mock_sql_client,
        monitor_client=mock_monitor_client,
    )

    assert len(findings) == 1
    assert findings[0].details["server_name"] == "sql-east"


def test_metric_failure_conservative_skip(mock_sql_client, mock_monitor_client):
    """If metric query fails, DB should NOT be flagged (conservative)."""
    server = _make_server("sql-server-1")
    db = _make_database("sql-server-1", "unknown-db", sku_name="P1", sku_tier="Premium")

    mock_sql_client.servers.list.return_value = [server]
    mock_sql_client.databases.list_by_server.return_value = [db]
    mock_monitor_client.metrics.list.side_effect = Exception("Azure Monitor unavailable")

    findings = find_idle_sql_databases(
        subscription_id="sub-123",
        credential=None,
        client=mock_sql_client,
        monitor_client=mock_monitor_client,
    )

    assert len(findings) == 0


def test_empty_subscription(mock_sql_client, mock_monitor_client):
    """No servers should return empty findings."""
    mock_sql_client.servers.list.return_value = []

    findings = find_idle_sql_databases(
        subscription_id="sub-123",
        credential=None,
        client=mock_sql_client,
        monitor_client=mock_monitor_client,
    )

    assert findings == []
