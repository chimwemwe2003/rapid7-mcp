"""Tests for the InsightIDR router."""

from fastapi.testclient import TestClient

from rapid7_mcp.client import get_idr_client
from rapid7_mcp.main import app


def test_list_investigations(client: TestClient) -> None:
    response = client.get("/idr/investigations")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert len(data["data"]) == 2
    inv = data["data"][0]
    assert inv["status"] == "OPEN"
    assert inv["priority"] == "HIGH"
    assert "title" in inv


def test_list_investigations_filters(client: TestClient) -> None:
    response = client.get("/idr/investigations?status=INVESTIGATING&priority=CRITICAL")
    assert response.status_code == 200


def test_list_investigations_date_filters(client: TestClient) -> None:
    captured_params: dict = {}

    class CapturingClient:
        async def get(self, path: str, params: dict | None = None) -> dict:
            captured_params.update(params or {})
            return {"data": [], "metadata": {"total_data": 0}}

    app.dependency_overrides[get_idr_client] = lambda: CapturingClient()
    response = client.get(
        "/idr/investigations"
        "?start_date=2024-01-01T00:00:00Z&end_date=2024-02-01T00:00:00Z"
    )

    assert response.status_code == 200
    assert captured_params["start_time"] == "2024-01-01T00:00:00Z"
    assert captured_params["end_time"] == "2024-02-01T00:00:00Z"


def test_list_investigations_rejects_reversed_date_range(client: TestClient) -> None:
    response = client.get(
        "/idr/investigations"
        "?start_date=2024-02-01T00:00:00Z&end_date=2024-01-01T00:00:00Z"
    )
    assert response.status_code == 422


def test_get_monthly_report_data_paginates_and_aggregates(client: TestClient) -> None:
    requested_indexes: list[int] = []
    investigations = [
        {
            "priority": "CRITICAL",
            "disposition": "MALICIOUS",
            "alerts": [
                {
                    "detection_rule_name": "Suspicious PowerShell",
                    "targeted_user": {"username": "alice"},
                }
            ],
        },
        {
            "priority": "HIGH",
            "disposition": "BENIGN",
            "alerts": [
                {
                    "alert_type": "Suspicious PowerShell",
                    "users": [{"username": "alice"}, {"username": "bob"}],
                }
            ],
        },
    ]

    class PaginatedClient:
        async def get(self, path: str, params: dict | None = None) -> dict:
            assert params is not None
            requested_indexes.append(params["index"])
            index = params["index"]
            return {
                "data": investigations[index : index + 1],
                "metadata": {"total_data": 2},
            }

    app.dependency_overrides[get_idr_client] = lambda: PaginatedClient()
    response = client.get("/idr/reports/monthly?year=2024&month=1")

    assert response.status_code == 200
    assert requested_indexes == [0, 1]
    data = response.json()
    assert data["month"] == "2024-01"
    assert data["period"] == {
        "start_date": "2024-01-01T00:00:00Z",
        "end_date": "2024-02-01T00:00:00Z",
    }
    assert data["total_investigations"] == 2
    assert data["investigations_by_priority"] == {
        "Critical": 1,
        "High": 1,
        "Medium": 0,
        "Low": 0,
    }
    assert data["malicious_investigations"] == 1
    assert data["top_triggered_detection_rules"] == [
        {"rule": "Suspicious PowerShell", "count": 2}
    ]
    assert data["top_targeted_users"] == [
        {"user": "alice", "count": 2},
        {"user": "bob", "count": 1},
    ]


def test_get_investigation(client: TestClient) -> None:
    response = client.get("/idr/investigations/INV-002")
    assert response.status_code == 200
    data = response.json()
    assert data["priority"] == "CRITICAL"
    assert len(data["alerts"]) == 2


def test_query_logs(client: TestClient) -> None:
    payload = {
        "query": 'where(destination_ip = "185.220.101.1")',
        "from_time": 1705276800000,
        "to_time": 1705363200000,
        "logs": ["firewall-logs"],
    }
    response = client.post("/idr/logs", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "events" in data
    assert len(data["events"]) == 3


def test_list_indicators(client: TestClient) -> None:
    response = client.get("/idr/iocs")
    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    assert len(data["data"]) == 3
    ioc = data["data"][0]
    assert ioc["indicator_type"] == "IP_ADDRESS"
    assert ioc["active"] is True


def test_list_indicators_type_filter(client: TestClient) -> None:
    response = client.get("/idr/iocs?indicator_type=FILE_HASH")
    assert response.status_code == 200
