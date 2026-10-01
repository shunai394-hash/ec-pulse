import pytest
from fastapi.testclient import TestClient

from app import main


def test_cron_monitor_endpoint_requires_secret(monkeypatch):
    monkeypatch.setenv("CRON_SECRET", "test-secret")
    client = TestClient(main.app)

    response = client.get("/api/cron/check-monitors")

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_cron_monitor_endpoint_runs_due_monitors(monkeypatch):
    monkeypatch.setenv("CRON_SECRET", "test-secret")

    async def fake_run_due_monitors():
        return {
            "checked": 2,
            "changed": 1,
            "failed": 0,
            "webhooks_delivered": 1,
        }

    monkeypatch.setattr(main, "run_due_monitors", fake_run_due_monitors)
    client = TestClient(main.app)

    response = client.get(
        "/api/cron/check-monitors",
        headers={"Authorization": "Bearer test-secret"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["checked"] == 2
    assert body["changed"] == 1
    assert body["failed"] == 0
    assert body["webhooks_delivered"] == 1
    assert body["checked_at"]


def test_cron_monitor_endpoint_rejects_wrong_secret(monkeypatch):
    monkeypatch.setenv("CRON_SECRET", "test-secret")
    client = TestClient(main.app)

    response = client.get(
        "/api/cron/check-monitors",
        headers={"Authorization": "Bearer wrong-secret"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized"


def test_cron_secret_with_trailing_newline_still_authenticates(monkeypatch):
    monkeypatch.setenv("CRON_SECRET", "test-secret\n")

    async def fake_run_due_monitors():
        return {"checked": 0, "changed": 0, "failed": 0, "webhooks_delivered": 0}

    monkeypatch.setattr(main, "run_due_monitors", fake_run_due_monitors)
    client = TestClient(main.app)

    assert client.get("/api/cron/check-monitors", headers={"Authorization": "Bearer test-secret"}).status_code == 200
    assert client.get("/api/cron/check-monitors", headers={"Authorization": "Bearer wrong"}).status_code == 401
    monkeypatch.setenv("CRON_SECRET", "  ")
    assert client.get("/api/cron/check-monitors", headers={"Authorization": "Bearer "}).status_code == 401
