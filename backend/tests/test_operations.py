from datetime import UTC, datetime, timedelta

from backend import models
from backend.db import session_scope


def test_schedule_and_maintenance_window(client, csrf_headers):
    headers = csrf_headers()
    host = client.post(
        "/api/v1/hosts",
        headers=headers,
        json={"name": "web01", "ip": "10.0.0.10", "environment": "production"},
    )
    assert host.status_code == 201
    schedule = client.post(
        "/api/v1/operations/schedules",
        headers=headers,
        json={
            "name": "nightly-openscap",
            "operation": "openscap",
            "environment": "production",
            "interval_minutes": 1440,
            "hosts": ["web01"],
        },
    )
    assert schedule.status_code == 201, schedule.text
    assert schedule.json()["operation"] == "openscap"

    now = datetime.now(UTC)
    window = client.post(
        "/api/v1/operations/maintenance",
        headers=headers,
        json={
            "name": "Sunday window",
            "environment": "production",
            "starts_at": (now - timedelta(hours=1)).isoformat(),
            "ends_at": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert window.status_code == 201, window.text
    assert window.json()["name"] == "Sunday window"

    with session_scope() as db:
        schedule_row = db.query(models.OperationSchedule).one()
        schedule_row.next_run_at = now - timedelta(minutes=1)
        db.commit()

    run = client.post("/api/v1/operations/schedules/run-due", headers=headers)
    assert run.status_code == 200
    assert run.json()["queued"] == 1


def test_maintenance_window_rejects_scheduled_job(client, csrf_headers):
    headers = csrf_headers()
    now = datetime.now(UTC)
    client.post(
        "/api/v1/operations/maintenance",
        headers=headers,
        json={
            "name": "patch freeze",
            "environment": "production",
            "starts_at": (now + timedelta(hours=2)).isoformat(),
            "ends_at": (now + timedelta(hours=3)).isoformat(),
        },
    )
    schedule = client.post(
        "/api/v1/operations/schedules",
        headers=headers,
        json={
            "name": "patch run",
            "operation": "patch",
            "environment": "production",
            "interval_minutes": 60,
        },
    )
    assert schedule.status_code == 201
    with session_scope() as db:
        row = db.query(models.OperationSchedule).one()
        row.next_run_at = now - timedelta(minutes=1)
        db.commit()
    run = client.post("/api/v1/operations/schedules/run-due", headers=headers)
    assert run.json()["queued"] == 0
