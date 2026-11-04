import json
from pathlib import Path
from uuid import UUID

from app.models.alert import Alert, AlertStatus


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ALERTS_FILE = PROJECT_ROOT / "data" / "alerts" / "alerts.jsonl"


def load_alerts() -> list[Alert]:
    if not ALERTS_FILE.exists():
        return []

    alerts = []

    with ALERTS_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                alerts.append(Alert.model_validate_json(line))

    return alerts


def store_alert(alert: Alert) -> Alert:
    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    existing = load_alerts()

    # Prevent duplicate alerts for the same rule and event group.
    for saved_alert in existing:
        if (
            saved_alert.rule_id == alert.rule_id
            and set(saved_alert.event_ids) == set(alert.event_ids)
        ):
            return saved_alert

    with ALERTS_FILE.open("a", encoding="utf-8") as file:
        file.write(alert.model_dump_json() + "\n")

    return alert


def update_alert_status(
    alert_id: UUID,
    new_status: AlertStatus
) -> Alert | None:
    alerts = load_alerts()
    target = None

    for alert in alerts:
        if alert.alert_id == alert_id:
            alert.status = new_status
            target = alert
            break

    if target is None:
        return None

    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_file = ALERTS_FILE.with_suffix(".tmp")

    with temp_file.open("w", encoding="utf-8") as file:
        for alert in alerts:
            file.write(alert.model_dump_json() + "\n")

    temp_file.replace(ALERTS_FILE)

    return target
