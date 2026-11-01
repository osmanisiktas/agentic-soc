import json
from pathlib import Path

from app.models.event import SecurityEvent


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVENTS_FILE = PROJECT_ROOT / "data" / "events" / "events.jsonl"


def store_event(event: SecurityEvent) -> None:
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    event_data = event.model_dump(mode="json")

    with EVENTS_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event_data, ensure_ascii=False) + "\n")
