import json
from pathlib import Path
from threading import Lock

from app.audit.models import AuditEvent


class AuditStorage:
    def __init__(self, file_path: str = "data/audit/audit.jsonl") -> None:
        self.file_path = Path(file_path)
        self._lock = Lock()

        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: AuditEvent) -> None:
        record = event.model_dump_json()

        with self._lock:
            with self.file_path.open("a", encoding="utf-8") as file:
                file.write(record + "\n")
                file.flush()

    def read_all(self) -> list[AuditEvent]:
        if not self.file_path.exists():
            return []

        events: list[AuditEvent] = []

        with self._lock:
            with self.file_path.open("r", encoding="utf-8") as file:
                for line_number, line in enumerate(file, start=1):
                    if not line.strip():
                        continue

                    try:
                        data = json.loads(line)
                        events.append(AuditEvent.model_validate(data))
                    except (json.JSONDecodeError, ValueError) as exc:
                        raise ValueError(
                            f"Invalid audit record at line {line_number}"
                        ) from exc

        return events
