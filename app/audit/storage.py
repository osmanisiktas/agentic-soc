import hashlib
import json
from pathlib import Path
from threading import Lock
from typing import Any

from app.audit.models import AuditEvent


GENESIS_HASH = "0" * 64


class AuditStorage:
    def __init__(
        self,
        file_path: str = "data/audit/audit.jsonl",
    ) -> None:
        self.file_path = Path(file_path)
        self._lock = Lock()

        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _canonical_json(data: dict[str, Any]) -> str:
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @classmethod
    def _calculate_hash(
        cls,
        event_data: dict[str, Any],
        previous_hash: str,
    ) -> str:
        payload = {
            "event": event_data,
            "previous_hash": previous_hash,
        }

        canonical = cls._canonical_json(payload)

        return hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

    def append(self, event: AuditEvent) -> None:
        with self._lock:
            previous_hash = GENESIS_HASH

            if self.file_path.exists() and self.file_path.stat().st_size > 0:
                records = self._read_records()
                if not records:
                    raise ValueError("Audit chain is empty or invalid")

                previous_hash = records[-1]["record_hash"]

            event_data = event.model_dump(mode="json")

            record_hash = self._calculate_hash(
                event_data,
                previous_hash,
            )

            record = {
                **event_data,
                "previous_hash": previous_hash,
                "record_hash": record_hash,
            }

            with self.file_path.open("a", encoding="utf-8") as file:
                file.write(self._canonical_json(record) + "\n")
                file.flush()

    def _read_records(self) -> list[dict[str, Any]]:
        if not self.file_path.exists():
            return []

        records: list[dict[str, Any]] = []

        with self.file_path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON at line {line_number}"
                    ) from exc

        return records

    def read_all(self) -> list[AuditEvent]:
        with self._lock:
            records = self._read_records()

            return [
                AuditEvent.model_validate({
                    key: value
                    for key, value in record.items()
                    if key not in ("previous_hash", "record_hash")
                })
                for record in records
            ]

    def verify_chain(self) -> bool:
        with self._lock:
            records = self._read_records()

            expected_previous_hash = GENESIS_HASH

            for record in records:
                previous_hash = record.get("previous_hash")
                record_hash = record.get("record_hash")

                if previous_hash != expected_previous_hash:
                    return False

                event_data = {
                    key: value
                    for key, value in record.items()
                    if key not in ("previous_hash", "record_hash")
                }

                expected_hash = self._calculate_hash(
                    event_data,
                    expected_previous_hash,
                )

                if record_hash != expected_hash:
                    return False

                expected_previous_hash = record_hash

            return True
