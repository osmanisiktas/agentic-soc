import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.detection.rules.brute_force import detect_brute_force
from app.ingestion.alert_storage import store_alert
from app.models.event import SecurityEvent


router = APIRouter(
    prefix="/api/v1/detections",
    tags=["Detection Engine"]
)

EVENTS_FILE = "data/events/events.jsonl"


class DetectionResponse(BaseModel):
    status: str
    analyzed_events: int
    alerts_generated: int
    alert_ids: list[str]


@router.post("/brute-force", response_model=DetectionResponse)
def run_brute_force_detection():

    events = []

    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    events.append(
                        SecurityEvent.model_validate_json(line)
                    )

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="No event data available"
        )

    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Event data could not be read: {exc}"
        )

    detected_alerts = detect_brute_force(events)
    saved_alerts = [
        store_alert(alert) for alert in detected_alerts
    ]

    return DetectionResponse(
        status="completed",
        analyzed_events=len(events),
        alerts_generated=len(saved_alerts),
        alert_ids=[str(alert.alert_id) for alert in saved_alerts]
    )
