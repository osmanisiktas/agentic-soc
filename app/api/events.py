from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.ingestion.storage import store_event
from app.models.event import SecurityEvent


router = APIRouter(prefix="/api/v1/events", tags=["Event Ingestion"])


class EventIngestionResponse(BaseModel):
    status: str
    event_id: UUID
    message: str


@router.post(
    "",
    response_model=EventIngestionResponse,
    status_code=status.HTTP_201_CREATED
)
def ingest_event(event: SecurityEvent):
    try:
        store_event(event)
    except OSError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Event could not be stored"
        )

    return EventIngestionResponse(
        status="accepted",
        event_id=event.event_id,
        message="Security event successfully ingested"
    )
