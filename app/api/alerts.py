from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.ingestion.alert_storage import (
    load_alerts,
    update_alert_status,
)
from app.models.alert import Alert, AlertStatus


router = APIRouter(
    prefix="/api/v1/alerts",
    tags=["Alert Management"]
)


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


@router.get("", response_model=list[Alert])
def list_alerts():
    return load_alerts()


@router.get("/{alert_id}", response_model=Alert)
def get_alert(alert_id: UUID):
    for alert in load_alerts():
        if alert.alert_id == alert_id:
            return alert

    raise HTTPException(
        status_code=404,
        detail="Alert not found"
    )


@router.patch("/{alert_id}/status", response_model=Alert)
def change_alert_status(
    alert_id: UUID,
    update: AlertStatusUpdate
):
    alert = update_alert_status(
        alert_id,
        update.status
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return alert
