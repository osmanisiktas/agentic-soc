from datetime import datetime, timezone

from fastapi import FastAPI

from app.api.events import router as events_router
from app.api.detections import router as detections_router
from app.api.alerts import router as alerts_router


app = FastAPI(
    title="Agentic SOC",
    description="Agentic Security Operations Platform",
    version="0.3.0"
)

app.include_router(events_router)
app.include_router(detections_router)
app.include_router(alerts_router)


@app.get("/")
def root():
    return {
        "project": "Agentic SOC",
        "status": "running",
        "version": "0.3.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "agentic-soc-api",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
