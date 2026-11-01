from datetime import datetime, timezone

from fastapi import FastAPI

from app.api.events import router as events_router


app = FastAPI(
    title="Agentic SOC",
    description="Agentic Security Operations Platform",
    version="0.2.0"
)

app.include_router(events_router)


@app.get("/")
def root():
    return {
        "project": "Agentic SOC",
        "status": "running",
        "version": "0.2.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "agentic-soc-api",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
