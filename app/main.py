from fastapi import FastAPI
from datetime import datetime, timezone

app = FastAPI(
    title="Agentic SOC",
    description="Agentic Security Operations Platform",
    version="0.1.0"
)

@app.get("/")
def root():
    return {
        "project": "Agentic SOC",
        "status": "running",
        "version": "0.1.0"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "agentic-soc-api",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
