from fastapi import FastAPI
from pydantic import BaseModel
from celery import Celery
import os

app = FastAPI()

celery_app = Celery(
    "tasks",
    broker=os.getenv("REDIS_URL"),
    backend=os.getenv("REDIS_URL")
)

class ScanRequest(BaseModel):
    repo_url: str
    target_url: str | None = None

@app.post("/scan")
def scan(req: ScanRequest):
    task = celery_app.send_task("tasks.run_scan", args=[req.dict()])
    return {
        "status": "accepted",
        "message": "request received",
        "task_id": task.id
    }

@app.get("/health")
def health():
    return {"status": "ok"}
