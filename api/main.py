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
    product_name: str
    engagement_name: str
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

@app.get("/status/{task_id}")
def status(task_id: str):
    result = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "state": result.state,
        "result": str(result.result) if result.result else None
    }
``
