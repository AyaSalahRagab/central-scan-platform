import os
import re
import logging
from fastapi import FastAPI, UploadFile, Form, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from celery.result import AsyncResult
from tasks import run_scan
from celery_app import celery_app

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Security Scanner API")

# Configuration
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/security_scans")
REPORT_DIR = os.getenv("REPORT_DIR", "reports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

app.mount("/static-reports", StaticFiles(directory=REPORT_DIR), name="reports")


@app.post("/api/v1/scan")
async def scan_code(
    request: Request,
    project_name: str = Form(...),
    language: str = Form(...),
    app_type: str = Form(...),
    framework: str = Form(...),
    file: UploadFile = Form(...),
):
    # Sanitize project_name
    safe_project_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", project_name)

    # Read file content
    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(400, "Uploaded file is empty")

    # Enqueue task
    base_url = str(request.base_url)
    task = run_scan.delay(
        project_name=safe_project_name,
        language=language,
        app_type=app_type,
        framework=framework,
        file_bytes=file_bytes,
        base_url=base_url,
    )

    return {
        "job_id": task.id,
        "status": "queued",
        "message": "Scan task enqueued. Poll /api/v1/status/{job_id} for results.",
    }


@app.get("/api/v1/status/{job_id}")
async def get_status(job_id: str):
    task_result = AsyncResult(job_id, app=celery_app)
    if task_result.state == "PENDING":
        return {"job_id": job_id, "status": "pending"}
    elif task_result.state == "STARTED":
        return {"job_id": job_id, "status": "running"}
    elif task_result.state == "SUCCESS":
        result = task_result.result
        return {"job_id": job_id, "status": "success", "result": result}
    elif task_result.state == "FAILURE":
        # Optionally log the exception
        return {"job_id": job_id, "status": "failed", "error": str(task_result.info)}
    else:
        return {"job_id": job_id, "status": task_result.state}
