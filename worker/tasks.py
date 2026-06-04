from celery import Celery
import os
import subprocess
from pathlib import Path
import requests

celery_app = Celery(
    "tasks",
    broker=os.getenv("REDIS_URL"),
    backend=os.getenv("REDIS_URL")
)

DOJO_URL = os.getenv("DEFECTDOJO_URL")
DOJO_TOKEN = os.getenv("DEFECTDOJO_TOKEN")
ENGAGEMENT_ID = os.getenv("DEFECTDOJO_ENGAGEMENT_ID")

@celery_app.task(name="tasks.run_scan")
def run_scan(req):
    repo_url = req["repo_url"]
    target_url = req.get("target_url")

    workdir = Path("/tmp/scan")
    workdir.mkdir(exist_ok=True)

    repo_dir = workdir / "repo"
    subprocess.run(f"git clone {repo_url} {repo_dir}", shell=True)

    # Semgrep
    subprocess.run(f"semgrep scan {repo_dir} --json --output {workdir}/semgrep.json", shell=True)

    # Trivy
    subprocess.run(f"trivy fs {repo_dir} -f json -o {workdir}/trivy.json", shell=True)

    # Upload to DefectDojo
    for tool, file, scan in [
        ("semgrep", "semgrep.json", "Semgrep JSON Report"),
        ("trivy", "trivy.json", "Trivy Scan"),
    ]:
        requests.post(
            f"{DOJO_URL}/api/v2/import-scan/",
            headers={"Authorization": f"Token {DOJO_TOKEN}"},
            files={"file": open(f"{workdir}/{file}", "rb")},
            data={"scan_type": scan, "engagement": ENGAGEMENT_ID},
        )

    # ZAP (optional)
    if target_url:
        subprocess.run(
            f'docker run --rm -v {workdir}:/zap/wrk ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t {target_url} -J /zap/wrk/zap.json',
            shell=True
        )

    return {"status": "done"}
