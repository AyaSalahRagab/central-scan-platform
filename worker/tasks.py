from celery import Celery
import os
import subprocess
import shutil
from pathlib import Path
import requests
from datetime import date

celery_app = Celery(
    "tasks",
    broker=os.getenv("REDIS_URL"),
    backend=os.getenv("REDIS_URL")
)

DOJO_URL = os.getenv("DEFECTDOJO_URL")
DOJO_TOKEN = os.getenv("DEFECTDOJO_TOKEN")
PRODUCT_TYPE_ID = os.getenv("DEFECTDOJO_PRODUCT_TYPE_ID", "1")
ZAP_IMAGE = os.getenv("ZAP_DOCKER_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")


def dojo_headers():
    return {
        "Authorization": f"Token {DOJO_TOKEN}"
    }


def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"FAILED: {cmd}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout


def get_or_create_product(product_name: str) -> int:
    # Search existing product
    r = requests.get(
        f"{DOJO_URL}/api/v2/products/",
        headers=dojo_headers(),
        params={"name": product_name},
        timeout=60
    )
    r.raise_for_status()
    data = r.json()

    if data.get("count", 0) > 0:
        return data["results"][0]["id"]

    # Create new product
    payload = {
        "name": product_name,
        "description": f"Auto-created product for {product_name}",
        "prod_type": int(PRODUCT_TYPE_ID)
    }

    r = requests.post(
        f"{DOJO_URL}/api/v2/products/",
        headers=dojo_headers(),
        json=payload,
        timeout=60
    )
    r.raise_for_status()
    return r.json()["id"]


def get_or_create_engagement(product_id: int, engagement_name: str) -> int:
    # Search existing engagement
    r = requests.get(
        f"{DOJO_URL}/api/v2/engagements/",
        headers=dojo_headers(),
        params={"name": engagement_name, "product": product_id},
        timeout=60
    )
    r.raise_for_status()
    data = r.json()

    if data.get("count", 0) > 0:
        return data["results"][0]["id"]

    # Create new engagement
    today = date.today().isoformat()
    payload = {
        "name": engagement_name,
        "description": f"Auto-created engagement for {engagement_name}",
        "product": product_id,
        "target_start": today,
        "target_end": today,
        "status": "In Progress",
        "engagement_type": "CI/CD"
    }

    r = requests.post(
        f"{DOJO_URL}/api/v2/engagements/",
        headers=dojo_headers(),
        json=payload,
        timeout=60
    )
    r.raise_for_status()
    return r.json()["id"]


def upload_to_dojo(scan_type, report_path, engagement_id):
    url = f"{DOJO_URL}/api/v2/import-scan/"
    headers = dojo_headers()

    with open(report_path, "rb") as f:
        files = {"file": f}
        data = {
            "scan_type": scan_type,
            "engagement": engagement_id,
            "active": "true",
            "verified": "false"
        }

        r = requests.post(
            url,
            headers=headers,
            files=files,
            data=data,
            timeout=300
        )

    if r.status_code not in [200, 201]:
        raise RuntimeError(f"DefectDojo upload failed: {r.status_code} {r.text}")

    return r.text


@celery_app.task(name="tasks.run_scan")
def run_scan(req):
    repo_url = req["repo_url"]
    product_name = req["product_name"]
    engagement_name = req["engagement_name"]
    target_url = req.get("target_url")

    # Create / get DefectDojo context dynamically
    product_id = get_or_create_product(product_name)
    engagement_id = get_or_create_engagement(product_id, engagement_name)

    workdir = Path("/tmp/scan")
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    repo_dir = workdir / "repo"

    # Clone repo
    run_cmd(f"git clone {repo_url} {repo_dir}")

    results = {
        "product_id": product_id,
        "engagement_id": engagement_id
    }

    # -------------------------------
    # 1) Semgrep
    # -------------------------------
    semgrep_file = workdir / "semgrep.json"
    try:
        run_cmd(f"semgrep scan {repo_dir} --config auto --json --output {semgrep_file}")
        upload_to_dojo("Semgrep JSON Report", str(semgrep_file), engagement_id)
        results["semgrep"] = "uploaded"
    except Exception as e:
        results["semgrep"] = f"failed: {str(e)}"

    # -------------------------------
    # 2) Trivy
    # -------------------------------
    trivy_file = workdir / "trivy.json"
    try:
        run_cmd(f"trivy fs {repo_dir} -f json -o {trivy_file}")
        upload_to_dojo("Trivy Scan", str(trivy_file), engagement_id)
        results["trivy"] = "uploaded"
    except Exception as e:
        results["trivy"] = f"failed: {str(e)}"

    # -------------------------------
    # 3) ZAP
    # -------------------------------
    if target_url:
        zap_file = workdir / "zap.json"
        try:
            run_cmd(
                f'docker run --rm -v {workdir}:/zap/wrk {ZAP_IMAGE} '
                f'zap-baseline.py -t {target_url} -J zap.json'
            )

            if zap_file.exists():
                upload_to_dojo("ZAP Scan", str(zap_file), engagement_id)
                results["zap"] = "uploaded"
            else:
                results["zap"] = "failed: zap.json was not generated"

        except Exception as e:
            results["zap"] = f"failed: {str(e)}"
    else:
        results["zap"] = "skipped: no target_url provided"

    # Final status
    if any(str(v).startswith("failed") for k, v in results.items() if k in ["semgrep", "trivy", "zap"]):
        results["status"] = "partial_success"
    else:
        results["status"] = "completed"

    return results
