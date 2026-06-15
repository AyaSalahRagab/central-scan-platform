from celery import Celery
import os
import subprocess
import shutil
from pathlib import Path
import requests
import json
from datetime import datetime, date

# ✅ Celery Config
celery_app = Celery(
    "tasks",
    broker=os.getenv("REDIS_URL"),
    backend=os.getenv("REDIS_URL")
)

DOJO_URL = os.getenv("DEFECTDOJO_URL")
DOJO_TOKEN = os.getenv("DEFECTDOJO_TOKEN")

# -------------------------
# ✅ Helpers
# -------------------------

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if result.returncode != 0:
        raise Exception(result.stderr)
    return result.stdout


def dojo_headers():
    return {
        "Authorization": f"Token {DOJO_TOKEN}"
    }

# -------------------------
# ✅ Product + Engagement (OLD WORKING ✅)
# -------------------------

def get_or_create_product(name):
    r = requests.get(
        f"{DOJO_URL}/api/v2/products/",
        headers=dojo_headers(),
        params={"name": name}
    )

    data = r.json()

    if data["count"] > 0:
        return data["results"][0]["id"]

    r = requests.post(
        f"{DOJO_URL}/api/v2/products/",
        headers=dojo_headers(),
        json={
            "name": name,
            "prod_type": 1
        }
    )

    return r.json()["id"]


def create_engagement(product_id, name):
    today = date.today().isoformat()

    r = requests.post(
        f"{DOJO_URL}/api/v2/engagements/",
        headers=dojo_headers(),
        json={
            "name": name,
            "product": product_id,
            "status": "In Progress",
            "engagement_type": "CI/CD",
            "target_start": today,
            "target_end": today
        }
    )

    return r.json()["id"]

# -------------------------
# ✅ Upload (IMPORTANT)
# -------------------------

def upload(scan_type, file_path, engagement_id):
    url = f"{DOJO_URL}/api/v2/import-scan/"

    with open(file_path, "rb") as f:
        files = {"file": f}
        data = {
            "scan_type": scan_type,
            "engagement": engagement_id,
            "active": "true",
            "verified": "false"
        }

        r = requests.post(url, headers=dojo_headers(), files=files, data=data)

    if r.status_code not in [200, 201]:
        raise Exception(f"Upload failed: {r.text}")

# -------------------------
# ✅ Parsing (NEW ✅)
# -------------------------

def empty_counts():
    return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


def parse_trivy(file):
    counts = empty_counts()
    try:
        data = json.load(open(file))
        for r in data.get("Results", []):
            for v in r.get("Vulnerabilities", []):
                sev = v.get("Severity", "").upper()
                if sev in counts:
                    counts[sev] += 1
    except:
        pass
    return counts


def parse_semgrep(file):
    counts = empty_counts()
    try:
        data = json.load(open(file))
        for r in data.get("results", []):
            sev = r.get("extra", {}).get("severity", "").upper()
            if sev == "ERROR":
                counts["HIGH"] += 1
            elif sev == "WARNING":
                counts["MEDIUM"] += 1
            elif sev == "INFO":
                counts["LOW"] += 1
    except:
        pass
    return counts

# -------------------------
# ✅ MAIN TASK
# -------------------------

@celery_app.task(name="tasks.run_scan")
def run_scan(req):

    repo_url = req["repo_url"]
    product_name = req["product_name"]
    engagement_name = req["engagement_name"]
    target_url = req.get("target_url")

    # ✅ CREATE PRODUCT + ENGAGEMENT ✅
    product_id = get_or_create_product(product_name)
    engagement_id = create_engagement(product_id, engagement_name)

    workdir = Path("/tmp/scan")
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)

    repo_dir = workdir / "repo"

    run_cmd(f"git clone {repo_url} {repo_dir}")

    results = {}

    # -------------------------
    # ✅ SEMGREP
    # -------------------------
    semgrep_file = workdir / "semgrep.json"

    try:
        run_cmd(f"semgrep scan {repo_dir} --config auto --json -o {semgrep_file}")
        upload("Semgrep JSON Report", semgrep_file, engagement_id)
        results["semgrep"] = "done"
    except Exception as e:
        print("SEMGRP ERROR:", str(e))
        results["semgrep"] = "failed"

    semgrep_counts = parse_semgrep(semgrep_file)

    # -------------------------
    # ✅ TRIVY
    # -------------------------
    trivy_file = workdir / "trivy.json"

    try:
        run_cmd(f"trivy fs {repo_dir} -f json -o {trivy_file}")
        upload("Trivy Scan", trivy_file, engagement_id)
        results["trivy"] = "done"
    except Exception as e:
        print("TRIVY ERROR:", str(e))
        results["trivy"] = "failed"

    trivy_counts = parse_trivy(trivy_file)

    # -------------------------
    # ✅ ZAP
    # -------------------------
    zap_counts = empty_counts()

    if target_url:
        try:
            run_cmd(f"docker run --rm ghcr.io/zaproxy/zaproxy zap-baseline.py -t {target_url}")
            results["zap"] = "done"
        except Exception as e:
            print("ZAP ERROR:", str(e))
            results["zap"] = "failed"
    else:
        results["zap"] = "skipped"

    # -------------------------
    # ✅ SUMMARY (NEW ✅)
    # -------------------------
    summary = [
        {
            "tool": "Semgrep",
            "type": "SAST",
            "status": results["semgrep"],
            **semgrep_counts
        },
        {
            "tool": "Trivy",
            "type": "SCA",
            "status": results["trivy"],
            **trivy_counts
        },
        {
            "tool": "ZAP",
            "type": "DAST",
            "status": results["zap"],
            **zap_counts
        }
    ]

    # -------------------------
    # ✅ SAVE FILE (NEW ✅)
    # -------------------------
    out_dir = Path("/tmp/scan-results") / product_name
    out_dir.mkdir(parents=True, exist_ok=True)

    file_name = f"{engagement_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    file_path = out_dir / file_name

    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w") as f:
        json.dump(summary, f, indent=2)

    # -------------------------
    # ✅ RETURN
    # -------------------------
    return {
        "status": "completed",
        "summary": summary,
        "saved_file": str(file_path)
    }
