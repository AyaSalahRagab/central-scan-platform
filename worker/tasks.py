from celery import Celery
import os
import subprocess
import shutil
from pathlib import Path
import requests
import json
from datetime import datetime

# ✅ Celery Config (مهم جدًا)
celery_app = Celery(
    "tasks",
    broker=os.getenv("REDIS_URL"),
    backend=os.getenv("REDIS_URL")
)

# ✅ Env variables
DOJO_URL = os.getenv("DEFECTDOJO_URL")
DOJO_TOKEN = os.getenv("DEFECTDOJO_TOKEN")

# -------------------------
# ✅ Helpers
# -------------------------

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if result.returncode != 0:
        raise Exception(f"Command failed:\n{result.stderr}")
    return result.stdout


def dojo_headers():
    return {
        "Authorization": f"Token {DOJO_TOKEN}"
    }


# -------------------------
# ✅ Parse Reports
# -------------------------

def parse_trivy(file):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    try:
        data = json.load(open(file))
        for r in data.get("Results", []):
            for v in r.get("Vulnerabilities", []):
                sev = v.get("Severity", "")
                if sev in counts:
                    counts[sev] += 1
    except:
        pass

    return counts


def parse_semgrep(file):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

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
# ✅ DefectDojo Upload
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
# ✅ MAIN TASK
# -------------------------

@celery_app.task(name="tasks.run_scan")
def run_scan(req):

    repo_url = req["repo_url"]
    product_name = req["product_name"]
    engagement_name = req["engagement_name"]
    target_url = req.get("target_url")

    # ✅ Working dir
    workdir = Path("/tmp/scan")
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)

    repo_dir = workdir / "repo"

    # ✅ Clone
    run_cmd(f"git clone {repo_url} {repo_dir}")

    results = {}

    # -------------------------
    # ✅ Semgrep
    # -------------------------
    semgrep_file = workdir / "semgrep.json"

    try:
        run_cmd(f"semgrep scan {repo_dir} --config auto --json -o {semgrep_file}")
        semgrep_counts = parse_semgrep(semgrep_file)
        results["semgrep"] = "done"
    except Exception as e:
        semgrep_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        results["semgrep"] = "failed"

    # -------------------------
    # ✅ Trivy
    # -------------------------
    trivy_file = workdir / "trivy.json"

    try:
        run_cmd(f"trivy fs {repo_dir} -f json -o {trivy_file}")
        trivy_counts = parse_trivy(trivy_file)
        results["trivy"] = "done"
    except Exception as e:
        trivy_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        results["trivy"] = "failed"

    # -------------------------
    # ✅ ZAP (optional)
    # -------------------------
    zap_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    if target_url:
        try:
            run_cmd(f"docker run --rm ghcr.io/zaproxy/zaproxy zap-baseline.py -t {target_url}")
            results["zap"] = "done"
        except:
            results["zap"] = "failed"
    else:
        results["zap"] = "skipped"

    # -------------------------
    # ✅ Summary Table
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
    # ✅ Save File
    # -------------------------
    out_dir = Path("/tmp/scan-results")
    out_dir.mkdir(exist_ok=True)

    file_name = f"{product_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    file_path = out_dir / file_name

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
