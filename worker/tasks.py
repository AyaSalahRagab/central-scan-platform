from celery import Celery
import os
import subprocess
import shutil
from pathlib import Path
import requests
from datetime import date, datetime
import json    backend=os.getenv("REDIS_URL")import json
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


def sanitize_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value)


def get_or_create_product(product_name: str) -> int:
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


def empty_counts():
    return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


def parse_trivy_report(file_path):
    counts = empty_counts()

    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "").upper()
                if severity in counts:
                    counts[severity] += 1

    except Exception as e:
        return {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "error": str(e)
        }

    return counts


def parse_semgrep_report(file_path):
    counts = empty_counts()

    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        for finding in data.get("results", []):
            severity = finding.get("extra", {}).get("severity", "").upper()

            # Semgrep severity mapping
            if severity == "ERROR":
                counts["HIGH"] += 1
            elif severity == "WARNING":
                counts["MEDIUM"] += 1
            elif severity == "INFO":
                counts["LOW"] += 1

    except Exception as e:
        return {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "error": str(e)
        }

    return counts


def parse_zap_report(file_path):
    counts = empty_counts()

    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        # ZAP JSON baseline output usually contains site -> alerts
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                riskcode = str(alert.get("riskcode", ""))

                # ZAP riskcode mapping:
                # 3 = High
                # 2 = Medium
                # 1 = Low
                # 0 = Informational
                if riskcode == "3":
                    counts["HIGH"] += 1
                elif riskcode == "2":
                    counts["MEDIUM"] += 1
                elif riskcode == "1":
                    counts["LOW"] += 1

    except Exception as e:
        return {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "error": str(e)
        }

    return counts


def save_summary_files(base_dir: Path, summary_payload: dict):
    """
    Save summary in:
    - summary.json
    - summary.csv
    - summary.md
    """
    base_dir.mkdir(parents=True, exist_ok=True)

    summary_json = base_dir / "summary.json"
    summary_csv = base_dir / "summary.csv"
    summary_md = base_dir / "summary.md"

    # JSON
    with open(summary_json, "w") as f:
        json.dump(summary_payload, f, indent=2)

    # CSV
    with open(summary_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Tool", "Type", "Status", "Critical", "High", "Medium", "Low"])
        for row in summary_payload.get("summary_table", []):
            writer.writerow([
                row["tool"],
                row["type"],
                row["status"],
                row["critical"],
                row["high"],
                row["medium"],
                row["low"],
            ])

    # Markdown
    md_lines = []
    md_lines.append(f"# Scan Summary")
    md_lines.append("")
    md_lines.append(f"- **Status:** {summary_payload.get('status')}")
    md_lines.append(f"- **Product ID:** {summary_payload.get('product_id')}")
    md_lines.append(f"- **Engagement ID:** {summary_payload.get('engagement_id')}")
    md_lines.append("")
    md_lines.append("| Tool | Type | Status | Critical | High | Medium | Low |")
    md_lines.append("|------|------|--------|----------|------|--------|-----|")

    for row in summary_payload.get("summary_table", []):
        md_lines.append(
            f"| {row['tool']} | {row['type']} | {row['status']} | {row['critical']} | {row['high']} | {row['medium']} | {row['low']} |"
        )

    with open(summary_md, "w") as f:
        f.write("\n".join(md_lines))

    return {
        "json": str(summary_json),
        "csv": str(summary_csv),
        "md": str(summary_md)
    }


@celery_app.task(name="tasks.run_scan")
def run_scan(req):
    repo_url = req["repo_url"]
    product_name = req["product_name"]
    engagement_name = req["engagement_name"]
    target_url = req.get("target_url")

    product_id = get_or_create_product(product_name)
    engagement_id = get_or_create_engagement(product_id, engagement_name)

    workdir = Path("/tmp/scan")
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    repo_dir = workdir / "repo"

    # directory for saved summaries on host
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_product = sanitize_name(product_name)
    safe_engagement = sanitize_name(engagement_name)

    results_dir = Path("/tmp/scan-results") / f"{safe_product}__{safe_engagement}__{timestamp}"
    results_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "product_id": product_id,
        "engagement_id": engagement_id
    }

    # Clone repo
    run_cmd(f"git clone {repo_url} {repo_dir}")

    # -------------------------------
    # 1) Semgrep
    # -------------------------------
    semgrep_file = workdir / "semgrep.json"
    semgrep_counts = empty_counts()
    try:
        run_cmd(f"semgrep scan {repo_dir} --config auto --json --output {semgrep_file}")
        semgrep_counts = parse_semgrep_report(semgrep_file)
        upload_to_dojo("Semgrep JSON Report", str(semgrep_file), engagement_id)
        results["semgrep"] = "uploaded"
    except Exception as e:
        results["semgrep"] = f"failed: {str(e)}"

    # -------------------------------
    # 2) Trivy
    # -------------------------------
    trivy_file = workdir / "trivy.json"
    trivy_counts = empty_counts()
    try:
        run_cmd(f"trivy fs {repo_dir} -f json -o {trivy_file}")
        trivy_counts = parse_trivy_report(trivy_file)
        upload_to_dojo("Trivy Scan", str(trivy_file), engagement_id)
        results["trivy"] = "uploaded"
    except Exception as e:
        results["trivy"] = f"failed: {str(e)}"

    # -------------------------------
    # 3) ZAP
    # -------------------------------
    zap_counts = empty_counts()
    if target_url:
        zap_file = workdir / "zap.json"
        try:
            run_cmd(
                f'docker run --rm -v {workdir}:/zap/wrk {ZAP_IMAGE} '
                f'zap-baseline.py -t {target_url} -J zap.json'
            )

            if zap_file.exists():
                zap_counts = parse_zap_report(zap_file)
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

    summary_table = [
        {
            "tool": "Semgrep",
            "type": "SAST",
            "status": results["semgrep"],
            "critical": semgrep_counts.get("CRITICAL", 0),
            "high": semgrep_counts.get("HIGH", 0),
            "medium": semgrep_counts.get("MEDIUM", 0),
            "low": semgrep_counts.get("LOW", 0)
        },
        {
            "tool": "Trivy",
            "type": "SCA",
            "status": results["trivy"],
            "critical": trivy_counts.get("CRITICAL", 0),
            "high": trivy_counts.get("HIGH", 0),
            "medium": trivy_counts.get("MEDIUM", 0),
            "low": trivy_counts.get("LOW", 0)
        },
        {
            "tool": "ZAP",
            "type": "DAST",
            "status": results["zap"],
            "critical": zap_counts.get("CRITICAL", 0),
            "high": zap_counts.get("HIGH", 0),
            "medium": zap_counts.get("MEDIUM", 0),
            "low": zap_counts.get("LOW", 0)
        }
    ]

    summary_payload = {
        "status": results["status"],
        "product_id": product_id,
        "engagement_id": engagement_id,
        "repo_url": repo_url,
        "product_name": product_name,
        "engagement_name": engagement_name,
        "target_url": target_url,
        "saved_at": datetime.utcnow().isoformat() + "Z",
        "summary_table": summary_table
    }

    saved_files = save_summary_files(results_dir, summary_payload)
    summary_payload["saved_files"] = saved_files

    return summary_payload

import csv
import re

celery_app = Celery(
    "tasks",
    broker=os.getenv("REDIS_URL"),
