import os
import shutil
import subprocess
import uuid
import re
import json
import logging
from celery_app import celery_app
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# Directories - use same env vars as before
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/security_scans")
REPORT_DIR = os.getenv("REPORT_DIR", "reports")
TEMPLATE_PATH = os.getenv("TRIVY_TEMPLATE", "trivy-html.tpl")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


@celery_app.task(bind=True)
def run_scan(self, project_name, language, app_type, framework, file_bytes, base_url):
    # Sanitize project_name
    safe_project_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", project_name)
    job_id = str(uuid.uuid4())
    workspace_path = os.path.join(UPLOAD_DIR, job_id)
    os.makedirs(workspace_path, exist_ok=True)

    archive_path = os.path.join(workspace_path, "code.tar")
    extract_path = os.path.join(workspace_path, "src")
    os.makedirs(extract_path, exist_ok=True)

    try:
        # Save uploaded file
        with open(archive_path, "wb") as buffer:
            buffer.write(file_bytes)

        # Extract safely using tarfile (instead of subprocess)
        import tarfile

        with tarfile.open(archive_path, "r") as tar:
            tar.extractall(path=extract_path, filter="data")  # Python 3.12+

        vulnerabilities = []

        # --- Opengrep SAST ---
        opengrep_json_path = os.path.join(workspace_path, "opengrep.json")
        opengrep_cmd = [
            "opengrep",
            "scan",
            "--taint-intrafile",
            "--config=auto",
            "--json",
            f"--output={opengrep_json_path}",
            extract_path,
        ]
        og_result = subprocess.run(opengrep_cmd, capture_output=True, text=True)
        if og_result.returncode not in (0, 1):
            logger.warning(
                f"Opengrep scan exited with code {og_result.returncode}: {og_result.stderr}"
            )

        if os.path.exists(opengrep_json_path):
            with open(opengrep_json_path, "r") as f:
                opengrep_data = json.load(f)
                for finding in opengrep_data.get("results", []):
                    vulnerabilities.append(
                        {
                            "scanner": "Opengrep",
                            "id": finding.get("check_id"),
                            "severity": finding.get("extra", {}).get(
                                "severity", "UNKNOWN"
                            ),
                            "description": finding.get("extra", {}).get("message"),
                            "file": finding.get("path", "").replace(extract_path, ""),
                            "line": finding.get("start", {}).get("line"),
                        }
                    )

        # --- Trivy SCA ---
        trivy_json_path = os.path.join(workspace_path, "trivy.json")
        trivy_html_path = os.path.join(REPORT_DIR, f"{safe_project_name}-{job_id}.html")

        # Run Trivy only once, generating both JSON and HTML from the same run?
        # We can generate JSON, parse it, and also generate HTML from the same run using a second command?
        # Better: run once with JSON, then use a separate conversion or client-side rendering.
        # But to keep your existing flow, we'll run twice as before (but we can optimize later).

        trivy_cmd_json = [
            "trivy",
            "fs",
            "--scanners",
            "vuln,misconfig,secret",
            "--format",
            "json",
            "--output",
            trivy_json_path,
            extract_path,
        ]
        tj_result = subprocess.run(trivy_cmd_json, capture_output=True, text=True)
        if tj_result.returncode != 0:
            logger.error(f"Trivy JSON generation failed: {tj_result.stderr}")

        # HTML report
        if not os.path.exists(TEMPLATE_PATH):
            raise Exception(f"Trivy HTML template not found at {TEMPLATE_PATH}")

        trivy_cmd_html = [
            "trivy",
            "fs",
            "--scanners",
            "vuln,misconfig,secret",
            "--format",
            "template",
            "--template",
            f"@{TEMPLATE_PATH}",
            "--output",
            trivy_html_path,
            extract_path,
        ]
        th_result = subprocess.run(trivy_cmd_html, capture_output=True, text=True)
        if th_result.returncode != 0:
            logger.error(f"Trivy HTML generation failed: {th_result.stderr}")

        # Parse Trivy JSON
        if os.path.exists(trivy_json_path):
            with open(trivy_json_path, "r") as f:
                trivy_data = json.load(f)
                for result in trivy_data.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []):
                        vulnerabilities.append(
                            {
                                "scanner": "Trivy",
                                "id": vuln.get("VulnerabilityID"),
                                "severity": vuln.get("Severity", "UNKNOWN"),
                                "description": vuln.get("Title", "No Title"),
                                "file": result.get("Target", "").replace(
                                    extract_path, ""
                                ),
                                "line": vuln.get("InstalledVersion", "N/A"),
                            }
                        )

        report_url = f"{base_url}static-reports/{safe_project_name}-{job_id}.html"

        # Return result
        return {
            "status": "success",
            "project_name": safe_project_name,
            "job_id": job_id,
            "report_url": report_url,
            "vulnerabilities": vulnerabilities,
        }

    except Exception as e:
        logger.exception("Task failed")
        # Re-raise to mark task as failed, so status will be FAILURE
        raise
    finally:
        # Cleanup workspace
        if os.path.exists(workspace_path):
            shutil.rmtree(workspace_path)
