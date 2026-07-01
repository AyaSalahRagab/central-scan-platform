import os
import shutil
import subprocess
import uuid
import re
import json
import logging
import requests
from datetime import datetime, timedelta
from celery_app import celery_app

logger = logging.getLogger(__name__)

# Directories - use same env vars as before
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/security_scans")
REPORT_DIR = os.getenv("REPORT_DIR", "reports")
TEMPLATE_PATH = os.getenv("TRIVY_TEMPLATE", "trivy-html.tpl")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# DefectDojo configuration
DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL")
DEFECTDOJO_API_KEY = os.getenv("DEFECTDOJO_API_KEY")

# ----------------------------------------------------------------------
# DefectDojo helper functions
# ----------------------------------------------------------------------

def defectdojo_request(method, endpoint, **kwargs):
    """Make an authenticated request to the DefectDojo API."""
    url = f"{DEFECTDOJO_URL}/{endpoint.lstrip('/')}"
    headers = {
        "Authorization": f"Token {DEFECTDOJO_API_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if "headers" in kwargs:
        headers.update(kwargs.pop("headers"))
    response = requests.request(method, url, headers=headers, **kwargs)
    return response


def get_or_create_product_type(name="Security Scans"):
    """
    Fetch an existing product type by name, or create a new one.
    Returns the product type ID.
    """
    # Search by name
    resp = defectdojo_request("GET", f"/product_types/?name={name}")
    if resp.status_code == 200:
        data = resp.json()
        if data["count"] > 0:
            return data["results"][0]["id"]
    # Create a new product type
    resp = defectdojo_request(
        "POST",
        "/product_types/",
        json={"name": name, "description": f"Auto-created: {name}"},
    )
    if resp.status_code in (200, 201):
        return resp.json()["id"]
    raise Exception(f"Failed to create product type: {resp.text}")


def get_or_create_product(product_name):
    """
    Fetch an existing product by name, or create a new one.
    Ensures a product type exists and uses it.
    """
    # Search for product
    resp = defectdojo_request("GET", f"/products/?name={product_name}")
    if resp.status_code == 200:
        data = resp.json()
        if data["count"] > 0:
            return data["results"][0]["id"]

    # Get (or create) a product type
    prod_type_id = get_or_create_product_type()

    # Create the product
    resp = defectdojo_request(
        "POST",
        "/products/",
        json={
            "name": product_name,
            "description": f"Auto-created for {product_name}",
            "prod_type": prod_type_id,  # <-- required field
        },
    )
    if resp.status_code in (200, 201):
        return resp.json()["id"]
    raise Exception(f"Failed to create product: {resp.text}")


def get_or_create_engagement(product_id, engagement_name):
    """Fetch an existing engagement by name under a product, or create a new one."""
    # Search for engagement
    resp = defectdojo_request(
        "GET", f"/engagements/?product={product_id}&name={engagement_name}"
    )
    if resp.status_code == 200:
        data = resp.json()
        if data["count"] > 0:
            return data["results"][0]["id"]
    # Create engagement
    payload = {
        "product": product_id,
        "name": engagement_name,
        "description": f"Scan run for {engagement_name}",
        "engagement_type": "CI/CD",
        "status": "In Progress",
        "target_start": datetime.now().strftime("%Y-%m-%d"),
        "target_end": (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d"),
    }
    resp = defectdojo_request("POST", "/engagements/", json=payload)
    if resp.status_code in (200, 201):
        return resp.json()["id"]
    raise Exception(f"Failed to create engagement: {resp.text}")


def import_scan_to_defectdojo(scan_type, json_file_path, product_name, engagement_name):
    """
    Upload a scan JSON file to DefectDojo.
    Creates product/engagement automatically if they don't exist.
    """
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        logger.warning("DefectDojo credentials not set. Skipping upload.")
        return

    # Map scanner types to DefectDojo's scan_type values
    scan_type_mapping = {
        "opengrep": "Semgrep JSON Report",  # Opengrep uses Semgrep-compatible JSON
        "trivy": "Trivy Scan",
    }
    scan_type = scan_type_mapping.get(scan_type, scan_type)

    # Ensure product and engagement exist
    product_id = get_or_create_product(product_name)
    engagement_id = get_or_create_engagement(product_id, engagement_name)

    # Now import the scan
    url = f"{DEFECTDOJO_URL}/import-scan/"
    headers = {"Authorization": f"Token {DEFECTDOJO_API_KEY}"}
    files = {"file": open(json_file_path, "rb")}
    data = {
        "scan_type": scan_type,
        "product_name": product_name,  # or use product_id
        "engagement_name": engagement_name,  # or use engagement_id
        "active": "true",
        "verified": "true",
        "minimum_severity": "Info",
        "close_old_findings": "false",
        "tags": product_name,
    }
    try:
        response = requests.post(
            url, headers=headers, files=files, data=data, timeout=60
        )
        if response.status_code in (200, 201):
            logger.info(
                f"✅ Uploaded {scan_type} scan to DefectDojo (engagement: {engagement_name})"
            )
        else:
            logger.error(
                f"❌ DefectDojo upload failed (status {response.status_code}): {response.text}"
            )
    except Exception as e:
        logger.error(f"Exception during DefectDojo upload: {e}")
    finally:
        files["file"].close()


# ----------------------------------------------------------------------
# Celery task
# ----------------------------------------------------------------------

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

    # Initialize separate summaries for tools
    summary = {
        "Opengrep": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0, "TOTAL": 0},
        "Trivy": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0, "TOTAL": 0}
    }

    try:
        # Save uploaded file
        with open(archive_path, "wb") as buffer:
            buffer.write(file_bytes)

        # Extract safely using tarfile
        import tarfile

        with tarfile.open(archive_path, "r") as tar:
            tar.extractall(path=extract_path)

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
                    # Extract and normalize severity
                    sev_raw = finding.get("extra", {}).get("severity", "UNKNOWN").upper()
                    sev = "HIGH" if sev_raw == "ERROR" else ("MEDIUM" if sev_raw == "WARNING" else sev_raw)
                    
                    if sev not in summary["Opengrep"]:
                        sev = "UNKNOWN"
                    
                    # Update counters
                    summary["Opengrep"][sev] += 1
                    summary["Opengrep"]["TOTAL"] += 1

                    vulnerabilities.append(
                        {
                            "scanner": "Opengrep",
                            "id": finding.get("check_id"),
                            "severity": sev,
                            "description": finding.get("extra", {}).get("message"),
                            "file": finding.get("path", "").replace(extract_path, ""),
                            "line": finding.get("start", {}).get("line"),
                        }
                    )

        # --- Trivy SCA ---
        trivy_json_path = os.path.join(workspace_path, "trivy.json")
        trivy_html_path = os.path.join(REPORT_DIR, f"{safe_project_name}-{job_id}.html")

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
                        sev = vuln.get("Severity", "UNKNOWN").upper()
                        
                        if sev not in summary["Trivy"]:
                            sev = "UNKNOWN"
                        
                        # Update counters
                        summary["Trivy"][sev] += 1
                        summary["Trivy"]["TOTAL"] += 1

                        vulnerabilities.append(
                            {
                                "scanner": "Trivy",
                                "id": vuln.get("VulnerabilityID"),
                                "severity": sev,
                                "description": vuln.get("Title", "No Title"),
                                "file": result.get("Target", "").replace(
                                    extract_path, ""
                                ),
                                "line": vuln.get("InstalledVersion", "N/A"),
                            }
                        )

        # --- Upload to DefectDojo ---
        if DEFECTDOJO_URL and DEFECTDOJO_API_KEY:
            # Use a unique engagement name per scan run
            engagement_name = (
                f"Scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{job_id[:8]}"
            )
            if os.path.exists(opengrep_json_path):
                import_scan_to_defectdojo(
                    "opengrep", opengrep_json_path, safe_project_name, engagement_name
                )
            if os.path.exists(trivy_json_path):
                import_scan_to_defectdojo(
                    "trivy", trivy_json_path, safe_project_name, engagement_name
                )
        else:
            logger.info("DefectDojo integration not configured – skipping upload.")

        # Build report URL
        report_url = f"{base_url}static-reports/{safe_project_name}-{job_id}.html"

        # Return result with structured summary
        return {
            "status": "success",
            "project_name": safe_project_name,
            "job_id": job_id,
            "report_url": report_url,
            "summary": summary,
            "vulnerabilities": vulnerabilities,
        }

    except Exception as e:
        logger.exception("Task failed")
        # Re-raise to mark task as failed
        raise
    finally:
        # Cleanup workspace
        if os.path.exists(workspace_path):
            shutil.rmtree(workspace_path)
