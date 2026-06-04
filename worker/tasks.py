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
