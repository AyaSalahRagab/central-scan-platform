FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git curl wget docker.io

# Install Trivy
RUN apt-get install -y gnupg lsb-release
RUN wget -qO- https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb bookworm main" > /etc/apt/sources.list.d/trivy.list
RUN apt-get update && apt-get install -y trivy

# Install Semgrep
RUN pip install semgrep

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY tasks.py .
