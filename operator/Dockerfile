FROM registry.access.redhat.com/ubi9/python-311:latest

WORKDIR /opt/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY controller.py icon.svg ./
COPY manifests/ manifests/

USER 1001
# Standalone: uma réplica só, sem peering entre instâncias
CMD ["kopf", "run", "--standalone", "--all-namespaces", "/opt/app/controller.py"]
