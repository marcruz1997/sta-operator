FROM registry.access.redhat.com/ubi9/python-312
WORKDIR /opt/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER 1001
# Escuta só em loopback: o único caminho até aqui é o oauth-proxy do mesmo pod.
# Um processo só, para o worker de expiração e o SQLite ficarem consistentes.
CMD ["gunicorn", "-b", "127.0.0.1:8080", "-w", "1", "--threads", "8", "--timeout", "120", "app:app"]
