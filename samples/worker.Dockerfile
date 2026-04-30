# Single-stage Python worker.

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV WORKER_CONCURRENCY=4
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["python", "-m"]
CMD ["worker"]
