FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --timeout 300 -r /app/requirements.txt

COPY watcher.py /app/watcher.py

CMD ["python", "watcher.py"]

