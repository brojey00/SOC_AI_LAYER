# SOC Hybrid IDS - Deployment Assets

This repository contains deployment-ready code for:
- `scripts/watcher.py` (Flow Agent)
- `fastAPI/main.py` (AI Engine API)
- `fastAPI/process_flows.py` (feature cleaning/preparation)

## Service Contract

- Watcher tails `/shared_data/live_flows.csv` and forwards each new CSV row as raw `text/plain` to `POST /predict`.
- AI Engine parses raw CSV using `feature_columns.pkl`, performs feature processing, runs model inference (`soc_model.pkl`), and returns/logs JSON for **all** traffic including `Normal`.
- If `ml_label == "Web Attack"`, AI Engine queries Wazuh Indexer for recent source-IP logs and applies regex sub-classification.

## Environment Variables

### AI Engine (`fastAPI/main.py`)
- `MODEL_PATH` (default: `soc_model.pkl`)
- `FEATURE_COLUMNS_PATH` (default: `feature_columns.pkl`)
- `LABEL_ENCODER_PATH` (default: `label_encoder.pkl`)
- `WAZUH_INDEXER_URL`
- `WAZUH_USERNAME`
- `WAZUH_PASSWORD`
- `WAZUH_INDEX_PATTERN` (default: `wazuh-alerts-*`)
- `WAZUH_VERIFY_TLS` (default: `false`)
- `WAZUH_TIMEOUT_SEC` (default: `5`)

### Watcher (`scripts/watcher.py`)
- `CSV_PATH` (default: `/shared_data/live_flows.csv`)
- `AI_URL` (default: `http://ai_engine:8000/predict`)
- `POLL_INTERVAL_SEC` (default: `0.2`)
- `REQUEST_TIMEOUT_SEC` (default: `10`)
- `BACKOFF_INITIAL_SEC` (default: `1`)
- `BACKOFF_MAX_SEC` (default: `60`)
- `BACKOFF_JITTER_SEC` (default: `0.25`)

## Quick Start (Docker Compose)

```bash
docker compose up --build
```

Ensure your flow CSV appears at `./shared_data/live_flows.csv` (or adapt the volume mapping to your remote host path).

## Local Python Run (without Docker)

```bash
pip install -r fastAPI/requirements.txt
pip install -r scripts/requirements.txt
python -m uvicorn fastAPI.main:app --host 0.0.0.0 --port 8000
python scripts/watcher.py
```

## Smoke Check

Start AI Engine, then POST one raw CSV line:

```bash
curl -X POST http://127.0.0.1:8000/predict -H "Content-Type: text/plain" --data "<csv_row_matching_feature_columns_order>"
```

