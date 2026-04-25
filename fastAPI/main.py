import csv
import json
import os
import pickle
import re
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import unquote
import httpx
from fastapi import FastAPI, HTTPException, Request

from process_flows import prepare_features

app = FastAPI(title="SOC AI Engine", version="1.0.0")

MODEL_PATH = os.getenv("MODEL_PATH", "soc_model.pkl")
FEATURE_COLUMNS_PATH = os.getenv("FEATURE_COLUMNS_PATH", "feature_columns.pkl")
LABEL_ENCODER_PATH = os.getenv("LABEL_ENCODER_PATH", "label_encoder.pkl")

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
WAZUH_INDEX_PATTERN = os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
WAZUH_VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "false").lower() == "true"
WAZUH_TIMEOUT_SEC = float(os.getenv("WAZUH_TIMEOUT_SEC", "5"))


def _norm(text: str) -> str:
    return text.strip().lower().replace(" ", "_")


def _find_value(flow: Dict[str, Any], aliases: List[str], default: Any = "") -> Any:
    index = {_norm(k): v for k, v in flow.items()}
    for alias in aliases:
        v = index.get(_norm(alias))
        if v is not None and str(v) != "":
            return v
    return default


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except Exception:
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        out = float(v)
        if out == float("inf") or out == float("-inf") or out != out:
            return default
        return out
    except Exception:
        return default


def _extract_identifiers(flow: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "src_ip": str(_find_value(flow, ["src_ip", "source_ip", "srcip"], "")),
        "dst_ip": str(_find_value(flow, ["dst_ip", "destination_ip", "dstip"], "")),
        "src_port": _safe_int(_find_value(flow, ["src_port", "source_port", "srcport"], 0)),
        "dst_port": _safe_int(_find_value(flow, ["dst_port", "destination_port", "dstport"], 0)),
    }


def _extract_observability_fields(flow: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "protocol": str(_find_value(flow, ["protocol", "protocol_type"], "unknown")),
        "flow_duration": _safe_float(_find_value(flow, ["flow_duration"], 0.0)),
        "flow_packets_per_sec": _safe_float(
            _find_value(flow, ["flow_packets_per_sec", "flow_pkts_s", "flow_packets/s"], 0.0)
        ),
        "flow_bytes_per_sec": _safe_float(
            _find_value(flow, ["flow_bytes_per_sec", "flow_byts_s", "flow_bytes/s"], 0.0)
        ),
    }


def _decode_payload(text: str) -> str:
    """Decode URL-encoded payloads before regex matching (handles %3Cscript%3E etc.)"""
    try:
        return unquote(unquote(text))  # double-decode catches double-encoded payloads
    except Exception:
        return text

SQLI_REGEX = re.compile(
    r"(union\s+select|select\s+.+\s+from|drop\s+table|insert\s+into|delete\s+from|or\s+1\s*=\s*1|xp_cmdshell|information_schema|--\s|;\s*--)",
    re.IGNORECASE,
)
XSS_REGEX = re.compile(
    r"(<script[\s>]|</script>|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|eval\s*\(|<img[^>]+src\s*=)",
    re.IGNORECASE,
)
RCE_REGEX = re.compile(
    r"(;\s*(cat|ls|whoami|id)\b|\$\(|\b(wget|curl)\b.*http|\b/bin/sh\b|\bcmd\.exe\b)",
    re.IGNORECASE,
)
LFI_REGEX = re.compile(
    r"(\.\./\.\./|/etc/passwd|/proc/self/environ|boot\.ini|win\.ini)",
    re.IGNORECASE,
)


def _classify_web_sub_type(full_log: str) -> str:
    if not full_log:
        return "Web Attack - Unknown"
    decoded = _decode_payload(full_log)
    if SQLI_REGEX.search(decoded):
        return "Web Attack - SQLi"
    if XSS_REGEX.search(decoded):
        return "Web Attack - XSS"
    if RCE_REGEX.search(decoded):
        return "Web Attack - RCE"
    if LFI_REGEX.search(decoded):
        return "Web Attack - LFI"
    return "Web Attack - Unknown"


async def _query_wazuh_full_log(src_ip: str) -> str:
    if not (WAZUH_INDEXER_URL and WAZUH_USERNAME and WAZUH_PASSWORD and src_ip):
        return ""

    query = {
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "should": [
                    {"match_phrase": {"data.srcip": src_ip}},
                    {"match_phrase": {"src_ip": src_ip}},
                    {"match_phrase": {"agent.ip": src_ip}},
                    {"match_phrase": {"source.ip": src_ip}},
                ],
                "minimum_should_match": 1,
            }
        },
        "_source": ["full_log", "data.url", "data.data", "rule.description", "@timestamp"],
    }

    url = f"{WAZUH_INDEXER_URL}/{WAZUH_INDEX_PATTERN}/_search"
    try:
        async with httpx.AsyncClient(verify=WAZUH_VERIFY_TLS, timeout=WAZUH_TIMEOUT_SEC) as client:
            resp = await client.post(
                url,
                auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
                json=query,
                headers={"Content-Type": "application/json"},
            )
        if resp.status_code >= 300:
            print(f"[ai_engine] wazuh query failed: {resp.status_code} {resp.text[:300]}")
            return ""

        payload = resp.json()
        hits = payload.get("hits", {}).get("hits", [])
        if not hits:
            return ""

        src = hits[0].get("_source", {})
        full_log = src.get("full_log")
        if full_log:
            return str(full_log)

        fallback = " ".join([
            str(src.get("rule.description", "")),
            str(src.get("data.url", "")),
            str(src.get("data.data", "")),
        ]).strip()
        return fallback
    except Exception as exc:
        print(f"[ai_engine] wazuh exception: {exc}")
        return ""


try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
except FileNotFoundError:
    raise RuntimeError(f"[ai_engine] Model file not found: {MODEL_PATH}. Place soc_model.pkl in the /app directory.")

try:
    with open(FEATURE_COLUMNS_PATH, "rb") as f:
        feature_columns = pickle.load(f)
except FileNotFoundError:
    raise RuntimeError(f"[ai_engine] Feature columns file not found: {FEATURE_COLUMNS_PATH}. Place feature_columns.pkl in the /app directory.")

label_encoder = None
if os.path.exists(LABEL_ENCODER_PATH):
    try:
        with open(LABEL_ENCODER_PATH, "rb") as f:
            label_encoder = pickle.load(f)
    except Exception as exc:
        print(f"[ai_engine] WARNING: Could not load label encoder: {exc}. Predictions will use raw numeric labels.")

# Use the model's expected columns if available, else fallback to feature_columns.
model_feature_columns = list(getattr(model, "feature_names_in_", feature_columns))


@app.post("/predict")
async def predict(request: Request):
    raw_body = await request.body()
    if not raw_body:
        raise HTTPException(status_code=400, detail="Empty body")

    try:
        raw_csv = raw_body.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid UTF-8 payload: {exc}") from exc

    try:
        values = next(csv.reader([raw_csv]))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid CSV row: {exc}") from exc

    if len(values) != len(feature_columns):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Column mismatch: got {len(values)} values, expected {len(feature_columns)} "
                f"(based on feature_columns.pkl). Check that the CSV row matches the training schema."
            ),
    )

    flow_dict = dict(zip(feature_columns, values))

    # Sanity check: warn if model_feature_columns diverges from feature_columns after ID stripping
    expected_model_cols = set(model_feature_columns)
    incoming_cols = set(feature_columns)
    missing = expected_model_cols - incoming_cols
    if missing:
        print(f"[ai_engine] WARNING: model expects columns not found in incoming flow: {missing}. Predictions may be wrong.")
    ids = _extract_identifiers(flow_dict)
    obs = _extract_observability_fields(flow_dict)

    X = prepare_features(
        raw_flow=flow_dict,
        model_feature_columns=model_feature_columns,
        feature_encoder=label_encoder,
    )

    pred_raw = model.predict(X)[0]
    if hasattr(label_encoder, "inverse_transform"):
        try:
            ml_label = str(label_encoder.inverse_transform([pred_raw])[0])
        except Exception:
            ml_label = str(pred_raw)
    else:
        ml_label = str(pred_raw)

    confidence = 1.0
    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(X)[0]
            confidence = float(max(proba))
        except Exception:
            confidence = 1.0

    sub_type = "N/A"
    if ml_label == "Web Attack":
        full_log = await _query_wazuh_full_log(ids["src_ip"])
        sub_type = _classify_web_sub_type(full_log)

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ml_label": ml_label,
        "src_ip": ids["src_ip"],
        "src_port": ids["src_port"],
        "dst_ip": ids["dst_ip"],
        "dst_port": ids["dst_port"],
        "protocol": obs["protocol"],
        "flow_duration": obs["flow_duration"],
        "flow_packets_per_sec": obs["flow_packets_per_sec"],
        "flow_bytes_per_sec": obs["flow_bytes_per_sec"],
        "source": "ml_pipeline",
        "sub_type": sub_type,
        "confidence": confidence,
    }

    # Must always print to container logs (including Normal).
    print(json.dumps(result, ensure_ascii=True))
    return result
