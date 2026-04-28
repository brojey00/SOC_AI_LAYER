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

from process_flows import prepare_features, debug_features

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

OUTPUT_URL= os.getenv("OUTPUT_URL", "http://100.104.54.105:8080/ingest")
OUTPUT_TIMEOUT_SEC = float(os.getenv("OUTPUT_TIMEOUT_SEC", "5"))
def _norm(text: str) -> str:
    """Mirror of process_flows._norm — keep both in sync."""
    return text.strip().lower().replace(" ", "_").replace("/", "_")


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


# Actual cicflowmeter (hieulw/cicflowmeter) output column order
# mapped to CIC-IDS2017 names that match the model's training features.
CIC_82_COLUMNS = [
    "src_ip",                      # 0  src_ip
    "dst_ip",                      # 1  dst_ip
    "src_port",                    # 2  src_port
    "Destination Port",            # 3  dst_port
    "Protocol",                    # 4  protocol
    "Timestamp",                   # 5  timestamp
    "Flow Duration",               # 6  flow_duration
    "Flow Bytes/s",                # 7  flow_byts_s
    "Flow Packets/s",              # 8  flow_pkts_s
    "Fwd Packets/s",               # 9  fwd_pkts_s
    "Bwd Packets/s",               # 10 bwd_pkts_s
    "Total Fwd Packets",           # 11 tot_fwd_pkts
    "Total Backward Packets",      # 12 tot_bwd_pkts
    "Total Length of Fwd Packets", # 13 totlen_fwd_pkts
    "Total Length of Bwd Packets", # 14 totlen_bwd_pkts
    "Fwd Packet Length Max",       # 15 fwd_pkt_len_max
    "Fwd Packet Length Min",       # 16 fwd_pkt_len_min
    "Fwd Packet Length Mean",      # 17 fwd_pkt_len_mean
    "Fwd Packet Length Std",       # 18 fwd_pkt_len_std
    "Bwd Packet Length Max",       # 19 bwd_pkt_len_max
    "Bwd Packet Length Min",       # 20 bwd_pkt_len_min
    "Bwd Packet Length Mean",      # 21 bwd_pkt_len_mean
    "Bwd Packet Length Std",       # 22 bwd_pkt_len_std
    "Max Packet Length",           # 23 pkt_len_max
    "Min Packet Length",           # 24 pkt_len_min
    "Packet Length Mean",          # 25 pkt_len_mean
    "Packet Length Std",           # 26 pkt_len_std
    "Packet Length Variance",      # 27 pkt_len_var
    "Fwd Header Length",           # 28 fwd_header_len
    "Bwd Header Length",           # 29 bwd_header_len
    "min_seg_size_forward",        # 30 fwd_seg_size_min
    "act_data_pkt_fwd",            # 31 fwd_act_data_pkts
    "Flow IAT Mean",               # 32 flow_iat_mean
    "Flow IAT Max",                # 33 flow_iat_max
    "Flow IAT Min",                # 34 flow_iat_min
    "Flow IAT Std",                # 35 flow_iat_std
    "Fwd IAT Total",               # 36 fwd_iat_tot
    "Fwd IAT Max",                 # 37 fwd_iat_max
    "Fwd IAT Min",                 # 38 fwd_iat_min
    "Fwd IAT Mean",                # 39 fwd_iat_mean
    "Fwd IAT Std",                 # 40 fwd_iat_std
    "Bwd IAT Total",               # 41 bwd_iat_tot
    "Bwd IAT Max",                 # 42 bwd_iat_max
    "Bwd IAT Min",                 # 43 bwd_iat_min
    "Bwd IAT Mean",                # 44 bwd_iat_mean
    "Bwd IAT Std",                 # 45 bwd_iat_std
    "Fwd PSH Flags",               # 46 fwd_psh_flags
    "Bwd PSH Flags",               # 47 bwd_psh_flags
    "Fwd URG Flags",               # 48 fwd_urg_flags
    "Bwd URG Flags",               # 49 bwd_urg_flags
    "FIN Flag Count",              # 50 fin_flag_cnt
    "SYN Flag Count",              # 51 syn_flag_cnt
    "RST Flag Count",              # 52 rst_flag_cnt
    "PSH Flag Count",              # 53 psh_flag_cnt
    "ACK Flag Count",              # 54 ack_flag_cnt
    "URG Flag Count",              # 55 urg_flag_cnt
    "ECE Flag Count",              # 56 ece_flag_cnt
    "Down/Up Ratio",               # 57 down_up_ratio
    "Average Packet Size",         # 58 pkt_size_avg
    "Init_Win_bytes_forward",      # 59 init_fwd_win_byts
    "Init_Win_bytes_backward",     # 60 init_bwd_win_byts
    "Active Max",                  # 61 active_max
    "Active Min",                  # 62 active_min
    "Active Mean",                 # 63 active_mean
    "Active Std",                  # 64 active_std
    "Idle Max",                    # 65 idle_max
    "Idle Min",                    # 66 idle_min
    "Idle Mean",                   # 67 idle_mean
    "Idle Std",                    # 68 idle_std
    "Fwd Avg Bytes/Bulk",          # 69 fwd_byts_b_avg
    "Fwd Avg Packets/Bulk",        # 70 fwd_pkts_b_avg
    "Bwd Avg Bytes/Bulk",          # 71 bwd_byts_b_avg
    "Bwd Avg Packets/Bulk",        # 72 bwd_pkts_b_avg
    "Fwd Avg Bulk Rate",           # 73 fwd_blk_rate_avg
    "Bwd Avg Bulk Rate",           # 74 bwd_blk_rate_avg
    "Fwd Segment Size Avg",        # 75 fwd_seg_size_avg (alias of fwd_pkt_len_mean)
    "Bwd Segment Size Avg",        # 76 bwd_seg_size_avg (alias of bwd_pkt_len_mean)
    "CWE Flag Count",              # 77 cwe_flag_count (alias of fwd_urg_flags)
    "Subflow Fwd Packets",         # 78 subflow_fwd_pkts
    "Subflow Bwd Packets",         # 79 subflow_bwd_pkts
    "Subflow Fwd Bytes",           # 80 subflow_fwd_byts
    "Subflow Bwd Bytes",           # 81 subflow_bwd_byts
]


async def _forward_result(result: dict) -> None:
    try:
        async with httpx.AsyncClient(timeout=OUTPUT_TIMEOUT_SEC) as client:
            resp = await client.post(
                OUTPUT_URL,
                json=result,
                headers={"Content-Type": "application/json"},
            )
        print(f"[ai_engine] forwarded result → {resp.status_code}")
    except Exception as exc:
        print(f"[ai_engine] forward failed: {exc}")


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

    if len(values) == 82:
        flow_dict = dict(zip(CIC_82_COLUMNS, values))
    elif len(values) == len(feature_columns):
        flow_dict = dict(zip(feature_columns, values))
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Column mismatch: got {len(values)} values, expected 82 or {len(feature_columns)} "
                f"(based on feature_columns.pkl). Check that the CSV row matches the training schema."
            ),
        )

    # Sanity check: warn if model_feature_columns diverges from feature_columns after ID stripping
    expected_model_cols = set(model_feature_columns)
    # Use flow_dict keys if we got 82 columns
    incoming_cols = set(flow_dict.keys())
    missing = expected_model_cols - incoming_cols
    # Remove identifiers from missing check
    from process_flows import ID_ALIASES
    missing = {m for m in missing if _norm(m) not in ID_ALIASES}
    
    if missing:
        print(f"[ai_engine] WARNING: model expects columns not found in incoming flow: {missing}. Predictions may be wrong.")
    ids = _extract_identifiers(flow_dict)
    obs = _extract_observability_fields(flow_dict)

    X = prepare_features(
        raw_flow=flow_dict,
        model_feature_columns=model_feature_columns,
        feature_encoder=label_encoder,
    )

    # ── Debug: log feature values so we can verify real data flows through ──
    if os.getenv("DEBUG_FEATURES", "false").lower() == "true":
        debug_features(X)

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

    # ── Bug 4 guard: low-confidence Normal is suspect when the pipeline
    #    may have been feeding zero-vectors (model has strong zero=Normal prior).
    CONFIDENCE_THRESHOLD = float(os.getenv("NORMAL_CONFIDENCE_THRESHOLD", "0.85"))
    if ml_label == "Normal" and confidence < CONFIDENCE_THRESHOLD:
        ml_label = "Unknown / Low Confidence"
        print(
            f"[ai_engine] WARNING: Prediction was Normal but confidence {confidence:.3f} "
            f"< {CONFIDENCE_THRESHOLD:.2f} — overriding to 'Unknown / Low Confidence'."
        )

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
    await _forward_result(result)
    return result
