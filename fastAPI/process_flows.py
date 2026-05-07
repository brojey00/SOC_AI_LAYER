import math
from typing import Any, Dict, Iterable, Optional

import pandas as pd


ID_ALIASES = {
    "src_ip",
    "source_ip",
    "srcip",
    "dst_ip",
    "destination_ip",
    "dstip",
    "src_port",
    "source_port",
    "srcport",
    "dst_port",
    "destination_port",
    "dstport",
}


def _norm(text: str) -> str:
    """Normalise a column name for fuzzy matching.

    Strips leading/trailing whitespace, lower-cases, and replaces both
    spaces *and* forward-slashes with underscores so that names like
    "Flow Bytes/s" and "Bwd Packets/s" round-trip correctly through the
    lookup table built in prepare_features().
    """
    return text.strip().lower().replace(" ", "_").replace("/", "_")


def _safe_float(value: Any) -> float:
    try:
        v = float(value)
    except Exception:
        return 0.0
    if math.isnan(v) or math.isinf(v):
        return 0.0
    return v


def _encode_value(column: str, value: Any, feature_encoder: Any) -> Any:
    if feature_encoder is None:
        return value

    # Supports dict-style per-column encoders.
    if isinstance(feature_encoder, dict):
        enc = feature_encoder.get(column)
        if enc is None:
            return value
        try:
            return enc.transform([value])[0]
        except Exception:
            return value

    if column.lower() in {"protocol", "protocol_type"}:
        try:
            return feature_encoder.transform([value])[0]
        except Exception:
            return value

    return value


# COLUMN_ALIASES bridges the gap between:
#   - Model feature names  (CIC-IDS2017 / training CSV naming convention)
#   - cicflowmeter output  (abbreviated snake_case naming convention)
#
# Key   = _norm(model feature name)
# Value = actual cicflowmeter CSV column name
#
# Diagnostic result (2026-05-07): without these aliases only 3/36 features
# matched, causing 33 zero-valued inputs and constant 'Normal' predictions.
COLUMN_ALIASES: Dict[str, str] = {
    # ── Destination port ──────────────────────────────────────────────────
    _norm("Destination Port"):              "dst_port",
    # ── Total packets / payload lengths ──────────────────────────────────
    _norm("Total Fwd Packets"):             "tot_fwd_pkts",
    _norm("Total Length of Fwd Packets"):   "totlen_fwd_pkts",
    _norm("Total Length of Bwd Packets"):   "totlen_bwd_pkts",
    # ── Fwd packet length stats ───────────────────────────────────────────
    _norm("Fwd Packet Length Max"):         "fwd_pkt_len_max",
    _norm("Fwd Packet Length Min"):         "fwd_pkt_len_min",
    _norm("Fwd Packet Length Mean"):        "fwd_pkt_len_mean",
    _norm("Fwd Packet Length Std"):         "fwd_pkt_len_std",
    # ── Bwd packet length stats ───────────────────────────────────────────
    _norm("Bwd Packet Length Min"):         "bwd_pkt_len_min",
    _norm("Bwd Packet Length Mean"):        "bwd_pkt_len_mean",
    _norm("Bwd Packet Length Std"):         "bwd_pkt_len_std",
    # ── Flow rates ────────────────────────────────────────────────────────
    _norm("Flow Bytes/s"):                  "flow_byts_s",
    _norm("Bwd Packets/s"):                 "bwd_pkts_s",
    # ── Header lengths ────────────────────────────────────────────────────
    _norm("Fwd Header Length"):             "fwd_header_len",
    _norm("Bwd Header Length"):             "bwd_header_len",
    _norm("Fwd Header Length.1"):           "fwd_header_len",  # pandas duplicate → same col
    # ── Packet length stats ───────────────────────────────────────────────
    _norm("Min Packet Length"):             "pkt_len_min",
    _norm("Max Packet Length"):             "pkt_len_max",
    _norm("Packet Length Mean"):            "pkt_len_mean",
    _norm("Packet Length Std"):             "pkt_len_std",
    _norm("Packet Length Variance"):        "pkt_len_var",
    # ── TCP flags  (_count vs _cnt) ───────────────────────────────────────
    _norm("FIN Flag Count"):                "fin_flag_cnt",
    _norm("PSH Flag Count"):                "psh_flag_cnt",
    _norm("ACK Flag Count"):                "ack_flag_cnt",
    # ── Packet / segment sizes ────────────────────────────────────────────
    _norm("Average Packet Size"):           "pkt_size_avg",
    _norm("Avg Bwd Segment Size"):          "bwd_seg_size_avg",
    # ── Subflows  (_packets/_bytes vs _pkts/_byts) ────────────────────────
    _norm("Subflow Fwd Packets"):           "subflow_fwd_pkts",
    _norm("Subflow Fwd Bytes"):             "subflow_fwd_byts",
    _norm("Subflow Bwd Packets"):           "subflow_bwd_pkts",
    _norm("Subflow Bwd Bytes"):             "subflow_bwd_byts",
    # ── Init window bytes ─────────────────────────────────────────────────
    _norm("Init_Win_bytes_forward"):        "init_fwd_win_byts",
    _norm("Init_Win_bytes_backward"):       "init_bwd_win_byts",
    # ── Min segment size ──────────────────────────────────────────────────
    _norm("min_seg_size_forward"):          "fwd_seg_size_min",
}


def prepare_features(
    raw_flow: Dict[str, Any],
    model_feature_columns: Iterable[str],
    feature_encoder: Optional[Any] = None,
) -> pd.DataFrame:

    norm_to_original = {_norm(k): k for k in raw_flow.keys()}
    prepared: Dict[str, Any] = {}

    for col in model_feature_columns:
        col_norm = _norm(col)

        original_key = norm_to_original.get(col_norm)

        # Fallback: try alias (e.g. "Fwd Header Length.1" → "Fwd Header Length")
        if original_key is None and col_norm in COLUMN_ALIASES:
            alias = _norm(COLUMN_ALIASES[col_norm])
            original_key = norm_to_original.get(alias)

        value = raw_flow.get(original_key) if original_key is not None else 0

        value = _encode_value(col, value, feature_encoder)

        numeric = _safe_float(value)
        if numeric == 0.0 and str(value).strip() not in {"0", "0.0"}:
            
            prepared[col] = str(value)
        else:
            prepared[col] = numeric

    frame = pd.DataFrame([prepared])

    frame = frame.replace([float("inf"), float("-inf")], 0).fillna(0)

    for col in frame.columns:
        frame[col] = pd.to_numeric(frame[col], errors="coerce")
    frame = frame.fillna(0)

    return frame


def debug_features(frame: "pd.DataFrame") -> None:
    """Print a diagnostic row showing every feature value sent to the model.

    Call this after prepare_features() to verify that real values are
    flowing through the pipeline (not all-zeros).  Remove or gate behind
    an env-var flag in production.
    """
    record = frame.to_dict(orient="records")[0]
    zero_cols = [k for k, v in record.items() if v == 0]
    nonzero_cols = {k: v for k, v in record.items() if v != 0}
    print(f"[DEBUG] Feature values (non-zero): {nonzero_cols}")
    if zero_cols:
        print(f"[DEBUG] Zero-valued features ({len(zero_cols)}): {zero_cols}")
