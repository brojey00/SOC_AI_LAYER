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
