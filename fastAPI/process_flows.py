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
    return text.strip().lower().replace(" ", "_")


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

    # Supports a single sklearn encoder, commonly for Protocol-like columns.
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
    """
    Build exactly one-row DataFrame in model feature order.
    - Drops identifier fields (IPs/ports)
    - Encodes categorical fields when encoder is provided
    - Converts numeric values safely and replaces Inf/NaN with 0
    """
    norm_to_original = {_norm(k): k for k in raw_flow.keys()}
    prepared: Dict[str, Any] = {}

    for col in model_feature_columns:
        col_norm = _norm(col)

        # Enforce dropping identifiers from model input.
        if col_norm in ID_ALIASES:
            continue

        original_key = norm_to_original.get(col_norm)
        value = raw_flow.get(original_key) if original_key is not None else 0

        value = _encode_value(col, value, feature_encoder)

        # Try numeric first; keep string only if numeric conversion fails.
        numeric = _safe_float(value)
        if numeric == 0.0 and str(value).strip() not in {"0", "0.0"}:
            # Preserve a non-numeric category if encoder did not convert it.
            prepared[col] = str(value)
        else:
            prepared[col] = numeric

    frame = pd.DataFrame([prepared])

    # Final sanitation.
    frame = frame.replace([float("inf"), float("-inf")], 0).fillna(0)

    # Keep only numeric columns whenever possible for sklearn models.
    for col in frame.columns:
        frame[col] = pd.to_numeric(frame[col], errors="coerce")
    frame = frame.fillna(0)

    return frame
