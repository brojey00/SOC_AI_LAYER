

## Step 1 — Read the code first, touch nothing

Open `fastAPI/main.py` and find the section where incoming CSV rows are parsed into a flow dict. Look for:
- A hardcoded list called `CIC_82_COLUMNS` or similar
- A `zip()` call that maps row values to column names by position
- Where `prepare_features()` from `process_flows.py` is called

Also open `fastAPI/process_flows.py` and note:
- The `_norm()` function that normalizes column names
- The `COLUMN_ALIASES` dict
- How `prepare_features()` builds the feature dict by iterating over `model_feature_columns`

**Goal:** Understand exactly how a raw CSV row becomes a feature vector for the model before touching anything.

---

## Step 2 — Validate the feature mapping

### 2a. Check what features the model expects

```bash
docker exec ai_engine python3 -c "
import pickle
cols = pickle.load(open('/app/models/feature_columns.pkl', 'rb'))
print(f'Total features: {len(cols)}')
for i, c in enumerate(cols):
    print(f'{i}: {c}')
"
```

### 2b. Check what cicflowmeter outputs as column names

```bash
docker exec pcap_processor head -1 /shared_data/live_flows.csv
```

### 2c. Check if _norm() bridges the naming gap

Run this to verify whether the normalization function can match model feature names to CSV header names:

```bash
docker exec ai_engine python3 -c "
def _norm(text):
    return text.strip().lower().replace(' ', '_').replace('/', '_')

model_feat = 'ACK Flag Count'
csv_header = 'ack_flag_cnt'
print(f'model normed: {_norm(model_feat)}')
print(f'csv normed:   {_norm(csv_header)}')
print(f'match: {_norm(model_feat) == _norm(csv_header)}')
"
```

> **Key issue:** `ack_flag_count` vs `ack_flag_cnt` will NOT match even after `_norm()`. The trailing `_cnt` vs `_count` difference is the likely culprit.

### 2d. Run a full match check across all 36 model features

```bash
docker exec ai_engine python3 - <<'EOF'
import pickle

def _norm(text):
    return text.strip().lower().replace(' ', '_').replace('/', '_')

cols = pickle.load(open('/app/models/feature_columns.pkl', 'rb'))

# Paste the full header line from step 2b here
csv_header_line = "src_ip,dst_ip,src_port,..."  # REPLACE THIS
csv_header = csv_header_line.strip().split(',')
csv_normed = {_norm(c): c for c in csv_header}

print(f"{'Model Feature':<35} {'Normed':<35} {'CSV Match'}")
print("-" * 90)
for feat in cols:
    n = _norm(feat)
    match = csv_normed.get(n, '>>> NO MATCH <<<')
    print(f"{feat:<35} {n:<35} {match}")
EOF
```

**Pay attention to:** Any row showing `NO MATCH` — those features will be **zero** in every prediction, which pushes the model toward Normal.

---

## Step 3 — Check the positional mapping in main.py

Find where `main.py` does something like:

```python
flow_dict = dict(zip(CIC_82_COLUMNS, row_values))
```

This only works correctly if:
- The CSV always has exactly 82 columns
- The column **order** from cicflowmeter exactly matches `CIC_82_COLUMNS`

### 3a. Verify column count matches

```bash
docker exec pcap_processor head -1 /shared_data/live_flows.csv | tr ',' '\n' | wc -l
docker exec pcap_processor tail -1 /shared_data/live_flows.csv | tr ',' '\n' | wc -l
```

Both must return the same number. If they differ, rows are malformed.

### 3b. The fix if positional mapping is broken

Replace positional mapping with header-based mapping. Read the header row from `live_flows.csv` once at startup and cache it:

```python
# BEFORE (fragile - positional):
flow_dict = dict(zip(CIC_82_COLUMNS, row_values))

# AFTER (robust - header-based):
flow_dict = dict(zip(cached_csv_headers, row_values))
```

`prepare_features()` already handles name normalization via `_norm()` — so once the keys in `flow_dict` are the actual CSV header names, everything downstream works correctly.

> **Note:** `ai_engine` needs access to `live_flows.csv` to read the header. If it is not already mounted, add the `shared_data` volume to `ai_engine` in `docker-compose.yml`:
> ```yaml
> volumes:
>   - ./shared_data:/shared_data:ro
> ```

---

## Step 4 — End-to-end prediction test

### 4a. Find a row with non-zero TCP flags

```bash
docker exec pcap_processor awk -F',' 'NR==1{for(i=1;i<=NF;i++) if($i=="ack_flag_cnt") col=i} NR>1 && $col+0 > 0 {print; exit}' /shared_data/live_flows.csv
```

### 4b. Feed it through prepare_features and inspect what reaches the model

```python
import pickle

def _norm(text):
    return text.strip().lower().replace(' ', '_').replace('/', '_')

cols = pickle.load(open('/app/models/feature_columns.pkl', 'rb'))

# Paste the full CSV header line here
csv_headers = "src_ip,dst_ip,...".strip().split(',')

# Paste the data row from 4a here
raw_row = "100.123.225.126,100.121.79.73,22,...".strip().split(',')

flow_dict = dict(zip(csv_headers, raw_row))

print("=== Key TCP flag values in flow_dict ===")
for k in ['ack_flag_cnt', 'psh_flag_cnt', 'fin_flag_cnt', 'syn_flag_cnt']:
    print(f"  {k}: {flow_dict.get(k, 'MISSING')}")
```

**What to look for:**
- Are `ack_flag_cnt`, `psh_flag_cnt` showing their real values from the CSV row?
- After `prepare_features()` runs, are `ACK Flag Count`, `PSH Flag Count` non-zero in the feature frame?
- If most features in the frame are zero — the mapping is broken

---

## Step 5 — Inspect model internals

```bash
docker exec ai_engine python3 - <<'EOF'
import pickle

model = pickle.load(open('/app/models/soc_model.pkl', 'rb'))
cols = pickle.load(open('/app/models/feature_columns.pkl', 'rb'))

print("Model type:", type(model))
print("Classes:", model.classes_ if hasattr(model, 'classes_') else "No classes_ attr")

if hasattr(model, 'feature_names_in_'):
    print("Training feature order:", list(model.feature_names_in_))
else:
    print("WARNING: No feature_names_in_ — column ORDER is critical")
    print("feature_columns.pkl order:")
    for i, c in enumerate(cols):
        print(f"  {i}: {c}")
EOF
```

**Pay attention to:**
- If `feature_names_in_` is `None`, the model is **order-sensitive**. The order in `feature_columns.pkl` must exactly match the order used during training. This is a critical risk.
- Check `model.classes_` to confirm what attack labels the model knows (e.g. `DDoS`, `PortScan`, `Web Attack`, `Normal`)

---

## Step 6 — Check raw model prediction probabilities on a real row

After fixing the mapping, run a prediction and check all class probabilities (not just the top label):

```bash
docker exec ai_engine python3 - <<'EOF'
import pickle
import numpy as np
import pandas as pd

model = pickle.load(open('/app/models/soc_model.pkl', 'rb'))
cols = pickle.load(open('/app/models/feature_columns.pkl', 'rb'))

# Import prepare_features from the actual app code
import sys
sys.path.insert(0, '/app')
from process_flows import prepare_features

# Build a flow_dict from a real CSV row (paste header and row from earlier steps)
csv_headers = "src_ip,dst_ip,...".strip().split(',')
raw_row = "100.123.225.126,...".strip().split(',')
flow_dict = dict(zip(csv_headers, raw_row))

frame = prepare_features(flow_dict, cols)
print("Features going to model:")
print(frame.to_dict(orient='records')[0])

probs = model.predict_proba(frame)[0]
classes = model.classes_
print("\nPrediction probabilities:")
for cls, prob in sorted(zip(classes, probs), key=lambda x: -x[1]):
    print(f"  {cls}: {prob:.6f}")
EOF
```

**Expected result if working:** Probabilities spread across classes, not 99.9% Normal.

---

## Summary — What to fix based on findings

| Finding | Fix |
|---|---|
| `_norm()` doesn't match CSV header to model feature (e.g. `_cnt` vs `_count`) | Add explicit alias mapping in `process_flows.py` for the mismatched names |
| Positional mapping in `main.py` using wrong column order | Replace with header-based mapping using cached CSV header from `live_flows.csv` |
| Most features are zero in the feature frame sent to model | Both fixes above are needed |
| Model has no `feature_names_in_` and training order is uncertain | Verify `feature_columns.pkl` order against the training script or notebook |
| Prediction still Normal after all fixes | Use a known CIC-IDS2017 attack CSV row and compare feature values against known attack signatures |

---

## Definition of "working correctly"

The system is confirmed working when:

1. A CSV row with non-zero `ack_flag_cnt` / `psh_flag_cnt` produces non-zero `ACK Flag Count` / `PSH Flag Count` in the feature frame sent to the model
2. The model returns **varying** probability scores across classes — not always 99.9% Normal
3. Known attack-like traffic (high packet rate, many connections, port scanning pattern) gets labeled as an attack class with high confidence
4. The `ai_engine` logs show `ml_label` values other than `Normal` appearing for suspicious flows