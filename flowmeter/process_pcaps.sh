#!/bin/bash

REMOTE_IP=${REMOTE_IP:-100.123.225.126}
REMOTE_PATH=${REMOTE_PATH:-/opt/pcap/}
SSH_USER=${SSH_USER:-root}
SSH_PASSWORD=${SSH_PASSWORD:-password}
SYNC_DIR="/shared_data/raw_pcaps"
OUTPUT_CSV="/shared_data/live_flows.csv"
PROCESSED_LOG="/shared_data/processed_pcaps.log"

mkdir -p "$SYNC_DIR"
touch "$PROCESSED_LOG"

echo "Starting PCAP Sync -> Flowmeter pipeline loop..."

while true; do

  echo "Syncing from $REMOTE_IP..."
  sshpass -p "$SSH_PASSWORD" rsync -avz \
    -e "ssh -o StrictHostKeyChecking=no" \
    "$SSH_USER@$REMOTE_IP:$REMOTE_PATH" "$SYNC_DIR/" \
    --include="tailscale_*.pcap" --exclude="*"

  for pcap_file in "$SYNC_DIR"/*.pcap; do
    [ -e "$pcap_file" ] || continue
    filename=$(basename -- "$pcap_file")

    if grep -Fxq "$filename" "$PROCESSED_LOG"; then
      continue
    fi

    echo "[*] Processing new PCAP: $filename"

    # Use a temp dir per file to avoid any naming collisions
    TMP_DIR=$(mktemp -d)
    TMP_PCAP_ETH="$TMP_DIR/input.pcap"
    # cicflowmeter -c writes to exactly the path you give — no .csv appended in newer versions
    # but to be safe we name the output dir and let cicflowmeter write its own filename
    TMP_CSV_OUT="$TMP_DIR/flows.csv"

    # Step 1: Convert RAW IP -> Ethernet directly (no tcpdump intermediary needed)
    python3 /app/convert_pcap.py "$pcap_file" "$TMP_PCAP_ETH"
    if [ $? -ne 0 ]; then
      echo "[!] Conversion failed for $filename, skipping."
      rm -rf "$TMP_DIR"
      continue
    fi

    # Step 2: Run cicflowmeter
    cicflowmeter -f "$TMP_PCAP_ETH" -c "$TMP_CSV_OUT"

    # Step 3: Find whatever CSV cicflowmeter actually wrote
    ACTUAL_CSV=$(find "$TMP_DIR" -name "*.csv" | head -1)

    if [ -z "$ACTUAL_CSV" ]; then
      echo "[!] cicflowmeter produced no CSV for $filename — skipping."
      rm -rf "$TMP_DIR"
      continue
    fi

    # Step 4: Append to shared output CSV (skip header if file already exists)
    if [ ! -f "$OUTPUT_CSV" ]; then
      cp "$ACTUAL_CSV" "$OUTPUT_CSV"
    else
      tail -n +2 "$ACTUAL_CSV" >> "$OUTPUT_CSV"
    fi

    rm -rf "$TMP_DIR"
    echo "$filename" >> "$PROCESSED_LOG"
    echo "[+] Done: $filename"
  done

  sleep 10
done