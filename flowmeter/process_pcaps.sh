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

  while IFS= read -r -d '' pcap_file; do
    filename=$(basename -- "$pcap_file")

    if grep -Fxq "$filename" "$PROCESSED_LOG"; then
      continue
    fi

    echo "[*] Processing: $filename"

    TMP_ETH="/tmp/${filename}.eth.pcap"
    TMP_PCAP="/tmp/${filename}.pcap"
    TMP_CSV="/tmp/${filename}.csv"

    # Step 1: Normalize pcapng -> pcap (tcpdump understands both)
    if ! tcpdump -r "$pcap_file" -w "$TMP_PCAP"; then
      echo "[!] tcpdump conversion failed for $filename, skipping."
      rm -f "$TMP_PCAP" "$TMP_ETH"
      continue
    fi

    # Step 2: Convert RAW IP -> Ethernet
    if ! python3 /app/convert_pcap.py "$TMP_PCAP" "$TMP_ETH"; then
      echo "[!] RAW->Ethernet conversion failed for $filename, skipping."
      rm -f "$TMP_PCAP" "$TMP_ETH"
      continue
    fi
    rm -f "$TMP_PCAP"

    # Step 3: Run cicflowmeter — in v0.1.6 the output arg is the CSV filename directly
    if ! cicflowmeter -f "$TMP_ETH" -c "$TMP_CSV"; then
      echo "[!] cicflowmeter failed for $filename"
      rm -f "$TMP_ETH" "$TMP_CSV"
      continue
    fi

    rm -f "$TMP_ETH"

    # Step 4: Append to shared CSV
    if [ -s "$TMP_CSV" ]; then
      if [ ! -f "$OUTPUT_CSV" ]; then
        cp "$TMP_CSV" "$OUTPUT_CSV"
      else
        tail -n +2 "$TMP_CSV" >> "$OUTPUT_CSV"
      fi
      rm -f "$TMP_CSV"
      echo "$filename" >> "$PROCESSED_LOG"
      echo "[+] Done: $filename"
    else
      echo "[!] No CSV output for $filename"
      rm -f "$TMP_CSV"
    fi
  done < <(find "$SYNC_DIR" -maxdepth 1 -type f -name "tailscale_*.pcap" -print0 | sort -z)

  sleep 10
done
