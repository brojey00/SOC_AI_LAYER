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

  for pcap_file in "$SYNC_DIR"/tailscale_*.pcap; do
    [ -e "$pcap_file" ] || continue
    filename=$(basename -- "$pcap_file")

    if grep -Fxq "$filename" "$PROCESSED_LOG"; then
      continue
    fi

    echo "[*] Processing: $filename"

    TMP_ETH="/tmp/${filename}.eth.pcap"
    TMP_PCAP="/tmp/${filename}.pcap"
    TMP_CSV="/tmp/${filename}.csv"

    # Step 1: Convert RAW IP -> Ethernet
    python3 /app/convert_pcap.py "$pcap_file" "$TMP_ETH"
    if [ $? -ne 0 ]; then
      echo "[!] Conversion failed for $filename, attempting pcapng -> pcap."
      tcpdump -r "$pcap_file" -w "$TMP_PCAP"
      if [ $? -ne 0 ]; then
        echo "[!] pcapng -> pcap conversion failed for $filename, skipping."
        rm -f "$TMP_PCAP" "$TMP_ETH"
        continue
      fi

      echo "[+] pcapng -> pcap conversion complete for $filename"

      python3 /app/convert_pcap.py "$TMP_PCAP" "$TMP_ETH"
      conv_status=$?
      rm -f "$TMP_PCAP"
      if [ $conv_status -ne 0 ]; then
        echo "[!] Conversion failed after pcapng -> pcap for $filename, skipping."
        rm -f "$TMP_ETH"
        continue
      fi
    fi

    # Step 2: Run cicflowmeter — in v0.1.6 the output arg is the CSV filename directly
    cicflowmeter -f "$TMP_ETH" -c "$TMP_CSV"

    rm -f "$TMP_ETH"

    # Step 3: Append to shared CSV
    if [ -f "$TMP_CSV" ]; then
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
    fi
  done

  sleep 10
done
