#!/bin/bash

# Configuration
REMOTE_IP=${REMOTE_IP:-100.123.225.126}
REMOTE_PATH=${REMOTE_PATH:-/opt/pcap/}
SSH_USER=${SSH_USER:-root}
SSH_PASSWORD=${SSH_PASSWORD:-password}
SYNC_DIR="/shared_data/raw_pcaps"
PROCESSED_DIR="/shared_data/processed_pcaps"
OUTPUT_CSV="/shared_data/live_flows.csv"
PROCESSED_LOG="/shared_data/processed_pcaps.log"
SYNC_INTERVAL=${SYNC_INTERVAL:-10}

mkdir -p "$SYNC_DIR"
mkdir -p "$PROCESSED_DIR"
touch "$PROCESSED_LOG"

echo "Starting PCAP Sync -> Flowmeter pipeline loop (Interval: ${SYNC_INTERVAL}s)..."

while true; do
  # 1. Sync new pcaps
  echo "[*] Syncing from $REMOTE_IP..."
  sshpass -p "$SSH_PASSWORD" rsync -avz --timeout=30 -e "ssh -o StrictHostKeyChecking=no" "$SSH_USER@$REMOTE_IP:$REMOTE_PATH" "$SYNC_DIR/"
  
  # 2. Process
  for pcap_file in "$SYNC_DIR"/*; do
    [ -e "$pcap_file" ] || continue
    filename=$(basename -- "$pcap_file")
    
    if grep -Fxq "$filename" "$PROCESSED_LOG"; then
      echo "[!] $filename already processed but still in sync dir. Moving it."
      mv "$pcap_file" "$PROCESSED_DIR/"
      continue
    fi
    
    echo "[*] Processing new PCAP: $filename"
    TMP_CSV="/tmp/${filename}.csv"
    TMP_PCAP_LEGACY="/tmp/${filename}.legacy.pcap"
    TMP_PCAP_ETH="/tmp/${filename}.eth.pcap"

    # 1. Convert PCAPNG -> legacy PCAP (maintains RAW IP link type)
    tcpdump -r "$pcap_file" -w "$TMP_PCAP_LEGACY" 2>/dev/null
    
    # 2. Convert RAW IP -> Ethernet legacy PCAP
    python3 /app/convert_pcap.py "$TMP_PCAP_LEGACY" "$TMP_PCAP_ETH"
    if [ $? -ne 0 ]; then
      echo "[!] Conversion failed for $filename, skipping."
      rm -f "$TMP_PCAP_LEGACY" "$TMP_PCAP_ETH"
      continue
    fi

    # 3. Process with cicflowmeter
    cicflowmeter -f "$TMP_PCAP_ETH" -c "$TMP_CSV"
    
    rm -f "$TMP_PCAP_LEGACY" "$TMP_PCAP_ETH"
    
    if [ -f "$TMP_CSV" ]; then
      if [ ! -f "$OUTPUT_CSV" ]; then
         cp "$TMP_CSV" "$OUTPUT_CSV"
      else
         tail -n +2 "$TMP_CSV" >> "$OUTPUT_CSV"
      fi
      rm "$TMP_CSV"
      echo "$filename" >> "$PROCESSED_LOG"
      echo "[+] Successfully processed and appended: $filename"
      
      # Move to processed directory to keep sync dir clean
      mv "$pcap_file" "$PROCESSED_DIR/"
    fi
  done
  
  echo "[*] Sleeping for ${SYNC_INTERVAL}s..."
  sleep "$SYNC_INTERVAL"
done

