#!/bin/bash

# Configuration
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
  sshpass -p "$SSH_PASSWORD" rsync -avz -e "ssh -o StrictHostKeyChecking=no" "$SSH_USER@$REMOTE_IP:$REMOTE_PATH" "$SYNC_DIR/" --include="tailscale_*.pcap" --exclude="*"
  
  for pcap_file in "$SYNC_DIR"/*.pcap; do
    [ -e "$pcap_file" ] || continue
    filename=$(basename -- "$pcap_file")
    
    if grep -Fxq "$filename" "$PROCESSED_LOG"; then
      continue 
    fi
    
    echo "[*] Processing new PCAP: $filename"
    TMP_CSV="/tmp/${filename}.csv"
    TMP_PCAP_LEGACY="/tmp/${filename}.legacy.pcap"
    TMP_PCAP_ETH="/tmp/${filename}.eth.pcap"

    
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
    fi
  done
  
  sleep 10
done
