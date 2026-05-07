FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    sshpass \
    rsync \
    openssh-client \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Patch 1: Fix cicflowmeter EDecimal timestamps
RUN sed -i 's/def get_statistics(alist: list):/def get_statistics(alist: list):\n    alist = [float(x) for x in alist]/g' \
    /usr/local/lib/python3.9/site-packages/cicflowmeter/utils.py

# Patch 2: Fix flag_count.py to read TCP flags (packet[TCP].flags)
#           instead of IP flags (packet.flags) — fixes ACK/PSH/FIN always = 0
RUN python3 - <<'PYEOF'
content = """from scapy.layers.inet import TCP

class FlagCount:
    def __init__(self, feature):
        self.feature = feature
        self.flags = {
            "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
            "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
        }

    def has_flag(self, flag, packet_direction=None) -> bool:
        packets = (
            (packet for packet, direction in self.feature.packets
             if direction == packet_direction)
            if packet_direction is not None
            else (packet for packet, _ in self.feature.packets)
        )
        for packet in packets:
            if TCP in packet and flag[0] in str(packet[TCP].flags):
                return 1
        return 0
"""
with open('/usr/local/lib/python3.9/site-packages/cicflowmeter/features/flag_count.py', 'w') as f:
    f.write(content)
print("flag_count.py patched OK")
PYEOF

WORKDIR /app
COPY process_pcaps.sh .
COPY convert_pcap.py .
RUN chmod +x process_pcaps.sh

CMD ["./process_pcaps.sh"]