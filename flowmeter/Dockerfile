FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    sshpass \
    rsync \
    openssh-client \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Patch cicflowmeter to cast scapy's EDecimal timestamps to floats before numpy aggregation
RUN sed -i 's/def get_statistics(alist: list):/def get_statistics(alist: list):\n    alist = [float(x) for x in alist]/g' /usr/local/lib/python3.9/site-packages/cicflowmeter/utils.py

WORKDIR /app
COPY process_pcaps.sh .
COPY convert_pcap.py .
RUN chmod +x process_pcaps.sh

CMD ["./process_pcaps.sh"]
