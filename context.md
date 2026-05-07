## 1. Capture (CICFlowMeter)

The sensor listens directly to the server’s network interface  
(specifically `tailscale0`) to capture traffic in the form of packets (PCAP) in real time.  

It then transforms this raw data into mathematical statistics and writes the result,  
line by line, into a CSV file.

---

## 2. Relay (The Watcher)

A script monitors this CSV file. As soon as a new line appears,  
it instantly captures it and sends it to the AI via a simple HTTP POST request.

---

## 3. Prediction (FastAPI + XGBoost)

- The API discards IP addresses and ports (since the AI does not need them for computation).
- It feeds the remaining statistical features into the XGBoost model,  
  which predicts the nature of the traffic (Normal, Port Scan, Web Attack, etc.).

---

## 4. Verification (Wazuh Indexer)

If the AI classifies the traffic as a **"Web Attack"**,  
the API immediately queries the Wazuh log database.

It searches for actions related to the suspicious IP address and uses a rule (Regex)  
to identify the exact type of attack (e.g., SQL Injection, XSS).

---

## 5. Final Alert

The API aggregates all the information (source IP, destination IP,  
ML attack type, Wazuh subtype, etc.) and outputs a clean JSON report  
for the security team.