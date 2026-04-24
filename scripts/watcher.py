import asyncio
import websockets
import json
import csv
import os

# SecOps will tell us where the CSV is and where the API is
CSV_PATH = os.getenv("CSV_PATH", "/shared_data/live_flows.csv")
API_WS_URL = os.getenv("API_WS_URL", "ws://localhost:8000/ws/predict")


async def stream_traffic():
    # Wait for the file to be created if it's not there yet
    while not os.path.exists(CSV_PATH):
        await asyncio.sleep(2)

    async with websockets.connect(API_WS_URL) as ws:
        with open(CSV_PATH, 'r') as f:
            reader = csv.reader(f)
            headers = next(reader)  # Grab headers (Source IP, Flow Duration, etc.)

            # Jump to the end of the file
            f.seek(0, 2)

            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.1)  # Wait for new traffic
                    continue

                # Convert the CSV line to a dictionary
                values = line.strip().split(',')
                if len(values) == len(headers):
                    payload = dict(zip(headers, values))
                    await ws.send(json.dumps(payload))


if __name__ == "__main__":
    asyncio.run(stream_traffic())