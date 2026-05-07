import csv
import os
import random
import time
from typing import Optional

import requests

CSV_PATH = os.getenv("CSV_PATH", "/shared_data/live_flows.csv")
AI_URL = os.getenv("AI_URL", "http://ai_engine:8000/predict")

POLL_INTERVAL_SEC = float(os.getenv("POLL_INTERVAL_SEC", "0.2"))
REQUEST_TIMEOUT_SEC = float(os.getenv("REQUEST_TIMEOUT_SEC", "10"))

BACKOFF_INITIAL_SEC = float(os.getenv("BACKOFF_INITIAL_SEC", "1"))
BACKOFF_MAX_SEC = float(os.getenv("BACKOFF_MAX_SEC", "60"))
BACKOFF_JITTER_SEC = float(os.getenv("BACKOFF_JITTER_SEC", "0.25"))


def wait_for_file(path: str) -> None:
    while not os.path.exists(path):
        print(f"[watcher] waiting for file: {path}")
        time.sleep(1.0)
    print(f"[watcher] monitoring: {path}")


def post_with_exponential_backoff(session: requests.Session, raw_csv_row: str) -> None:
    attempt = 0
    while True:
        try:
            response = session.post(
                AI_URL,
                data=raw_csv_row.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
                timeout=REQUEST_TIMEOUT_SEC,
            )
            if 200 <= response.status_code < 300:
                return

            print(
                f"[watcher] AI returned {response.status_code}: {response.text[:300]}"
            )
        except requests.RequestException as exc:
            print(f"[watcher] AI unreachable: {exc}")

        delay = min(BACKOFF_INITIAL_SEC * (2 ** attempt), BACKOFF_MAX_SEC)
        delay += random.uniform(0, BACKOFF_JITTER_SEC)
        attempt += 1
        print(f"[watcher] retrying in {delay:.2f}s")
        time.sleep(delay)


def _is_complete_line(line: str) -> bool:
    # Protects against reading a partially-written row.
    return bool(line) and line.endswith("\n")


def _validate_row_shape(header_count: int, raw_line: str) -> bool:
    try:
        parsed = next(csv.reader([raw_line.rstrip("\n")]))
    except Exception:
        return False
    return len(parsed) == header_count


def tail_and_forward() -> None:
    wait_for_file(CSV_PATH)

    with open(CSV_PATH, "r", encoding="utf-8", newline="") as f, requests.Session() as session:
        header_line = f.readline()
        if not header_line:
            raise RuntimeError("CSV header not found.")

        headers = next(csv.reader([header_line.rstrip("\n")]))
        header_count = len(headers)
        print(f"[watcher] header columns: {header_count}")

        # Tail mode: only new rows after startup.
        # f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not _is_complete_line(line):
                time.sleep(POLL_INTERVAL_SEC)
                continue

            raw_row = line.rstrip("\n")
            if not _validate_row_shape(header_count, line):
                print("[watcher] skipping malformed row (column mismatch)")
                continue

            post_with_exponential_backoff(session, raw_row)


if __name__ == "__main__":
    while True:
        try:
            tail_and_forward()
        except Exception as exc:
            print(f"[watcher] fatal loop error: {exc}; restarting in 2s")
            time.sleep(2)
