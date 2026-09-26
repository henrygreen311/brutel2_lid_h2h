#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import argparse
import urllib.request
from google.cloud import bigquery
from google.oauth2 import service_account

# ------------------ CONFIG ------------------
GCP_KEY_URL = "https://flat-limit-0c50.qringgreen.workers.dev/"
GCP_KEY_FILE = "gcp-service-account.json"

# ETH threshold in wei (0.037 ETH)
ETH_THRESHOLD_WEI = 37_000_000_000_000_000

# Safety cap on estimated bytes scanned (900 GB < 1 TB free tier)
MAX_BYTES_BUDGET = 900 * 1024 ** 3

# Progress logging interval
PROGRESS_EVERY = 250_000

OUTPUT_FILE = "eth_addresses.txt"


# ------------------ HELPERS ------------------
def _is_valid_service_account_json(path):
    """Return True if the file is a valid GCP service account JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return (
            isinstance(data, dict)
            and data.get("type") == "service_account"
            and "client_email" in data
            and "private_key" in data
            and "project_id" in data
        )
    except Exception:
        return False


def download_service_account():
    """
    Download the service account JSON from Cloudflare Workers.
    Validates it's real JSON before saving.
    """
    if os.path.exists(GCP_KEY_FILE) and _is_valid_service_account_json(GCP_KEY_FILE):
        print(f"Using existing valid {GCP_KEY_FILE}")
        return

    print(f"Downloading service account JSON from {GCP_KEY_URL} ...")

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    }

    req = urllib.request.Request(GCP_KEY_URL, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content_type = resp.headers.get("Content-Type", "")
            data = resp.read()
    except Exception as e:
        print(f"ERROR: Failed to download service account JSON: {e}")
        _print_download_help()
        sys.exit(1)

    print(f"  Content-Type   : {content_type}")
    print(f"  Content-Length : {len(data):,} bytes")

    if "html" in content_type.lower():
        print("\nERROR: Server returned HTML instead of JSON.")
        print("First 300 bytes of response:")
        print(data[:300].decode("utf-8", errors="replace"))
        _print_download_help()
        sys.exit(1)

    try:
        parsed = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as e:
        print(f"\nERROR: Downloaded content is not valid JSON: {e}")
        print("First 300 bytes of response:")
        print(data[:300].decode("utf-8", errors="replace"))
        _print_download_help()
        sys.exit(1)

    required = ["type", "client_email", "private_key", "project_id"]
    missing = [k for k in required if k not in parsed]
    if missing:
        print(f"\nERROR: JSON is missing required fields: {missing}")
        _print_download_help()
        sys.exit(1)

    if parsed.get("type") != "service_account":
        print(f"\nERROR: JSON type is '{parsed.get('type')}', expected 'service_account'")
        sys.exit(1)

    with open(GCP_KEY_FILE, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2)

    print(f"  ✅ Saved valid service account JSON to {GCP_KEY_FILE}")
    print(f"     client_email: {parsed['client_email']}")
    print(f"     project_id  : {parsed['project_id']}")


def _print_download_help():
    print()
    print("=" * 65)
    print("DOWNLOAD FAILED — WHAT TO DO")
    print("=" * 65)
    print()
    print("If the Cloudflare Worker URL is unreachable, check:")
    print("  1. The worker is deployed and the URL is correct.")
    print("  2. The worker returns 'application/json' as Content-Type.")
    print("  3. The worker is not behind any auth / rate-limit.")
    print()
    print("Alternative: store the JSON as a GitHub Secret:")
    print("  - Settings → Secrets and variables → Actions")
    print("  - New secret: GCP_SERVICE_ACCOUNT_JSON")
    print("  - Paste the full JSON as the value.")
    print("  - Then the workflow writes it to a file before running main.py.")
    print()
    print("=" * 65)


def get_client():
    creds = service_account.Credentials.from_service_account_file(
        GCP_KEY_FILE,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    return bigquery.Client(credentials=creds, project=creds.project_id)


def build_query():
    return """
        SELECT address
        FROM `bigquery-public-data.crypto_ethereum.balances`
        WHERE eth_balance >= @threshold
    """


def estimate_cost(client, sql, params):
    print("\nEstimating query cost (dry run)...")
    job_config = bigquery.QueryJobConfig(
        query_parameters=params,
        dry_run=True,
        use_query_cache=False,
    )
    job = client.query(sql, job_config=job_config)
    bytes_processed = job.total_bytes_processed or 0
    gb = bytes_processed / (1024 ** 3)
    tb = gb / 1024
    print(f"Estimated scan: {gb:,.2f} GB ({tb:.3f} TB)")
    return bytes_processed


def run_query_and_save(client, sql, params):
    print("\nRunning query...")
    start = time.time()

    job_config = bigquery.QueryJobConfig(query_parameters=params)
    job = client.query(sql, job_config=job_config)
    result = job.result()

    row_count = 0
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for row in result:
            f.write(f"{row.address}\n")
            row_count += 1
            if row_count % PROGRESS_EVERY == 0:
                elapsed = time.time() - start
                rate = row_count / elapsed if elapsed > 0 else 0
                print(f"  ...{row_count:>12,} rows  ({rate:,.0f} rows/s, {elapsed:.0f}s)")

    elapsed = time.time() - start
    print(f"Query finished in {elapsed:.1f}s. Wrote {row_count:,} addresses.")
    return row_count


def file_size_mb(path):
    try:
        return os.path.getsize(path) / (1024 * 1024)
    except OSError:
        return 0.0


# ------------------ MAIN ------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true",
                        help="Allow running even if estimated scan exceeds the safety budget.")
    parser.add_argument("--skip-download", action="store_true",
                        help="Skip downloading the service account JSON (use local file).")
    args = parser.parse_args()

    print("=" * 60)
    print("ETH ADDRESS EXPORTER")
    print("=" * 60)
    print(f"Threshold     : {ETH_THRESHOLD_WEI:,} wei (0.037 ETH)")
    print(f"Safety budget : {MAX_BYTES_BUDGET / 1024**3:.0f} GB (BigQuery free tier = 1 TB)")
    print("=" * 60)

    if not args.skip_download:
        download_service_account()

    if not os.path.exists(GCP_KEY_FILE):
        print(f"ERROR: {GCP_KEY_FILE} missing.")
        sys.exit(1)

    if not _is_valid_service_account_json(GCP_KEY_FILE):
        print(f"ERROR: {GCP_KEY_FILE} is not a valid service account JSON.")
        sys.exit(1)

    client = get_client()

    params = [
        bigquery.ScalarQueryParameter("threshold", "NUMERIC", ETH_THRESHOLD_WEI),
    ]

    sql = build_query()

    estimated = estimate_cost(client, sql, params)
    if estimated > MAX_BYTES_BUDGET and not args.force:
        print(f"\nABORTING: Estimated scan {estimated / 1024**3:.2f} GB exceeds "
              f"safety budget {MAX_BYTES_BUDGET / 1024**3:.0f} GB.")
        print("Pass --force to override.")
        sys.exit(2)

    row_count = run_query_and_save(client, sql, params)
    size_mb = file_size_mb(OUTPUT_FILE)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Addresses written : {row_count:>12,}")
    print(f"  Output file       : {OUTPUT_FILE}")
    print(f"  File size         : {size_mb:,.2f} MB")
    print(f"  Est. bytes scanned: {estimated / 1024**3:,.2f} GB")
    print("=" * 60)


if __name__ == "__main__":
    main()