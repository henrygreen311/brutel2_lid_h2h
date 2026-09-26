#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse
import urllib.request
from google.cloud import bigquery
from google.oauth2 import service_account

# ------------------ CONFIG ------------------
GCP_KEY_URL = "https://tradex.fwh.is/gcp/gcp-service-account.json"
GCP_KEY_FILE = "gcp-service-account.json"

# ETH threshold in wei (0.037 ETH)
ETH_THRESHOLD_WEI = 37_000_000_000_000_000

# Safety cap on estimated bytes scanned (900 GB < 1 TB free tier)
MAX_BYTES_BUDGET = 900 * 1024 ** 3

# Progress logging interval
PROGRESS_EVERY = 250_000

OUTPUT_FILE = "eth_addresses.txt"


# ------------------ HELPERS ------------------
def download_service_account():
    """Download the service account JSON from the remote URL."""
    print(f"Downloading service account JSON from {GCP_KEY_URL} ...")
    try:
        req = urllib.request.Request(GCP_KEY_URL, headers={"User-Agent": "eth-exporter/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        with open(GCP_KEY_FILE, "wb") as f:
            f.write(data)
        print(f"Saved {len(data):,} bytes to {GCP_KEY_FILE}")
    except Exception as e:
        print(f"ERROR: Failed to download service account JSON: {e}")
        sys.exit(1)


def get_client():
    creds = service_account.Credentials.from_service_account_file(
        GCP_KEY_FILE,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    return bigquery.Client(credentials=creds, project=creds.project_id)


def build_query():
    """
    ETH query: full snapshot of all addresses with balance >= threshold.
    The crypto_ethereum.balances table is a single snapshot table (not history),
    so the scan is small (~10-15 GB) — well within the free tier.
    """
    return """
        SELECT address
        FROM `bigquery-public-data.crypto_ethereum.balances`
        WHERE eth_balance >= @threshold
    """


def estimate_cost(client, sql, params):
    """Dry run to estimate bytes processed."""
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
    """Execute the query and stream addresses to OUTPUT_FILE."""
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

    client = get_client()

    params = [
        bigquery.ScalarQueryParameter("threshold", "NUMERIC", ETH_THRESHOLD_WEI),
    ]

    sql = build_query()

    # -------- Cost check --------
    estimated = estimate_cost(client, sql, params)
    if estimated > MAX_BYTES_BUDGET and not args.force:
        print(f"\nABORTING: Estimated scan {estimated / 1024**3:.2f} GB exceeds "
              f"safety budget {MAX_BYTES_BUDGET / 1024**3:.0f} GB.")
        print("Pass --force to override (may exceed free tier).")
        sys.exit(2)

    # -------- Real run --------
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