#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
from google.cloud import bigquery
from google.oauth2 import service_account

# ------------------ CONFIG ------------------
GCP_KEY_FILE = "gcp-service-account.json"

# Minimum holdings per chain (raw units)
THRESHOLDS = {
    "btc":  {"display": 0.0012, "raw": 120_000},                  # satoshi
    "eth":  {"display": 0.037,  "raw": 37_000_000_000_000_000},   # wei
    "tron": {"display": 34,     "raw": 34_000_000},               # sun
    "sol":  {"display": 0.82,   "raw": 820_000_000},              # lamports
}

# Hard cap so a runaway query doesn't fill your disk
MAX_ROWS_PER_CHAIN = 30_000_000

# Progress interval
PROGRESS_EVERY = 250_000


# ------------------ HELPERS ------------------
def get_client():
    creds = service_account.Credentials.from_service_account_file(
        GCP_KEY_FILE,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    return bigquery.Client(credentials=creds, project=creds.project_id)


def run_and_save(client, chain, sql, params):
    """Run a BigQuery query and stream ONLY addresses to <chain>_addresses.txt."""
    print(f"\n[{chain.upper()}] Running query (threshold {THRESHOLDS[chain]['display']})...")
    start = time.time()

    job_config = bigquery.QueryJobConfig(query_parameters=params)
    query_job = client.query(sql, job_config=job_config)

    # Wait for the query to actually finish executing before we read rows
    result = query_job.result()

    out_path = f"{chain}_addresses.txt"
    row_count = 0

    with open(out_path, "w", encoding="utf-8") as f:
        for row in result:
            f.write(f"{row.address}\n")
            row_count += 1
            if row_count % PROGRESS_EVERY == 0:
                elapsed = time.time() - start
                rate = row_count / elapsed if elapsed > 0 else 0
                print(f"  ...{row_count:>12,} rows  ({rate:,.0f} rows/s, {elapsed:.0f}s elapsed)")
            if row_count >= MAX_ROWS_PER_CHAIN:
                print(f"[{chain.upper()}] Hit MAX_ROWS_PER_CHAIN ({MAX_ROWS_PER_CHAIN:,}). Stopping.")
                break

    elapsed = time.time() - start
    print(f"[{chain.upper()}] Done. {row_count:,} addresses → {out_path} in {elapsed:.1f}s")
    return row_count


# ------------------ QUERIES ------------------
def export_btc(client):
    # Full double-entry book — expensive but complete.
    # Filters out multi-address coinbase outputs (addresses is an ARRAY).
    sql = """
        WITH double_entry_book AS (
            SELECT ARRAY_TO_STRING(inputs.addresses, ",") AS address,
                   -inputs.value AS value
            FROM `bigquery-public-data.crypto_bitcoin.inputs` AS inputs
            UNION ALL
            SELECT ARRAY_TO_STRING(outputs.addresses, ",") AS address,
                   outputs.value AS value
            FROM `bigquery-public-data.crypto_bitcoin.outputs` AS outputs
        )
        SELECT address
        FROM double_entry_book
        WHERE address IS NOT NULL
        GROUP BY address
        HAVING SUM(value) >= @threshold
    """
    params = [bigquery.ScalarQueryParameter("threshold", "INT64", THRESHOLDS["btc"]["raw"])]
    return run_and_save(client, "btc", sql, params)


def export_eth(client):
    sql = """
        SELECT address
        FROM `bigquery-public-data.crypto_ethereum.balances`
        WHERE eth_balance >= @threshold
    """
    params = [bigquery.ScalarQueryParameter("threshold", "NUMERIC", THRESHOLDS["eth"]["raw"])]
    return run_and_save(client, "eth", sql, params)


def export_tron(client):
    # Hex address (41...). Convert to base58 later if needed.
    sql = """
        SELECT address
        FROM `bigquery-public-data.goog_blockchain_tron_mainnet_us.accounts`
        WHERE balance >= @threshold
    """
    params = [bigquery.ScalarQueryParameter("threshold", "INT64", THRESHOLDS["tron"]["raw"])]
    return run_and_save(client, "tron", sql, params)


def export_sol(client):
    # pubkey is BYTES → hex string. Convert to base58 later if needed.
    sql = """
        SELECT TO_HEX(pubkey) AS address
        FROM `bigquery-public-data.crypto_solana_mainnet_us.Accounts`
        WHERE lamports >= @threshold
    """
    params = [bigquery.ScalarQueryParameter("threshold", "INT64", THRESHOLDS["sol"]["raw"])]
    return run_and_save(client, "sol", sql, params)


# ------------------ MAIN ------------------
def main():
    if not os.path.exists(GCP_KEY_FILE):
        print(f"ERROR: {GCP_KEY_FILE} not found.")
        print("Create a GCP service account with 'BigQuery Job User' and")
        print("'BigQuery Data Viewer' roles, download the JSON key, and save")
        print("it as gcp-service-account.json in this folder.")
        sys.exit(1)

    client = get_client()

    print("=" * 60)
    print("EXPORTING ADDRESSES ONLY (>= threshold)")
    print("=" * 60)
    for chain, t in THRESHOLDS.items():
        print(f"  {chain.upper():6} : >= {t['display']}")
    print("=" * 60)

    totals = {}
    grand_start = time.time()

    totals["btc"]  = export_btc(client)
    totals["eth"]  = export_eth(client)
    totals["tron"] = export_tron(client)
    totals["sol"]  = export_sol(client)

    grand_elapsed = time.time() - grand_start

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    total = 0
    for chain, count in totals.items():
        print(f"  {chain.upper():6} : {count:>12,} addresses")
        total += count
    print("-" * 60)
    print(f"  {'TOTAL':6} : {total:>12,} addresses")
    print(f"  Elapsed : {grand_elapsed/60:.1f} minutes")
    print("=" * 60)
    print("\nOutput files:")
    for chain in totals:
        print(f"  {chain}_addresses.txt")


if __name__ == "__main__":
    main()