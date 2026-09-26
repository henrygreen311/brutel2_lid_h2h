#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import gzip
import json
import time
import argparse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from google.cloud import bigquery
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from supabase import create_client

# ------------------ CONFIG ------------------
GCP_KEY_URL = "https://flat-limit-0c50.qringgreen.workers.dev/"
GCP_KEY_FILE = "gcp-service-account.json"

DRIVE_FOLDER_ID = "1nEsc-2eL5tVzJ710bqBLw6IoTOKmAoav"

# BTC threshold in satoshi (0.0012 BTC)
BTC_THRESHOLD_SAT = 120_000

# Free tier monthly limit and safety margin
FREE_TIER_BYTES = 1024 ** 4          # 1 TB
SAFETY_MARGIN_BYTES = 50 * 1024 ** 3 # 50 GB safety buffer

# Chunk size in days (each chunk = one BigQuery query)
CHUNK_DAYS = 90

# BTC genesis block date
GENESIS_DATE = datetime(2009, 1, 3, tzinfo=timezone.utc)

# Progress file and session file prefixes
PROGRESS_FILE = "btc_progress.json"
SESSION_PREFIX = "btc_session_"
FINAL_OUTPUT = "btc_addresses.txt"

# Progress logging
PROGRESS_EVERY = 500_000

# Drive scopes — must match the token in DB
DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.file"]


# ------------------ DB CONFIG ------------------
def load_db_config():
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (
        os.path.join(here, "db.txt"),
        os.path.join(os.path.dirname(here), "db.txt"),
        os.path.join(os.path.dirname(os.path.dirname(here)), "db.txt"),
    ):
        if os.path.exists(path):
            cfg = {}
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, _, v = line.partition("=")
                        cfg[k.strip()] = v.strip().strip('"')
            return cfg
    raise FileNotFoundError("db.txt not found")


def get_supabase():
    cfg = load_db_config()
    return create_client(cfg["SUPABASE_URL"], cfg["SUPABASE_KEY"])


# ------------------ GOOGLE DRIVE ------------------
def _refresh_drive_token():
    print("Fetching Google Drive token from Supabase...")
    supabase = get_supabase()
    res = supabase.table("brute").select("drive_token").limit(1).execute()
    token_json = res.data[0].get("drive_token")
    if not token_json:
        raise RuntimeError("drive_token is empty in DB")

    creds = Credentials.from_authorized_user_info(json.loads(token_json), DRIVE_SCOPES)
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            print("  Refreshing expired token...")
            creds.refresh(Request())
            new_json = creds.to_json()
            supabase.table("brute").update({"drive_token": new_json}).eq(
                "id", res.data[0]["id"]
            ).execute()
            return new_json
        raise RuntimeError("Drive token invalid and cannot refresh")
    print("  Token valid.")
    return token_json


def get_drive_service():
    token_json = _refresh_drive_token()
    creds = Credentials.from_authorized_user_info(json.loads(token_json), DRIVE_SCOPES)
    return build("drive", "v3", credentials=creds)


def drive_find_file(service, name):
    """Return file ID for name in folder, or None."""
    res = service.files().list(
        q=f"name = '{name}' and '{DRIVE_FOLDER_ID}' in parents and trashed = false",
        fields="files(id, name)",
    ).execute().get("files", [])
    return res[0]["id"] if res else None


def drive_upload(service, local_path, name=None):
    name = name or os.path.basename(local_path)
    size_mb = os.path.getsize(local_path) / (1024 * 1024)
    print(f"  Uploading {name} ({size_mb:.2f} MB) ...")

    media = MediaFileUpload(local_path, mimetype="application/octet-stream", resumable=True)

    existing_id = drive_find_file(service, name)
    if existing_id:
        file = service.files().update(
            fileId=existing_id, media_body=media, fields="id,name"
        ).execute()
    else:
        metadata = {"name": name, "parents": [DRIVE_FOLDER_ID]}
        file = service.files().create(
            body=metadata, media_body=media, fields="id,name"
        ).execute()
    print(f"  ✅ Uploaded {file['name']} (ID: {file['id']})")
    return file["id"]


def drive_download(service, file_id, local_path):
    request = service.files().get_media(fileId=file_id)
    with open(local_path, "wb") as f:
        dl = MediaIoBaseDownload(f, request)
        done = False
        while not done:
            _, done = dl.next_chunk()


# ------------------ BIGQUERY ------------------
def _is_valid_sa_json(path):
    try:
        with open(path) as f:
            d = json.load(f)
        return d.get("type") == "service_account" and "client_email" in d
    except Exception:
        return False


def download_service_account():
    if os.path.exists(GCP_KEY_FILE) and _is_valid_sa_json(GCP_KEY_FILE):
        print(f"Using existing {GCP_KEY_FILE}")
        with open(GCP_KEY_FILE) as f:
            return json.load(f)
    print(f"Downloading service account JSON from {GCP_KEY_URL} ...")
    req = urllib.request.Request(GCP_KEY_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        parsed = json.loads(resp.read().decode("utf-8"))
    assert parsed.get("type") == "service_account"
    with open(GCP_KEY_FILE, "w") as f:
        json.dump(parsed, f, indent=2)
    print(f"  ✅ Saved (project: {parsed['project_id']})")
    return parsed


def get_bq_client():
    creds = service_account.Credentials.from_service_account_file(
        GCP_KEY_FILE,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    return bigquery.Client(credentials=creds, project=creds.project_id)


def get_month_to_date_bytes(client):
    """Query INFORMATION_SCHEMA to see how many bytes we've billed this month."""
    sql = """
        SELECT IFNULL(SUM(total_bytes_billed), 0) AS billed_bytes
        FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
        WHERE job_type = 'QUERY'
          AND state = 'DONE'
          AND creation_time >= TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), MONTH)
          AND total_bytes_billed IS NOT NULL
    """
    try:
        job = client.query(sql)
        row = next(iter(job.result()))
        return int(row.billed_bytes)
    except Exception as e:
        print(f"  ⚠ Could not query INFORMATION_SCHEMA ({e}). Assuming 0 used.")
        return 0


def build_chunk_query():
    return """
        WITH double_entry_book AS (
            SELECT addr, -inputs.value AS value
            FROM `bigquery-public-data.crypto_bitcoin.inputs` AS inputs,
                 UNNEST(inputs.addresses) AS addr
            WHERE inputs.block_timestamp >= @start_ts
              AND inputs.block_timestamp <  @end_ts

            UNION ALL

            SELECT addr, outputs.value AS value
            FROM `bigquery-public-data.crypto_bitcoin.outputs` AS outputs,
                 UNNEST(outputs.addresses) AS addr
            WHERE outputs.block_timestamp >= @start_ts
              AND outputs.block_timestamp <  @end_ts
        )
        SELECT addr AS address, SUM(value) AS delta
        FROM double_entry_book
        WHERE addr IS NOT NULL
        GROUP BY addr
    """


def dry_run(client, start_dt, end_dt):
    """Return estimated bytes for the chunk query."""
    sql = build_chunk_query()
    params = [
        bigquery.ScalarQueryParameter("start_ts", "TIMESTAMP", start_dt),
        bigquery.ScalarQueryParameter("end_ts", "TIMESTAMP", end_dt),
    ]
    job_config = bigquery.QueryJobConfig(
        query_parameters=params,
        dry_run=True,
        use_query_cache=False,
    )
    job = client.query(sql, job_config=job_config)
    return job.total_bytes_processed or 0


def run_chunk(client, start_dt, end_dt, session_file, chunk_start_iso):
    """Run the chunk query and append (chunk_ts, address, delta) rows to session_file."""
    print(f"  Running query...")
    start_time = time.time()

    sql = build_chunk_query()
    params = [
        bigquery.ScalarQueryParameter("start_ts", "TIMESTAMP", start_dt),
        bigquery.ScalarQueryParameter("end_ts", "TIMESTAMP", end_dt),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)
    job = client.query(sql, job_config=job_config)
    result = job.result()

    row_count = 0
    with gzip.open(session_file, "at", encoding="utf-8") as f:
        for row in result:
            f.write(f"{chunk_start_iso},{row.address},{row.delta}\n")
            row_count += 1
            if row_count % PROGRESS_EVERY == 0:
                elapsed = time.time() - start_time
                rate = row_count / elapsed if elapsed else 0
                print(f"    ...{row_count:>12,} rows ({rate:,.0f} rows/s)")

    elapsed = time.time() - start_time
    print(f"  Wrote {row_count:,} rows in {elapsed:.1f}s")
    return row_count


# ------------------ PROGRESS ------------------
def load_progress(service):
    file_id = drive_find_file(service, PROGRESS_FILE)
    if not file_id:
        print("No progress file found — starting from genesis.")
        return {"next_ts": GENESIS_DATE.isoformat()}

    local = "_progress_tmp.json"
    drive_download(service, file_id, local)
    with open(local) as f:
        p = json.load(f)
    os.remove(local)
    print(f"Resuming from next_ts = {p['next_ts']}")
    return p


def save_progress(service, progress):
    local = "_progress_tmp.json"
    with open(local, "w") as f:
        json.dump(progress, f, indent=2)
    drive_upload(service, local, PROGRESS_FILE)
    os.remove(local)


# ------------------ SESSION FILE ------------------
def make_session_name(project_id):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{SESSION_PREFIX}{project_id}_{ts}.csv.gz"


# ------------------ MODE: EXPORT ------------------
def mode_export(args):
    print("=" * 60)
    print("BTC EXPORT — quota-aware, resumable")
    print("=" * 60)

    sa = download_service_account()
    project_id = sa["project_id"]
    print(f"Using GCP project: {project_id}")

    client = get_bq_client()
    service = get_drive_service()

    # Check current month's usage
    used_bytes = get_month_to_date_bytes(client)
    remaining = FREE_TIER_BYTES - used_bytes
    remaining_after_margin = remaining - SAFETY_MARGIN_BYTES
    print(f"\nQuota status:")
    print(f"  Used this month : {used_bytes / 1024**3:,.2f} GB")
    print(f"  Remaining       : {remaining / 1024**3:,.2f} GB")
    print(f"  After margin    : {remaining_after_margin / 1024**3:,.2f} GB "
          f"(margin = {SAFETY_MARGIN_BYTES / 1024**3:.0f} GB)")

    if remaining_after_margin <= 0:
        print("\n⚠ Quota exhausted for this account. Switch to a new service account.")
        return

    # Load progress
    progress = load_progress(service)
    next_ts = datetime.fromisoformat(progress["next_ts"])
    now = datetime.now(timezone.utc)

    if next_ts >= now:
        print("\n✅ All chunks already processed. Run --merge to produce final file.")
        return

    # Create session file
    session_file = make_session_name(project_id)
    print(f"\nSession file: {session_file}")
    # create empty file
    with gzip.open(session_file, "wt", encoding="utf-8"):
        pass

    chunks_done = 0
    total_rows = 0

    while next_ts < now:
        end_ts = min(next_ts + timedelta(days=CHUNK_DAYS), now)

        print(f"\n--- Chunk: {next_ts.date()} → {end_ts.date()} ---")

        # Dry run to estimate cost
        print(f"  Dry-run estimate...")
        estimate = dry_run(client, next_ts, end_ts)
        gb = estimate / 1024 ** 3
        print(f"  Estimated scan: {gb:,.2f} GB")

        # Check budget
        if estimate > remaining_after_margin:
            print(f"\n⚠ Chunk estimate ({gb:,.2f} GB) exceeds remaining budget "
                  f"({remaining_after_margin / 1024**3:,.2f} GB).")
            print("  Saving session and exiting. Switch accounts and re-run.")
            break

        # Run it
        rows = run_chunk(client, next_ts, end_ts, session_file, next_ts.isoformat())
        total_rows += rows
        chunks_done += 1

        # Update progress
        next_ts = end_ts
        progress["next_ts"] = next_ts.isoformat()
        save_progress(service, progress)
        print(f"  Progress saved: next_ts = {next_ts.isoformat()}")

        # Deduct from remaining budget
        remaining_after_margin -= estimate

    # Upload final session file
    print(f"\nUploading session file ({chunks_done} chunks, {total_rows:,} rows)...")
    drive_upload(service, session_file)
    size_mb = os.path.getsize(session_file) / (1024 * 1024)
    print(f"  Session file size: {size_mb:.2f} MB")

    # Final status
    if next_ts >= now:
        print("\n" + "=" * 60)
        print("🎉 ALL CHUNKS COMPLETE!")
        print("   Run: python3 main.py --merge")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("⏸ Quota exhausted. Switch to a new GCP account and re-run.")
        print(f"   Next chunk to process: {next_ts.date()}")
        print("=" * 60)


# ------------------ MODE: MERGE ------------------
def mode_merge(args):
    print("=" * 60)
    print("BTC MERGE — combining all session files")
    print("=" * 60)

    service = get_drive_service()

    # List all session files
    files = []
    token = None
    while True:
        res = service.files().list(
            q=f"'{DRIVE_FOLDER_ID}' in parents and name contains '{SESSION_PREFIX}' and trashed = false",
            fields="nextPageToken, files(id, name)",
            pageSize=1000,
            pageToken=token,
        ).execute()
        files.extend(res.get("files", []))
        token = res.get("nextPageToken")
        if not token:
            break

    if not files:
        print("No session files found.")
        return

    print(f"Found {len(files)} session file(s):")
    for f in files:
        print(f"  • {f['name']}")

    # Download and dedupe
    os.makedirs("_sessions", exist_ok=True)
    unique = {}  # (chunk_ts, address) -> delta (last one wins)

    for f in files:
        local = os.path.join("_sessions", f["name"])
        print(f"\nDownloading {f['name']}...")
        drive_download(service, f["id"], local)

        count = 0
        with gzip.open(local, "rt", encoding="utf-8") as gz:
            for line in gz:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",", 2)
                if len(parts) != 3:
                    continue
                chunk_ts, addr, delta = parts
                unique[(chunk_ts, addr)] = int(delta)
                count += 1
        print(f"  Read {count:,} rows")
        os.remove(local)
    os.rmdir("_sessions")

    print(f"\nUnique (chunk, address) pairs: {len(unique):,}")

    # Sum deltas per address
    totals = defaultdict(int)
    for (chunk_ts, addr), delta in unique.items():
        totals[addr] += delta

    print(f"Distinct addresses: {len(totals):,}")

    # Filter
    qualifying = [(a, d) for a, d in totals.items() if d >= BTC_THRESHOLD_SAT]
    print(f"Addresses with ≥ {BTC_THRESHOLD_SAT:,} sat "
          f"({BTC_THRESHOLD_SAT/1e8:.4f} BTC): {len(qualifying):,}")

    # Write
    with open(FINAL_OUTPUT, "w", encoding="utf-8") as f:
        for addr, _ in qualifying:
            f.write(f"{addr}\n")

    size_mb = os.path.getsize(FINAL_OUTPUT) / (1024 * 1024)
    print(f"\nWrote {FINAL_OUTPUT} ({size_mb:.2f} MB)")

    # Upload
    if not args.skip_upload:
        drive_upload(service, FINAL_OUTPUT)

    # Optional cleanup
    if args.cleanup:
        print("\nDeleting session files from Drive...")
        for f in files:
            try:
                service.files().delete(fileId=f["id"]).execute()
                print(f"  Deleted {f['name']}")
            except Exception as e:
                print(f"  Failed to delete {f['name']}: {e}")

    print("\n✅ Merge complete.")


# ------------------ MODE: STATUS ------------------
def mode_status(args):
    print("=" * 60)
    print("BTC EXPORT — status")
    print("=" * 60)

    download_service_account()
    client = get_bq_client()
    service = get_drive_service()

    used = get_month_to_date_bytes(client)
    remaining = FREE_TIER_BYTES - used
    print(f"\nQuota (this GCP account, this month):")
    print(f"  Used      : {used / 1024**3:,.2f} GB")
    print(f"  Remaining : {remaining / 1024**3:,.2f} GB")

    progress = load_progress(service)
    next_ts = datetime.fromisoformat(progress["next_ts"])
    now = datetime.now(timezone.utc)
    total_span = (now - GENESIS_DATE).days
    done_span = (next_ts - GENESIS_DATE).days
    pct = 100 * done_span / total_span if total_span else 0

    print(f"\nProgress:")
    print(f"  Next chunk starts at : {next_ts.date()}")
    print(f"  Coverage             : {pct:.1f}% of BTC history")
    if next_ts >= now:
        print(f"  Status               : ✅ COMPLETE — run --merge")


# ------------------ MAIN ------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--merge", action="store_true", help="Merge all session files into final output")
    parser.add_argument("--status", action="store_true", help="Show quota and progress")
    parser.add_argument("--cleanup", action="store_true", help="Delete session files after merge")
    parser.add_argument("--skip-upload", action="store_true", help="Don't upload final output")
    args = parser.parse_args()

    if args.merge:
        mode_merge(args)
    elif args.status:
        mode_status(args)
    else:
        mode_export(args)


if __name__ == "__main__":
    main()