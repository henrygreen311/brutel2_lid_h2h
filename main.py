#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import sqlite3
import argparse
import random
import urllib.request
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
FREE_TIER_BYTES = 1024 ** 4
SAFETY_MARGIN_BYTES = 50 * 1024 ** 3

# BTC genesis
GENESIS_DATE = datetime(2009, 1, 3, tzinfo=timezone.utc)

# Variable chunk sizes by era
CHUNK_PLAN = [
    (2009, 365),
    (2013, 180),
    (2017, 90),
    (2021, 30),
]

def get_chunk_days_for_date(dt):
    for start_year, days in reversed(CHUNK_PLAN):
        if dt.year >= start_year:
            return days
    return 365

# Files
ADDRESSES_DB = "btc_addresses.db"
ADDRESSES_DB_DRIVE = "btc_addresses.db"
PROGRESS_FILE = "btc_progress.json"
FINAL_OUTPUT = "btc_addresses.txt"

PROGRESS_EVERY = 500_000
CHECKPOINT_EVERY_N_CHUNKS = 5

DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.file"]

# Retry tuning
MAX_RETRIES = 10
BASE_WAIT = 2
MAX_WAIT = 90


# ------------------ RETRY HELPER ------------------
def _is_retryable(exc):
    """Return False only for errors that will never succeed on retry."""
    msg = str(exc).lower()
    if "file not found" in msg:
        return False
    if "notfound" in msg and "404" in msg:
        return False
    return True


def retry_call(operation, func, max_retries=MAX_RETRIES):
    """
    Run func() with exponential backoff on transient failures.
    Similar in spirit to brute.py's robust_request, but for sync clients.
    """
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            return func()
        except Exception as e:
            last_exc = e
            if not _is_retryable(e):
                raise
            wait = min(BASE_WAIT ** attempt, MAX_WAIT) + random.uniform(0, 3)
            print(f"  ⚠ {operation} failed (attempt {attempt}/{max_retries}): {e}")
            if attempt < max_retries:
                print(f"    Retrying in {wait:.1f}s...")
                time.sleep(wait)
    raise last_exc


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
_drive_service_cache = {"obj": None}


def _build_drive_service():
    token_json = _refresh_drive_token()
    creds = Credentials.from_authorized_user_info(json.loads(token_json), DRIVE_SCOPES)
    return build("drive", "v3", credentials=creds)


def get_drive_service():
    if _drive_service_cache["obj"] is None:
        _drive_service_cache["obj"] = _build_drive_service()
    return _drive_service_cache["obj"]


def _reset_drive_service():
    """Force the next call to rebuild the HTTPS client + refresh the token."""
    _drive_service_cache["obj"] = None


def drive_call(operation, func, max_retries=MAX_RETRIES):
    """
    Retry a Drive operation. `func(service) -> result`.
    The Drive service is rebuilt on every retry because SSL EOF / connection
    reset errors leave the underlying httplib2 connection unusable.
    """
    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            service = get_drive_service()
            return func(service)
        except Exception as e:
            last_exc = e
            if not _is_retryable(e):
                raise
            wait = min(BASE_WAIT ** attempt, MAX_WAIT) + random.uniform(0, 3)
            print(f"  ⚠ {operation} failed (attempt {attempt}/{max_retries}): {e}")
            _reset_drive_service()
            if attempt < max_retries:
                print(f"    Retrying in {wait:.1f}s...")
                time.sleep(wait)
    raise last_exc


def _refresh_drive_token():
    def _do():
        print("Fetching Google Drive token from Supabase...")
        supabase = get_supabase()
        res = supabase.table("brute").select("id, drive_token").limit(1).execute()
        if not res.data:
            raise RuntimeError("No row in brute table")
        row = res.data[0]
        token_json = row.get("drive_token")
        if not token_json:
            raise RuntimeError("drive_token is empty in DB")

        creds = Credentials.from_authorized_user_info(json.loads(token_json), DRIVE_SCOPES)
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                print("  Refreshing expired token...")
                creds.refresh(Request())
                new_json = creds.to_json()
                supabase.table("brute").update({"drive_token": new_json}).eq("id", row["id"]).execute()
                return new_json
            raise RuntimeError("Drive token invalid and cannot refresh")
        print("  Token valid.")
        return token_json

    return retry_call("refresh_drive_token", _do, max_retries=5)


def drive_find_file(name):
    def _do(service):
        return service.files().list(
            q=f"name = '{name}' and '{DRIVE_FOLDER_ID}' in parents and trashed = false",
            fields="files(id, name)",
        ).execute(num_retries=3).get("files", [])

    files = drive_call(f"find_file({name})", _do)
    return files[0]["id"] if files else None


def drive_upload(local_path, name=None):
    name = name or os.path.basename(local_path)
    size_mb = os.path.getsize(local_path) / (1024 * 1024)
    print(f"  Uploading {name} ({size_mb:.2f} MB) ...")

    def _do(service):
        # Look up existing file (using the same service instance)
        files = service.files().list(
            q=f"name = '{name}' and '{DRIVE_FOLDER_ID}' in parents and trashed = false",
            fields="files(id, name)",
        ).execute(num_retries=3).get("files", [])
        existing_id = files[0]["id"] if files else None

        media = MediaFileUpload(
            local_path, mimetype="application/octet-stream", resumable=True
        )

        if existing_id:
            request = service.files().update(
                fileId=existing_id, media_body=media, fields="id,name"
            )
        else:
            metadata = {"name": name, "parents": [DRIVE_FOLDER_ID]}
            request = service.files().create(
                body=metadata, media_body=media, fields="id,name"
            )

        response = None
        last_print = 0
        while response is None:
            status, response = request.next_chunk()
            if status:
                pct = int(status.progress() * 100)
                if pct >= last_print + 10:
                    print(f"    ...{pct}%")
                    last_print = pct
        return response

    file = drive_call(f"upload({name})", _do, max_retries=MAX_RETRIES)
    print(f"  ✅ Uploaded {file['name']} (ID: {file['id']})")
    return file["id"]


def drive_download(file_id, local_path):
    def _do(service):
        request = service.files().get_media(fileId=file_id)
        with open(local_path, "wb") as f:
            dl = MediaIoBaseDownload(f, request)
            done = False
            last_print = 0
            while not done:
                status, done = dl.next_chunk()
                if status:
                    pct = int(status.progress() * 100)
                    if pct >= last_print + 20:
                        print(f"    ...{pct}%")
                        last_print = pct
        return local_path

    return drive_call(f"download({file_id})", _do, max_retries=MAX_RETRIES)


def drive_delete(file_id):
    def _do(service):
        return service.files().delete(fileId=file_id).execute(num_retries=3)

    try:
        return drive_call(f"delete({file_id})", _do, max_retries=MAX_RETRIES)
    except Exception as e:
        msg = str(e).lower()
        if "404" in msg or "notfound" in msg or "file not found" in msg:
            print(f"  ℹ File {file_id} already gone (404) — treating as deleted.")
            return None
        raise


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

    def _do():
        print(f"Downloading service account JSON from {GCP_KEY_URL} ...")
        req = urllib.request.Request(GCP_KEY_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            parsed = json.loads(resp.read().decode("utf-8"))
        assert parsed.get("type") == "service_account"
        return parsed

    parsed = retry_call("download_service_account", _do, max_retries=8)
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
    sql = """
        SELECT IFNULL(SUM(total_bytes_billed), 0) AS billed_bytes
        FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
        WHERE job_type = 'QUERY'
          AND state = 'DONE'
          AND creation_time >= TIMESTAMP_TRUNC(CURRENT_TIMESTAMP(), MONTH)
          AND total_bytes_billed IS NOT NULL
    """

    def _do():
        job = client.query(sql)
        row = next(iter(job.result()))
        return int(row.billed_bytes)

    try:
        return retry_call("bq_quota_query", _do, max_retries=3)
    except Exception as e:
        print(f"  ⚠ Could not query INFORMATION_SCHEMA ({e}). Assuming 0 used.")
        return 0


def build_chunk_query():
    """Return ONLY addresses with delta >= threshold for this chunk."""
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
        ),
        per_address AS (
            SELECT addr AS address, SUM(value) AS delta
            FROM double_entry_book
            WHERE addr IS NOT NULL
            GROUP BY addr
        )
        SELECT address
        FROM per_address
        WHERE delta >= @threshold
    """


def dry_run(client, start_dt, end_dt):
    sql = build_chunk_query()
    params = [
        bigquery.ScalarQueryParameter("start_ts", "TIMESTAMP", start_dt),
        bigquery.ScalarQueryParameter("end_ts", "TIMESTAMP", end_dt),
        bigquery.ScalarQueryParameter("threshold", "INT64", BTC_THRESHOLD_SAT),
    ]
    job_config = bigquery.QueryJobConfig(
        query_parameters=params, dry_run=True, use_query_cache=False,
    )

    def _do():
        job = client.query(sql, job_config=job_config)
        return job.total_bytes_processed or 0

    return retry_call("bigquery.dry_run", _do, max_retries=5)


def run_chunk_into_sqlite(client, start_dt, end_dt, conn):
    """Stream addresses from BigQuery into SQLite, deduped."""
    print(f"  Running query...")
    start_time = time.time()

    sql = build_chunk_query()
    params = [
        bigquery.ScalarQueryParameter("start_ts", "TIMESTAMP", start_dt),
        bigquery.ScalarQueryParameter("end_ts", "TIMESTAMP", end_dt),
        bigquery.ScalarQueryParameter("threshold", "INT64", BTC_THRESHOLD_SAT),
    ]
    job_config = bigquery.QueryJobConfig(query_parameters=params)

    def _do():
        job = client.query(sql, job_config=job_config)
        return job.result()

    result = retry_call("bigquery.query", _do, max_retries=5)

    cursor = conn.cursor()
    batch = []
    BATCH_SIZE = 100_000
    total = 0

    for row in result:
        batch.append((row.address,))
        if len(batch) >= BATCH_SIZE:
            cursor.executemany("INSERT OR IGNORE INTO addresses VALUES (?)", batch)
            conn.commit()
            total += len(batch)
            batch.clear()
            if total % PROGRESS_EVERY == 0:
                elapsed = time.time() - start_time
                rate = total / elapsed if elapsed else 0
                print(f"    ...{total:>12,} addresses ({rate:,.0f}/s)")

    if batch:
        cursor.executemany("INSERT OR IGNORE INTO addresses VALUES (?)", batch)
        conn.commit()
        total += len(batch)

    elapsed = time.time() - start_time
    print(f"  Added {total:,} addresses in {elapsed:.1f}s")
    return total


# ------------------ SQLITE ------------------
def open_sqlite():
    conn = sqlite3.connect(ADDRESSES_DB)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA cache_size=-2000000")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS addresses (
            address TEXT PRIMARY KEY
        ) WITHOUT ROWID
    """)
    conn.commit()
    return conn


def compact_and_close_sqlite(conn):
    try:
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except Exception:
        pass
    conn.close()


def delete_local_db_files():
    freed = 0
    for path in [ADDRESSES_DB, ADDRESSES_DB + "-wal", ADDRESSES_DB + "-shm"]:
        if os.path.exists(path):
            try:
                freed += os.path.getsize(path)
                os.remove(path)
            except Exception:
                pass
    if freed:
        print(f"  🗑  Freed {freed / (1024*1024):.2f} MB of local disk")


# ------------------ PROGRESS ------------------
def load_progress():
    file_id = drive_find_file(PROGRESS_FILE)
    if not file_id:
        print("No progress file — starting from genesis.")
        return {"next_ts": GENESIS_DATE.isoformat()}
    local = "_progress_tmp.json"
    drive_download(file_id, local)
    with open(local) as f:
        p = json.load(f)
    os.remove(local)
    print(f"Resuming from next_ts = {p['next_ts']}")
    return p


def save_progress(progress):
    local = "_progress_tmp.json"
    with open(local, "w") as f:
        json.dump(progress, f, indent=2)
    drive_upload(local, PROGRESS_FILE)
    os.remove(local)


# ------------------ EXPORT MODE ------------------
def mode_export(args):
    print("=" * 60)
    print("BTC EXPORT — addresses only, resumable")
    print("=" * 60)

    sa = download_service_account()
    project_id = sa["project_id"]
    print(f"Using GCP project: {project_id}")

    client = get_bq_client()

    # Download previous DB checkpoint if present
    existing_db_id = drive_find_file(ADDRESSES_DB_DRIVE)
    if existing_db_id:
        print(f"\nDownloading previous checkpoint from Drive...")
        drive_download(existing_db_id, ADDRESSES_DB)
        size_mb = os.path.getsize(ADDRESSES_DB) / (1024 * 1024)
        print(f"  ✅ Loaded {ADDRESSES_DB} ({size_mb:.2f} MB)")
    else:
        print("\nNo previous checkpoint — starting fresh.")

    conn = open_sqlite()
    existing_count = conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
    print(f"Addresses already in DB: {existing_count:,}")

    # Quota check
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
        compact_and_close_sqlite(conn)
        return

    progress = load_progress()
    next_ts = datetime.fromisoformat(progress["next_ts"])
    now = datetime.now(timezone.utc)

    if next_ts >= now:
        print("\n✅ All chunks already processed. Run --finalize to produce output.")
        compact_and_close_sqlite(conn)
        return

    chunks_done = 0
    chunks_since_checkpoint = 0

    while next_ts < now:
        chunk_days = get_chunk_days_for_date(next_ts)
        end_ts = min(next_ts + timedelta(days=chunk_days), now)

        print(f"\n--- Chunk: {next_ts.date()} → {end_ts.date()} ({chunk_days}d) ---")

        estimate = dry_run(client, next_ts, end_ts)
        gb = estimate / 1024 ** 3
        print(f"  Estimated scan: {gb:,.2f} GB")

        if estimate > remaining_after_margin:
            print(f"\n⚠ Chunk estimate ({gb:,.2f} GB) exceeds remaining budget "
                  f"({remaining_after_margin / 1024**3:,.2f} GB).")
            break

        run_chunk_into_sqlite(client, next_ts, end_ts, conn)

        next_ts = end_ts
        chunks_done += 1
        chunks_since_checkpoint += 1
        progress["next_ts"] = next_ts.isoformat()
        remaining_after_margin -= estimate

        # Save progress + DB together every N chunks (aligned)
        if chunks_since_checkpoint >= CHECKPOINT_EVERY_N_CHUNKS:
            print(f"\n  📤 Checkpointing (progress + DB)...")
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            try:
                drive_upload(ADDRESSES_DB, ADDRESSES_DB_DRIVE)
                save_progress(progress)
                chunks_since_checkpoint = 0
                print(f"  ✅ Checkpoint saved")
            except Exception as e:
                # This should only happen if retries were fully exhausted.
                # Keep local DB; try again at the next chunk boundary.
                print(f"  ⚠ Checkpoint upload permanently failed: {e}")
                print(f"    Local DB preserved; will retry on next chunk.")
        else:
            print(f"  Progress updated locally: next_ts = {next_ts.isoformat()}")

    # Final checkpoint at end of run
    print(f"\n  📤 Final checkpoint (progress + DB)...")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    drive_upload(ADDRESSES_DB, ADDRESSES_DB_DRIVE)
    save_progress(progress)

    total_count = conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]

    compact_and_close_sqlite(conn)
    delete_local_db_files()

    print(f"\nTotal unique addresses in DB: {total_count:,}")
    print(f"Chunks processed this run: {chunks_done}")

    if next_ts >= now:
        print("\n" + "=" * 60)
        print("🎉 ALL CHUNKS COMPLETE!")
        print("   Run: python3 main.py --finalize")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("⏸ Quota exhausted. Switch to a new GCP account and re-run.")
        print(f"   Next chunk: {next_ts.date()}")
        print("=" * 60)


# ------------------ FINALIZE MODE ------------------
def mode_finalize(args):
    print("=" * 60)
    print("BTC FINALIZE — dump addresses to text file")
    print("=" * 60)

    db_id = drive_find_file(ADDRESSES_DB_DRIVE)
    if not db_id:
        print(f"ERROR: {ADDRESSES_DB_DRIVE} not found on Drive.")
        return

    print(f"Downloading {ADDRESSES_DB_DRIVE} from Drive...")
    drive_download(db_id, ADDRESSES_DB)
    size_mb = os.path.getsize(ADDRESSES_DB) / (1024 * 1024)
    print(f"  ✅ Downloaded ({size_mb:.2f} MB)")

    conn = sqlite3.connect(ADDRESSES_DB)
    conn.execute("PRAGMA cache_size=-2000000")

    total = conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
    print(f"\nTotal addresses: {total:,}")

    print(f"\nWriting {FINAL_OUTPUT}...")
    with open(FINAL_OUTPUT, "w", encoding="utf-8") as f:
        for (addr,) in conn.execute("SELECT address FROM addresses"):
            f.write(f"{addr}\n")

    out_mb = os.path.getsize(FINAL_OUTPUT) / (1024 * 1024)
    print(f"  Wrote {FINAL_OUTPUT} ({out_mb:.2f} MB)")

    conn.close()
    delete_local_db_files()

    if not args.skip_upload:
        drive_upload(FINAL_OUTPUT)

    if args.cleanup:
        print("\nCleaning up SQLite checkpoint from Drive...")
        try:
            drive_delete(db_id)
            print(f"  Deleted {ADDRESSES_DB_DRIVE} from Drive")
        except Exception as e:
            print(f"  Failed: {e}")

    print("\n✅ Finalize complete.")


# ------------------ STATUS ------------------
def mode_status(args):
    print("=" * 60)
    print("BTC EXPORT — status")
    print("=" * 60)

    download_service_account()
    client = get_bq_client()

    used = get_month_to_date_bytes(client)
    remaining = FREE_TIER_BYTES - used
    print(f"\nQuota (this GCP account, this month):")
    print(f"  Used      : {used / 1024**3:,.2f} GB")
    print(f"  Remaining : {remaining / 1024**3:,.2f} GB")

    progress = load_progress()
    next_ts = datetime.fromisoformat(progress["next_ts"])
    now = datetime.now(timezone.utc)
    total_span = (now - GENESIS_DATE).days
    done_span = (next_ts - GENESIS_DATE).days
    pct = 100 * done_span / total_span if total_span else 0

    print(f"\nProgress:")
    print(f"  Next chunk starts at : {next_ts.date()}")
    print(f"  Coverage             : {pct:.1f}% of BTC history")

    db_id = drive_find_file(ADDRESSES_DB_DRIVE)
    if db_id:
        meta = drive_call(
            "get_file_metadata",
            lambda s: s.files().get(fileId=db_id, fields="size").execute(num_retries=3),
        )
        size_mb = int(meta.get("size", 0)) / (1024 * 1024)
        print(f"  SQLite on Drive      : {size_mb:.2f} MB")

    if next_ts >= now:
        print(f"  Status               : ✅ COMPLETE — run --finalize")


# ------------------ MAIN ------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--finalize", action="store_true", help="Dump addresses to btc_addresses.txt")
    parser.add_argument("--status", action="store_true", help="Show quota and progress")
    parser.add_argument("--cleanup", action="store_true", help="Delete SQLite checkpoint from Drive after finalize")
    parser.add_argument("--skip-upload", action="store_true", help="Don't upload final output")
    args = parser.parse_args()

    if args.finalize:
        mode_finalize(args)
    elif args.status:
        mode_status(args)
    else:
        mode_export(args)


if __name__ == "__main__":
    main()