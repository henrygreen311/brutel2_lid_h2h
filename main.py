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
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from supabase import create_client

# ------------------ CONFIG ------------------
GCP_KEY_URL = "https://flat-limit-0c50.qringgreen.workers.dev/"
GCP_KEY_FILE = "gcp-service-account.json"

# Hardcoded Drive folder ID
DRIVE_FOLDER_ID = "1nEsc-2eL5tVzJ710bqBLw6IoTOKmAoav"

# ETH threshold in wei (0.037 ETH)
ETH_THRESHOLD_WEI = 37_000_000_000_000_000

# Safety cap on estimated bytes scanned (900 GB < 1 TB free tier)
MAX_BYTES_BUDGET = 900 * 1024 ** 3

# Progress logging interval
PROGRESS_EVERY = 250_000

OUTPUT_FILE = "eth_addresses.txt"

# Drive scopes
DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.file"]


# ------------------ DB CONFIG (from brute.py) ------------------
def load_db_config():
    """Read Supabase URL and KEY from db.txt (project root or parent)."""
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (
        os.path.join(here, "db.txt"),
        os.path.join(os.path.dirname(here), "db.txt"),
        os.path.join(os.path.dirname(os.path.dirname(here)), "db.txt"),
    ):
        if os.path.exists(path):
            config = {}
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, _, value = line.partition("=")
                        config[key.strip()] = value.strip().strip('"')
            return config
    raise FileNotFoundError("db.txt not found")


def get_supabase():
    cfg = load_db_config()
    return create_client(cfg["SUPABASE_URL"], cfg["SUPABASE_KEY"])


# ------------------ GOOGLE DRIVE (from Supabase token) ------------------
def get_drive_token_from_db():
    """Fetch drive_token from the brute table."""
    supabase = get_supabase()
    res = supabase.table("brute").select("drive_token").limit(1).execute()
    if not res.data:
        raise RuntimeError("No row in brute table")
    token = res.data[0].get("drive_token")
    if not token:
        raise RuntimeError("drive_token column is empty in brute table")
    return token


def update_drive_token_in_db(token_json):
    """Push refreshed token JSON back to the brute table."""
    supabase = get_supabase()
    row = supabase.table("brute").select("id").limit(1).execute()
    if not row.data:
        return
    row_id = row.data[0]["id"]
    supabase.table("brute").update({"drive_token": token_json}).eq("id", row_id).execute()
    print("  ✅ Updated drive_token in DB.")


def refresh_drive_token_if_needed():
    """
    Fetch token from DB, refresh if expired, save back to DB.
    Returns the token JSON string.
    """
    print("Fetching Google Drive token from Supabase...")
    token_json = get_drive_token_from_db()

    try:
        token_info = json.loads(token_json)
        creds = Credentials.from_authorized_user_info(info=token_info, scopes=DRIVE_SCOPES)
    except Exception as e:
        raise RuntimeError(f"Failed to parse drive_token: {e}")

    if not creds.valid:
        if creds.expired and creds.refresh_token:
            print("  Access token expired — refreshing with refresh_token...")
            creds.refresh(Request())
            new_token_json = creds.to_json()
            update_drive_token_in_db(new_token_json)
            return new_token_json
        else:
            raise RuntimeError(
                "Drive token invalid and no refresh_token available. "
                "Run test_drive.py interactively once to regenerate."
            )

    print("  Token is valid.")
    return token_json


def get_drive_service():
    """Build a Drive service using the token from Supabase."""
    token_json = refresh_drive_token_if_needed()
    creds = Credentials.from_authorized_user_info(
        info=json.loads(token_json),
        scopes=DRIVE_SCOPES,
    )
    return build("drive", "v3", credentials=creds)


def upload_to_drive(local_path, folder_id):
    """Upload a local file to Google Drive (create or update)."""
    service = get_drive_service()
    name = os.path.basename(local_path)
    size_mb = os.path.getsize(local_path) / (1024 * 1024)

    print(f"\nUploading {name} ({size_mb:.2f} MB) to Drive folder {folder_id} ...")

    query = f"name = '{name}' and '{folder_id}' in parents and trashed = false"
    existing = service.files().list(
        q=query,
        fields="files(id, name)",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
    ).execute().get("files", [])

    media = MediaFileUpload(local_path, mimetype="text/plain", resumable=True)

    if existing:
        file_id = existing[0]["id"]
        print(f"  Found existing file (ID: {file_id}) — updating...")
        file = service.files().update(
            fileId=file_id,
            media_body=media,
            fields="id, name, size",
            supportsAllDrives=True,
        ).execute()
    else:
        metadata = {"name": name, "parents": [folder_id]}
        file = service.files().create(
            body=metadata,
            media_body=media,
            fields="id, name, size",
            supportsAllDrives=True,
        ).execute()

    print(f"  ✅ Uploaded: {file['name']} (ID: {file['id']}, size: {int(file['size']) / (1024**2):.2f} MB)")
    return file["id"]


# ------------------ BIGQUERY (service account) ------------------
def _is_valid_service_account_json(path):
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
        sys.exit(1)

    print(f"  Content-Type   : {content_type}")
    print(f"  Content-Length : {len(data):,} bytes")

    if "html" in content_type.lower():
        print("\nERROR: Server returned HTML instead of JSON.")
        print(data[:300].decode("utf-8", errors="replace"))
        sys.exit(1)

    try:
        parsed = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as e:
        print(f"\nERROR: Downloaded content is not valid JSON: {e}")
        print(data[:300].decode("utf-8", errors="replace"))
        sys.exit(1)

    required = ["type", "client_email", "private_key", "project_id"]
    missing = [k for k in required if k not in parsed]
    if missing:
        print(f"\nERROR: JSON is missing required fields: {missing}")
        sys.exit(1)

    if parsed.get("type") != "service_account":
        print(f"\nERROR: JSON type is '{parsed.get('type')}', expected 'service_account'")
        sys.exit(1)

    with open(GCP_KEY_FILE, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2)

    print(f"  ✅ Saved valid service account JSON to {GCP_KEY_FILE}")
    print(f"     client_email: {parsed['client_email']}")
    print(f"     project_id  : {parsed['project_id']}")


def get_bq_client():
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
    parser.add_argument("--skip-upload", action="store_true",
                        help="Skip uploading the result to Google Drive.")
    args = parser.parse_args()

    print("=" * 60)
    print("ETH ADDRESS EXPORTER")
    print("=" * 60)
    print(f"Threshold     : {ETH_THRESHOLD_WEI:,} wei (0.037 ETH)")
    print(f"Safety budget : {MAX_BYTES_BUDGET / 1024**3:.0f} GB (BigQuery free tier = 1 TB)")
    print(f"Drive folder  : {DRIVE_FOLDER_ID}")
    print("=" * 60)

    # --- BigQuery service account ---
    if not args.skip_download:
        download_service_account()

    if not os.path.exists(GCP_KEY_FILE):
        print(f"ERROR: {GCP_KEY_FILE} missing.")
        sys.exit(1)

    if not _is_valid_service_account_json(GCP_KEY_FILE):
        print(f"ERROR: {GCP_KEY_FILE} is not a valid service account JSON.")
        sys.exit(1)

    # --- BigQuery run ---
    client = get_bq_client()
    params = [bigquery.ScalarQueryParameter("threshold", "NUMERIC", ETH_THRESHOLD_WEI)]
    sql = build_query()

    estimated = estimate_cost(client, sql, params)
    if estimated > MAX_BYTES_BUDGET and not args.force:
        print(f"\nABORTING: Estimated scan {estimated / 1024**3:.2f} GB exceeds "
              f"safety budget {MAX_BYTES_BUDGET / 1024**3:.0f} GB.")
        print("Pass --force to override.")
        sys.exit(2)

    row_count = run_query_and_save(client, sql, params)
    size_mb = file_size_mb(OUTPUT_FILE)

    # --- Drive upload (token from Supabase) ---
    upload_id = None
    if not args.skip_upload:
        try:
            upload_id = upload_to_drive(OUTPUT_FILE, DRIVE_FOLDER_ID)
        except Exception as e:
            print(f"\n⚠ Drive upload failed: {e}")
            print("   The file remains locally at:", OUTPUT_FILE)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Addresses written : {row_count:>12,}")
    print(f"  Output file       : {OUTPUT_FILE}")
    print(f"  File size         : {size_mb:,.2f} MB")
    print(f"  Est. bytes scanned: {estimated / 1024**3:,.2f} GB")
    if upload_id:
        print(f"  Drive file ID     : {upload_id}")
    print("=" * 60)


if __name__ == "__main__":
    main()