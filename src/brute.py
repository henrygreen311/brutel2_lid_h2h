#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import io
import json
import time
import signal
import sqlite3
import subprocess
import logging
import contextlib
import urllib.request
import urllib.parse
import gdown
from mnemonic import Mnemonic
from bip_utils import (
    Bip39SeedGenerator,
    Bip44,
    Bip44Coins,
    Bip44Changes,
    Bip49,
    Bip49Coins,
    Bip84,
    Bip84Coins,
    Bip44Conf,
)
from supabase import create_client

Bip44Conf.ENABLE_UNSAFE_HDWALLET = True

BTC_FILE_ID = "1rysnhDGWd6OxtqbjHy-UEiDt6VDBsbAI"
ETH_FILE_ID = "1G9CCyNnDoTxvQhqdQxYkbPG-HV2WN-Fx"
SOL_FILE_ID = "1_ILIimHqOzws0Ld3IteMcH1_Rww9a-Ic"

BTC_TXT = "btc_addresses.txt"
ETH_TXT = "eth_addresses.txt"
SOL_TXT = "sol_addresses.txt"

BTC_DB = "btc_addresses.db"
ETH_DB = "eth_addresses.db"
SOL_DB = "sol_addresses.db"

VALID_SEEDS_FILE = "valid_seeds.txt"
FOUND_FILE = "found_matches.txt"

GENERATOR_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generator.py")

ATOMIC_ID = 1
TELEGRAM_MESSAGE_LIMIT = 4000
SCAN_LOG_INTERVAL = 300


class NullHandler(logging.Handler):
    def emit(self, record):
        pass

logger = logging.getLogger("wallet_scanner")
logger.handlers = []
logger.addHandler(NullHandler())
logger.propagate = False
logger.setLevel(logging.CRITICAL)

logging.getLogger("aiohttp").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

mnemo = Mnemonic("english")
scanned_counter = 0
match_counter = 0

_telegram_bot_id = None
_telegram_chat_id = None


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


def get_atomic_row():
    supabase = get_supabase()
    res = supabase.table("atomic").select("*").eq("id", ATOMIC_ID).limit(1).execute()
    return res.data[0] if res.data else None


def update_atomic(fields):
    supabase = get_supabase()
    supabase.table("atomic").update(fields).eq("id", ATOMIC_ID).execute()


def set_progress_flag(value):
    try:
        update_atomic({"progress": value})
        print(f"progress = {value}")
    except Exception as e:
        print(f"WARN: could not set progress: {e}")


def load_telegram_config():
    global _telegram_bot_id, _telegram_chat_id
    try:
        row = get_atomic_row()
        if row and row.get("telegram"):
            cfg = row["telegram"]
            if isinstance(cfg, dict):
                _telegram_bot_id = cfg.get("bot_id")
                _telegram_chat_id = cfg.get("chat_id")
        if _telegram_bot_id and _telegram_chat_id:
            print(f"telegram on (chat={_telegram_chat_id})")
        else:
            print("telegram off")
    except Exception as e:
        print(f"WARN: telegram config: {e}")


def append_found_record(record):
    last_err = None
    for attempt in range(1, 6):
        try:
            row = get_atomic_row()
            current = []
            if row and row.get("found"):
                current = row["found"]
                if not isinstance(current, list):
                    current = []
            current.append(record)
            update_atomic({"found": current})
            return True
        except Exception as e:
            last_err = e
            wait = min(2 ** attempt, 30)
            print(f"WARN: append_found failed ({attempt}/5): {e}")
            if attempt < 5:
                time.sleep(wait)
    print(f"WARN: giving up on append_found: {last_err}")
    return False


def _telegram_post(url, payload, timeout=15):
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"telegram error: {e}")
        return False


def send_telegram_alert(coin, seed, address, extra=None):
    if not _telegram_bot_id or not _telegram_chat_id:
        return False

    lines = [
        f"<b>MATCH FOUND [{coin}]</b>",
        f"<b>Seed:</b> <code>{seed}</code>",
        f"<b>Address:</b> <code>{address}</code>",
    ]
    if extra:
        lines.append(f"<b>Info:</b> <code>{extra}</code>")
    text = "\n".join(lines)

    if len(text) > TELEGRAM_MESSAGE_LIMIT:
        text = text[:TELEGRAM_MESSAGE_LIMIT - 3] + "..."

    url = f"https://api.telegram.org/bot{_telegram_bot_id}/sendMessage"
    payload = {
        "chat_id": _telegram_chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    ok = _telegram_post(url, payload)
    if ok:
        print(f"telegram sent [{coin}] {address}")
    return ok


def download_public_drive_file(file_id, local_path, label):
    if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
        size_mb = os.path.getsize(local_path) / (1024 * 1024)
        print(f"{label}: {size_mb:.0f} MB (cached)")
        return local_path

    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            gdown.download(id=file_id, output=local_path, quiet=True)
    except Exception as e:
        print(f"ERROR downloading {label}: {e}")
        return None

    if not os.path.exists(local_path) or os.path.getsize(local_path) == 0:
        print(f"ERROR: {label} not public or empty")
        return None

    size_mb = os.path.getsize(local_path) / (1024 * 1024)
    print(f"{label}: {size_mb:.0f} MB")
    return local_path


def derive_btc_addresses(seed_phrase):
    results = []
    try:
        seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    except Exception:
        return results

    try:
        addr = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN) \
            .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT) \
            .AddressIndex(0).PublicKey().ToAddress()
        results.append(("p2pkh", addr))
    except Exception:
        pass

    try:
        addr = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN) \
            .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT) \
            .AddressIndex(0).PublicKey().ToAddress()
        results.append(("p2sh", addr))
    except Exception:
        pass

    try:
        addr = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN) \
            .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT) \
            .AddressIndex(0).PublicKey().ToAddress()
        results.append(("bech32", addr))
    except Exception:
        pass

    return results


def derive_eth_address(seed_phrase):
    try:
        seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
        return Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM) \
            .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT) \
            .AddressIndex(0).PublicKey().ToAddress()
    except Exception:
        return None


def derive_sol_address(seed_phrase):
    try:
        seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
        return Bip44.FromSeed(seed_bytes, Bip44Coins.SOLANA) \
            .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT) \
            .PublicKey().ToAddress()
    except Exception:
        return None


def build_sqlite_from_txt(txt_path, db_path, label):
    if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
        conn = sqlite3.connect(db_path)
        try:
            count = conn.execute("SELECT COUNT(*) FROM addresses").fetchone()[0]
        except Exception:
            count = 0
        conn.close()
        if count > 0:
            print(f"{label} index: {count:,} (cached)")
            return
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA cache_size=-2000000")
    conn.execute("CREATE TABLE addresses (address TEXT PRIMARY KEY)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_address ON addresses(address)")

    t0 = time.time()
    batch = []
    total = 0
    with open(txt_path, "r", encoding="utf-8") as f:
        for line in f:
            addr = line.strip()
            if addr:
                batch.append((addr,))
                if len(batch) >= 100000:
                    conn.executemany("INSERT OR IGNORE INTO addresses VALUES (?)", batch)
                    conn.commit()
                    total += len(batch)
                    batch.clear()
    if batch:
        conn.executemany("INSERT OR IGNORE INTO addresses VALUES (?)", batch)
        conn.commit()
        total += len(batch)
    conn.close()
    print(f"{label} index: {total:,} ({time.time()-t0:.0f}s)")


class AddressChecker:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA query_only = ON")
        self.conn.execute("PRAGMA cache_size=-500000")
        self._cur = self.conn.cursor()

    def contains(self, address):
        if not address:
            return False
        self._cur.execute("SELECT 1 FROM addresses WHERE address = ? LIMIT 1", (address,))
        return self._cur.fetchone() is not None

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def log_match(coin, seed, address, extra=None):
    global match_counter
    match_counter += 1

    record = {
        "coin": coin,
        "seed": seed,
        "address": address,
        "timestamp": time.time(),
    }
    if extra:
        record["extra"] = extra

    try:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception as e:
        print(f"WARN: local found file: {e}")

    append_found_record(record)
    send_telegram_alert(coin, seed, address, extra=extra)

    print(f"MATCH [{coin}] {address} <- {seed}")


def ensure_valid_seeds():
    if os.path.exists(VALID_SEEDS_FILE) and os.path.getsize(VALID_SEEDS_FILE) > 0:
        return True
    print(f"{VALID_SEEDS_FILE} missing, running generator")
    try:
        result = subprocess.run([sys.executable, GENERATOR_SCRIPT], check=False)
        if result.returncode != 0:
            print(f"generator exit: {result.returncode}")
            return False
    except Exception as e:
        print(f"generator failed: {e}")
        return False
    return os.path.exists(VALID_SEEDS_FILE) and os.path.getsize(VALID_SEEDS_FILE) > 0


def call_generator_for_next_round():
    print("calling generator for next round")
    try:
        result = subprocess.run([sys.executable, GENERATOR_SCRIPT], check=False)
        if result.returncode != 0:
            print(f"generator exit: {result.returncode}")
            return False
    except Exception as e:
        print(f"generator failed: {e}")
        return False
    return True


def finalize_round():
    if os.path.exists(VALID_SEEDS_FILE):
        try:
            os.remove(VALID_SEEDS_FILE)
            print(f"deleted {VALID_SEEDS_FILE}")
        except OSError as e:
            print(f"WARN: delete {VALID_SEEDS_FILE}: {e}")

    set_progress_flag(True)
    call_generator_for_next_round()


def scan_all_seeds(btc_checker, eth_checker, sol_checker, stop_event):
    global scanned_counter, match_counter
    scanned_counter = 0
    match_counter = 0

    with open(VALID_SEEDS_FILE, "r", encoding="utf-8") as f:
        seeds = [line.strip() for line in f if line.strip()]

    total = len(seeds)
    print(f"scanning {total:,}")

    t0 = time.time()
    last_log = t0
    for idx, seed in enumerate(seeds, 1):
        if stop_event.is_set():
            print("stop signal")
            break

        btc_addrs = derive_btc_addresses(seed)
        for addr_type, addr in btc_addrs:
            if btc_checker.contains(addr):
                log_match("BTC", seed, addr, extra=addr_type)

        eth_addr = derive_eth_address(seed)
        if eth_addr and eth_checker.contains(eth_addr):
            log_match("ETH", seed, eth_addr)

        sol_addr = derive_sol_address(seed)
        if sol_addr and sol_checker.contains(sol_addr):
            log_match("SOL", seed, sol_addr)

        scanned_counter += 1
        now = time.time()
        if now - last_log >= SCAN_LOG_INTERVAL:
            rate = idx / (now - t0) if (now - t0) else 0
            print(f"scanned {idx:,}/{total:,} ({rate:,.0f}/s, {match_counter} hits)")
            last_log = now

    elapsed = time.time() - t0
    rate = scanned_counter / elapsed if elapsed else 0
    print(f"scan done: {scanned_counter:,} in {elapsed:.0f}s ({rate:,.0f}/s), {match_counter} hits")
    return scanned_counter, match_counter


def main():
    global match_counter

    row = get_atomic_row()
    if row is None:
        print("ERROR: atomic row id=1 missing")
        sys.exit(1)

    load_telegram_config()

    if not ensure_valid_seeds():
        print("ERROR: no valid_seeds.txt")
        sys.exit(1)

    if not download_public_drive_file(BTC_FILE_ID, BTC_TXT, "btc"):
        sys.exit(1)
    if not download_public_drive_file(ETH_FILE_ID, ETH_TXT, "eth"):
        sys.exit(1)
    if not download_public_drive_file(SOL_FILE_ID, SOL_TXT, "sol"):
        sys.exit(1)

    build_sqlite_from_txt(BTC_TXT, BTC_DB, "btc")
    build_sqlite_from_txt(ETH_TXT, ETH_DB, "eth")
    build_sqlite_from_txt(SOL_TXT, SOL_DB, "sol")

    btc_checker = AddressChecker(BTC_DB)
    eth_checker = AddressChecker(ETH_DB)
    sol_checker = AddressChecker(SOL_DB)

    import multiprocessing as mp
    manager = mp.Manager()
    stop_event = manager.Event()

    def _signal_handler(sig, frame):
        print("interrupt")
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)

    interrupted = False
    try:
        scan_all_seeds(btc_checker, eth_checker, sol_checker, stop_event)
    except KeyboardInterrupt:
        interrupted = True
        print("scan interrupted")
    finally:
        btc_checker.close()
        eth_checker.close()
        sol_checker.close()

    if interrupted:
        print("exiting without finalizing")
        return

    finalize_round()
    print(f"total matches: {match_counter}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("shutdown")